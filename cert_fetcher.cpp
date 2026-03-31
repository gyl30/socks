#include <span>
#include <array>
#include <ctime>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>
#include <cstddef>
#include <cstring>
#include <utility>
#include <system_error>
#include <boost/asio.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "constants.h"
#include "tls/core.h"
#include "cert_fetcher.h"
#include "site_material.h"
#include "tls/cipher_context.h"
#include "tls/transcript.h"
#include "tls/crypto_util.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "tls/record_layer.h"
#include "tls/handshake_builder.h"
#include "tls/handshake_message.h"
#include "tls/handshake_reassembler.h"
#include "tls/certificate_compression.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/client_hello_builder.h"

namespace reality
{

namespace
{
struct fetch_context
{
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket{io_context};
    std::string host;
    uint16_t port = 0;
    std::string sni;
    fingerprint_type fingerprint = fingerprint_type::kChrome120;
    site_material material;
    bool saw_certificate = false;
    bool saw_server_finished = false;
    tls::transcript transcript;
    uint8_t client_public[32] = {0};
    uint8_t client_private[32] = {0};
    const EVP_CIPHER* negotiated_cipher = nullptr;
    std::vector<uint8_t> dec_key;
    std::vector<uint8_t> dec_iv;
    uint64_t seq = 0;
    const tls::cipher_context decrypt_ctx;

    ~fetch_context() { OPENSSL_cleanse(client_private, sizeof(client_private)); }
};

const char* fingerprint_name(const fingerprint_type fingerprint)
{
    switch (fingerprint)
    {
        case fingerprint_type::kChrome120:
            return "chrome120";
        case fingerprint_type::kFirefox120:
            return "firefox120";
        case fingerprint_type::kIOS14:
            return "ios14";
        case fingerprint_type::kAndroid11OkHttp:
            return "android11_okhttp";
        default:
            return "unknown";
    }
}

std::pair<uint8_t, std::span<uint8_t>> copy_plaintext_record(std::vector<uint8_t>& plaintext_buffer, const std::vector<uint8_t>& record)
{
    if (plaintext_buffer.size() < record.size())
    {
        plaintext_buffer.resize(record.size());
    }
    std::memcpy(plaintext_buffer.data(), record.data(), record.size());
    return std::make_pair(tls::kContentTypeChangeCipherSpec, std::span<uint8_t>(plaintext_buffer.data(), record.size()));
}

std::vector<uint8_t> build_encrypted_record_bytes(const uint8_t* header, const std::vector<uint8_t>& record)
{
    std::vector<uint8_t> ciphertext_record(5 + record.size());
    std::memcpy(ciphertext_record.data(), header, 5);
    std::memcpy(ciphertext_record.data() + 5, record.data(), record.size());
    return ciphertext_record;
}

boost::system::error_code derive_server_record_protection(fetch_context& ctx,
                                                          const std::vector<uint8_t>& server_hello,
                                                          const tls::negotiated_tls13_suite& suite)
{
    constexpr std::size_t iv_len = 12;

    const auto server_public_key = tls::extract_server_public_key(server_hello);
    boost::system::error_code ec;
    auto shared_secret = tls::crypto_util::x25519_derive(std::vector<uint8_t>(ctx.client_private, ctx.client_private + 32), server_public_key, ec);
    if (ec)
    {
        LOG_ERROR("{} x25519 derive failed", mux::log_event::kCert);
        return ec;
    }

    auto handshake_keys = tls::key_schedule::derive_handshake_keys(shared_secret, ctx.transcript.finish(), suite.md, ec);
    if (ec)
    {
        LOG_ERROR("{} derive keys failed", mux::log_event::kCert);
        return ec;
    }

    auto server_handshake_keys =
        tls::key_schedule::derive_traffic_keys(handshake_keys.server_handshake_traffic_secret, ec, suite.key_len, iv_len, suite.md);
    if (ec)
    {
        LOG_ERROR("{} derive traffic keys failed", mux::log_event::kCert);
        return ec;
    }

    ctx.negotiated_cipher = suite.cipher;
    ctx.dec_key = std::move(server_handshake_keys.first);
    ctx.dec_iv = std::move(server_handshake_keys.second);
    return boost::system::error_code{};
}

void connect(fetch_context& ctx, boost::system::error_code& ec)
{
    boost::asio::ip::tcp::resolver resolver(ctx.io_context);
    const auto resolved = resolver.resolve(ctx.host, std::to_string(ctx.port), ec);
    if (ec)
    {
        LOG_ERROR("{} stage resolve target {}:{} error {}", mux::log_event::kCert, ctx.host, ctx.port, ec.message());
        return;
    }
    boost::asio::connect(ctx.socket, resolved, ec);
    LOG_ERROR("{} stage connect target {}:{} error {}", mux::log_event::kCert, ctx.host, ctx.port, ec.message());
}

bool init_handshake_material(fetch_context& ctx, std::vector<uint8_t>& client_random, std::vector<uint8_t>& session_id)
{
    if (!tls::crypto_util::generate_x25519_keypair(ctx.client_public, ctx.client_private))
    {
        return false;
    }
    if (RAND_bytes(client_random.data(), static_cast<int>(client_random.size())) != 1)
    {
        return false;
    }
    if (RAND_bytes(session_id.data(), static_cast<int>(session_id.size())) != 1)
    {
        return false;
    }
    return true;
}

boost::system::error_code send_client_hello_record(fetch_context& ctx, const std::vector<uint8_t>& client_hello)
{
    if (client_hello.size() > std::numeric_limits<uint16_t>::max())
    {
        LOG_ERROR("{} client hello too large {}", mux::log_event::kCert, client_hello.size());
        return std::make_error_code(std::errc::message_size);
    }

    auto client_hello_record = tls::write_record_header(tls::kContentTypeHandshake, static_cast<uint16_t>(client_hello.size()));
    client_hello_record.insert(client_hello_record.end(), client_hello.begin(), client_hello.end());

    boost::system::error_code write_ec;
    const auto written = boost::asio::write(ctx.socket, boost::asio::buffer(client_hello_record), write_ec);
    if (write_ec)
    {
        LOG_ERROR("{} write ch failed {}", mux::log_event::kCert, write_ec.message());
        return write_ec;
    }
    if (written != client_hello_record.size())
    {
        LOG_ERROR("{} write ch short write {} of {}", mux::log_event::kCert, written, client_hello_record.size());
        return boost::asio::error::fault;
    }
    return boost::system::error_code{};
}

bool validate_server_hello_body(const fetch_context& ctx, const std::vector<uint8_t>& server_hello_body)
{
    if (!server_hello_body.empty())
    {
        return true;
    }
    LOG_ERROR("{} server hello empty", mux::log_event::kCert);
    return false;
}

void validate_record_length(uint16_t len, boost::system::error_code& ec)
{
    ec.clear();
    if (len <= constants::reality_limits::kMaxEncryptedRecordLen)
    {
        return;
    }
    ec = std::make_error_code(std::errc::message_size);
}

std::pair<boost::system::error_code, std::vector<uint8_t>> read_record_plaintext(fetch_context& ctx)
{
    uint32_t ccs_count = 0;
    for (;;)
    {
        uint8_t header[5] = {0};
        boost::system::error_code ec;
        const auto header_size = boost::asio::read(ctx.socket, boost::asio::buffer(header), ec);
        if (ec)
        {
            LOG_ERROR("{} read header failed {}", mux::log_event::kCert, ec.message());
            return std::make_pair(ec, std::vector<uint8_t>{});
        }
        if (header_size != sizeof(header))
        {
            LOG_ERROR("{} short read header {} of {}", mux::log_event::kCert, header_size, sizeof(header));
            return std::make_pair(boost::asio::error::fault, std::vector<uint8_t>{});
        }

        const auto len = static_cast<uint16_t>((static_cast<uint16_t>(header[3]) << 8) | static_cast<uint16_t>(header[4]));
        boost::system::error_code len_ec;
        validate_record_length(len, len_ec);
        if (len_ec)
        {
            LOG_ERROR("{} plaintext record too large {}", mux::log_event::kCert, len);
            return std::make_pair(len_ec, std::vector<uint8_t>{});
        }

        std::vector<uint8_t> body(len);
        boost::system::error_code body_ec;
        const auto body_size = len == 0 ? std::size_t{0} : boost::asio::read(ctx.socket, boost::asio::buffer(body), body_ec);
        if (body_ec)
        {
            LOG_ERROR("{} read body failed {}", mux::log_event::kCert, body_ec.message());
            return std::make_pair(body_ec, std::vector<uint8_t>{});
        }
        if (body_size != body.size())
        {
            LOG_ERROR("{} short read body {} of {}", mux::log_event::kCert, body_size, body.size());
            return std::make_pair(boost::asio::error::fault, std::vector<uint8_t>{});
        }

        if (header[0] == tls::kContentTypeChangeCipherSpec)
        {
            if (len != 1 || body[0] != 0x01)
            {
                LOG_ERROR("{} invalid tls13 compat ccs len {}", mux::log_event::kCert, len);
                return std::make_pair(boost::asio::error::invalid_argument, std::vector<uint8_t>{});
            }
            if (ccs_count >= constants::tls_limits::kMaxCompatCcsRecords)
            {
                LOG_ERROR("{} too many tls13 compat ccs before server hello {}", mux::log_event::kCert, ccs_count);
                return std::make_pair(std::make_error_code(std::errc::bad_message), std::vector<uint8_t>{});
            }

            ++ccs_count;
            ctx.material.sends_change_cipher_spec = true;
            LOG_DEBUG("{} skip tls13 compat ccs before server hello count {}", mux::log_event::kCert, ccs_count);
            continue;
        }

        if (header[0] != tls::kContentTypeHandshake)
        {
            LOG_ERROR("{} expected handshake type {}", mux::log_event::kCert, header[0]);
            return std::make_pair(boost::asio::error::fault, std::vector<uint8_t>{});
        }

        return std::make_pair(boost::system::error_code{}, std::move(body));
    }
}

boost::system::error_code process_server_hello(fetch_context& ctx, const std::vector<uint8_t>& server_hello_body)
{
    std::vector<uint8_t> server_hello;
    if (!tls::extract_handshake_message(server_hello_body, server_hello))
    {
        LOG_ERROR("{} server hello too short {}", mux::log_event::kCert, server_hello_body.size());
        return boost::asio::error::fault;
    }

    uint16_t cipher_suite = 0;
    if (auto cipher = tls::extract_cipher_suite_from_server_hello(server_hello); cipher)
    {
        cipher_suite = *cipher;
        ctx.material.fingerprint.cipher_suite = *cipher;
    }
    else
    {
        return boost::asio::error::fault;
    }

    tls::handshake_extension_layout server_hello_layout;
    if (tls::parse_server_hello_extension_layout(server_hello, server_hello_layout))
    {
        ctx.material.server_hello_extension_types = std::move(server_hello_layout.types);
    }
    else
    {
        LOG_WARN("{} parse server hello extensions failed", mux::log_event::kCert);
    }
    if (auto key_share = tls::extract_server_key_share(server_hello); key_share)
    {
        ctx.material.key_share_groups = {key_share->group};
    }

    ctx.transcript.update(server_hello);

    const auto suite = tls::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_ERROR("{} unsupported cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);
        return boost::asio::error::no_protocol_option;
    }
    LOG_INFO("{} selected tls13 cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);

    ctx.transcript.set_protocol_hash(suite->md);
    return derive_server_record_protection(ctx, server_hello, *suite);
}

boost::system::error_code perform_handshake_start(fetch_context& ctx)
{
    std::vector<uint8_t> client_random(32);
    std::vector<uint8_t> session_id(32);
    if (!init_handshake_material(ctx, client_random, session_id))
    {
        return boost::asio::error::operation_aborted;
    }

    const auto spec = fingerprint_factory::get(ctx.fingerprint);
    auto client_hello =
        client_hello_builder::build(spec, session_id, client_random, std::vector<uint8_t>(ctx.client_public, ctx.client_public + 32), {}, ctx.sni);
    if (client_hello.empty())
    {
        LOG_ERROR("{} invalid client hello for sni '{}' fingerprint {}", mux::log_event::kCert, ctx.sni, fingerprint_name(ctx.fingerprint));
        return boost::asio::error::invalid_argument;
    }

    if (auto write_ec = send_client_hello_record(ctx, client_hello))
    {
        return write_ec;
    }

    ctx.transcript.update(client_hello);

    const auto read_result = read_record_plaintext(ctx);
    if (read_result.first)
    {
        return read_result.first;
    }
    if (!validate_server_hello_body(ctx, read_result.second))
    {
        return boost::asio::error::fault;
    }
    return process_server_hello(ctx, read_result.second);
}

void read_record_body(fetch_context& ctx, uint16_t len, std::vector<uint8_t>& record, boost::system::error_code& ec)
{
    ec.clear();
    record.assign(len, 0);
    if (len == 0)
    {
        return;
    }

    const auto body_size = boost::asio::read(ctx.socket, boost::asio::buffer(record), ec);
    if (ec)
    {
        return;
    }
    if (body_size != len)
    {
        LOG_ERROR("{} short read record body {} of {}", mux::log_event::kCert, body_size, len);
        ec = boost::asio::error::fault;
    }
}

std::pair<uint8_t, std::span<uint8_t>> decrypt_application_record(fetch_context& ctx,
                                                                  const uint8_t header[5],
                                                                  const std::vector<uint8_t>& record,
                                                                  std::vector<uint8_t>& plaintext_buffer,
                                                                  boost::system::error_code& ec)
{
    auto ciphertext_record = build_encrypted_record_bytes(header, record);
    uint8_t content_type = 0;
    const auto plaintext_len = tls::record_layer::decrypt_tls_record(
        ctx.decrypt_ctx, ctx.negotiated_cipher, ctx.dec_key, ctx.dec_iv, ctx.seq++, ciphertext_record, plaintext_buffer, content_type, ec);
    if (ec)
    {
        return {};
    }
    return std::make_pair(content_type, std::span<uint8_t>(plaintext_buffer.data(), plaintext_len));
}

std::pair<uint8_t, std::span<uint8_t>> handle_record_by_content_type(fetch_context& ctx,
                                                                     const uint8_t header[5],
                                                                     const std::vector<uint8_t>& record,
                                                                     std::vector<uint8_t>& plaintext_buffer,
                                                                     boost::system::error_code& ec)
{
    ec.clear();
    switch (header[0])
    {
        case tls::kContentTypeChangeCipherSpec:
            return copy_plaintext_record(plaintext_buffer, record);

        case tls::kContentTypeApplicationData:
            return decrypt_application_record(ctx, header, record, plaintext_buffer, ec);

        case tls::kContentTypeAlert:
            LOG_WARN("{} received plaintext alert", mux::log_event::kCert);
            ec = boost::asio::error::connection_reset;
            return {};

        default:
            ec = boost::asio::error::invalid_argument;
            return {};
    }
}

std::pair<uint8_t, std::span<uint8_t>> read_record(fetch_context& ctx, std::vector<uint8_t>& plaintext_buffer, boost::system::error_code& ec)
{
    ec.clear();
    uint8_t header[5] = {0};
    const auto header_size = boost::asio::read(ctx.socket, boost::asio::buffer(header), ec);
    if (ec)
    {
        return {};
    }
    if (header_size != sizeof(header))
    {
        LOG_ERROR("{} short read record header {} of {}", mux::log_event::kCert, header_size, sizeof(header));
        ec = boost::asio::error::fault;
        return {};
    }

    const auto len = static_cast<uint16_t>((static_cast<uint16_t>(header[3]) << 8) | static_cast<uint16_t>(header[4]));
    validate_record_length(len, ec);
    if (ec)
    {
        return {};
    }

    std::vector<uint8_t> record;
    read_record_body(ctx, len, record, ec);
    if (ec)
    {
        return {};
    }
    return handle_record_by_content_type(ctx, header, record, plaintext_buffer, ec);
}

bool process_handshake_message(fetch_context& ctx, const std::vector<uint8_t>& message)
{
    const uint8_t message_type = message[0];
    const uint32_t message_len =
        (static_cast<uint32_t>(message[1]) << 16) | (static_cast<uint32_t>(message[2]) << 8) | static_cast<uint32_t>(message[3]);
    LOG_INFO("{} found handshake 0x{:02x} len {}", mux::log_event::kCert, message_type, message_len);

    if (message_type == 0x08)
    {
        if (auto alpn = tls::extract_alpn_from_encrypted_extensions(message); alpn)
        {
            LOG_INFO("{} learned alpn {}", mux::log_event::kCert, *alpn);
            ctx.material.fingerprint.alpn = *alpn;
        }
        tls::handshake_extension_layout encrypted_extensions_layout;
        if (tls::parse_encrypted_extensions_layout(message, encrypted_extensions_layout))
        {
            ctx.material.encrypted_extension_types = std::move(encrypted_extensions_layout.types);
            ctx.material.encrypted_extensions_padding_len = encrypted_extensions_layout.padding_len;
        }
        else
        {
            LOG_WARN("{} parse encrypted extensions layout failed", mux::log_event::kCert);
        }
    }
    else if (message_type == 0x0b)
    {
        LOG_INFO("{} found certificate len {}", mux::log_event::kCert, message_len);
        ctx.material.certificate_message = message;
        if (!tls::parse_certificate_chain(message, ctx.material.certificate_chain))
        {
            LOG_ERROR("{} parse certificate chain failed", mux::log_event::kCert);
            return false;
        }
        ctx.saw_certificate = true;
    }
    else if (message_type == 0x19)
    {
        boost::system::error_code ec;
        std::vector<uint8_t> certificate_message;
        if (!tls::decompress_certificate_message(message, constants::tls_limits::kMaxHandshakeMessageSize, certificate_message, ec))
        {
            LOG_ERROR("{} decompress certificate failed {}", mux::log_event::kCert, ec.message());
            return false;
        }
        LOG_INFO("{} found compressed certificate len {} decompressed_len {}", mux::log_event::kCert, message_len, certificate_message.size());
        ctx.material.certificate_message = std::move(certificate_message);
        if (!tls::parse_certificate_chain(ctx.material.certificate_message, ctx.material.certificate_chain))
        {
            LOG_ERROR("{} parse decompressed certificate chain failed", mux::log_event::kCert);
            return false;
        }
        ctx.saw_certificate = true;
    }
    else if (message_type == 0x14)
    {
        LOG_INFO("{} observed server finished", mux::log_event::kCert);
        ctx.saw_server_finished = true;
    }

    ctx.transcript.update(message);
    return ctx.saw_certificate && ctx.saw_server_finished;
}

bool consume_handshake_messages(fetch_context& ctx,
                                tls::handshake_reassembler& assembler,
                                std::vector<uint8_t>& message,
                                boost::system::error_code& ec)
{
    ec.clear();
    while (true)
    {
        const auto next = assembler.next(message, ec);
        if (ec)
        {
            return false;
        }
        if (!next)
        {
            break;
        }
        if (process_handshake_message(ctx, message))
        {
            return true;
        }
    }
    return false;
}

void append_next_handshake_record(fetch_context& ctx,
                                  tls::handshake_reassembler& assembler,
                                  std::vector<uint8_t>& plaintext_buffer,
                                  uint32_t record_index,
                                  boost::system::error_code& ec)
{
    ec.clear();
    const auto read_result = read_record(ctx, plaintext_buffer, ec);
    if (ec)
    {
        LOG_ERROR("{} read record {} failed {}", mux::log_event::kCert, record_index, ec.message());
        return;
    }

    if (read_result.first == tls::kContentTypeChangeCipherSpec)
    {
        ctx.material.sends_change_cipher_spec = true;
        return;
    }
    if (read_result.first != tls::kContentTypeHandshake)
    {
        return;
    }
    if (!read_result.second.empty())
    {
        ctx.material.encrypted_handshake_record_sizes.push_back(static_cast<uint16_t>(read_result.second.size()));
    }

    assembler.append(read_result.second);
}

bool collect_site_material(fetch_context& ctx)
{
    tls::handshake_reassembler assembler;
    std::vector<uint8_t> plaintext_buffer(tls::kMaxTlsPlaintextLen + 256);
    std::vector<uint8_t> message;

    for (uint32_t i = 0; i < constants::reality_limits::kMaxHandshakeRecords; ++i)
    {
        boost::system::error_code ec;
        append_next_handshake_record(ctx, assembler, plaintext_buffer, i, ec);
        if (ec)
        {
            LOG_ERROR("{} append record failed {}", mux::log_event::kCert, ec.message());
            break;
        }

        if (consume_handshake_messages(ctx, assembler, message, ec))
        {
            return true;
        }
        if (ec)
        {
            LOG_ERROR("{} consume failed {}", mux::log_event::kCert, ec.message());
            break;
        }
    }

    if (ctx.saw_certificate)
    {
        LOG_WARN("{} server finished not observed before fetch stopped", mux::log_event::kCert);
    }
    else
    {
        LOG_WARN("{} certificate not found", mux::log_event::kCert);
    }
    return false;
}

site_material fetch_once(std::string host,
                         uint16_t port,
                         std::string sni,
                         const fingerprint_type fingerprint,
                         boost::system::error_code& ec)
{
    fetch_context ctx;
    ctx.host = std::move(host);
    ctx.port = port;
    ctx.sni = std::move(sni);
    ctx.fingerprint = fingerprint;

    LOG_INFO("{} starting fetch fingerprint {}", mux::log_event::kCert, fingerprint_name(ctx.fingerprint));

    connect(ctx, ec);
    if (ec)
    {
        return {};
    }

    ec = perform_handshake_start(ctx);
    if (ec)
    {
        return {};
    }

    if (!collect_site_material(ctx))
    {
        ec = boost::asio::error::fault;
        return {};
    }

    ctx.material.fetched_at_unix_seconds = static_cast<uint64_t>(std::time(nullptr));
    ec.clear();
    return std::move(ctx.material);
}

}    // namespace

site_material fetch_site_material(
    const std::string& host, uint16_t port, const std::string& sni, boost::system::error_code& ec)
{
    ec.clear();
    boost::system::error_code last_ec = boost::asio::error::fault;

    for (const auto fingerprint : constants::reality_limits::kFetchFingerprints)
    {
        auto material = fetch_once(std::string(host), port, std::string(sni), fingerprint, ec);
        if (!ec)
        {
            return material;
        }
        last_ec = ec;
    }

    ec = last_ec ? last_ec : boost::asio::error::fault;
    return {};
}

}    // namespace reality
