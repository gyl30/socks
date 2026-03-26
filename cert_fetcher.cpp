#include <span>
#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <expected>
#include <limits>
#include <system_error>

#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
}

#include "log.h"
#include "timeout_io.h"
#include "tls/core.h"
#include "tls/crypto_util.h"
#include "tls/handshake_builder.h"
#include "tls/handshake_message.h"
#include "tls/handshake_reassembler.h"
#include "connection_context.h"
#include "cert_fetcher.h"
#include "tls/certificate_compression.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "tls/record_layer.h"
#include "tls/transcript.h"
#include "reality/handshake/client_hello_builder.h"
#include "reality/handshake/fingerprint.h"

namespace reality
{

namespace
{
constexpr std::size_t kMaxMsgSize = 64L * 1024;
constexpr std::size_t kMaxEncryptedRecordLen = 18432;
constexpr std::uint32_t kMaxTlsCompatCcsRecords = 8;
constexpr int kMaxHandshakeRecords = 256;

constexpr std::array<fingerprint_type, 4> kFetchFingerprints = {
    fingerprint_type::kChrome120,
    fingerprint_type::kIOS14,
    fingerprint_type::kFirefox120,
    fingerprint_type::kAndroid11OkHttp,
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

std::pair<std::uint8_t, std::span<std::uint8_t>> copy_plaintext_record(std::vector<std::uint8_t>& pt_buf, const std::vector<std::uint8_t>& rec)
{
    if (pt_buf.size() < rec.size())
    {
        pt_buf.resize(rec.size());
    }
    std::memcpy(pt_buf.data(), rec.data(), rec.size());
    return std::make_pair(::tls::kContentTypeChangeCipherSpec, std::span<std::uint8_t>(pt_buf.data(), rec.size()));
}

std::vector<std::uint8_t> build_encrypted_record_bytes(const std::uint8_t* head, const std::vector<std::uint8_t>& rec)
{
    std::vector<std::uint8_t> ciphertext_record(5 + rec.size());
    std::memcpy(ciphertext_record.data(), head, 5);
    std::memcpy(ciphertext_record.data() + 5, rec.data(), rec.size());
    return ciphertext_record;
}

boost::system::error_code derive_server_record_protection(const std::vector<std::uint8_t>& sh_real,
                                                          const ::tls::negotiated_tls13_suite& suite,
                                                          ::tls::transcript& trans,
                                                          const std::uint8_t* client_private,
                                                          const mux::connection_context& ctx,
                                                          const EVP_CIPHER*& negotiated_cipher,
                                                          std::vector<std::uint8_t>& dec_key,
                                                          std::vector<std::uint8_t>& dec_iv)
{
    constexpr std::size_t iv_len = 12;

    const auto server_pub = ::tls::extract_server_public_key(sh_real);
    boost::system::error_code ec;
    auto shared = ::tls::crypto_util::x25519_derive(std::vector<std::uint8_t>(client_private, client_private + 32), server_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", mux::log_event::kCert);
        return ec;
    }

    auto hs_keys = ::tls::key_schedule::derive_handshake_keys(shared, trans.finish(), suite.md, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} derive keys failed", mux::log_event::kCert);
        return ec;
    }

    auto s_hs_keys = ::tls::key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, suite.key_len, iv_len, suite.md);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} derive traffic keys failed", mux::log_event::kCert);
        return ec;
    }

    negotiated_cipher = suite.cipher;
    dec_key = std::move(s_hs_keys.first);
    dec_iv = std::move(s_hs_keys.second);
    return boost::system::error_code{};
}
}    // namespace

std::string cert_fetcher::hex(const std::vector<std::uint8_t>& data) { return ::tls::crypto_util::bytes_to_hex(data); }

std::string cert_fetcher::hex(const std::uint8_t* data, std::size_t len)
{
    return ::tls::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(data, data + len));
}

boost::asio::awaitable<std::expected<fetch_result, fetch_error>> cert_fetcher::fetch(boost::asio::io_context& io_context,
                                                                                     std::string host,
                                                                                     std::uint16_t port,
                                                                                     std::string sni,
                                                                                     const std::string& trace_id,
                                                                                     const std::uint32_t connect_timeout_sec,
                                                                                     const std::uint32_t read_timeout_sec,
                                                                                     const std::uint32_t write_timeout_sec)
{
    std::optional<fetch_error> last_error;
    for (const auto fingerprint : kFetchFingerprints)
    {
        fetch_session session(io_context,
                              host,
                              port,
                              sni,
                              fingerprint,
                              trace_id,
                              connect_timeout_sec,
                              read_timeout_sec,
                              write_timeout_sec);
        auto result = co_await session.run();
        if (result.has_value())
        {
            co_return result;
        }

        auto error = result.error();
        error.stage = std::string(fingerprint_name(fingerprint)) + ":" + error.stage;
        last_error = std::move(error);
    }

    co_return std::unexpected(last_error.value_or(fetch_error{.stage = "fetch", .reason = "all fingerprints failed"}));
}

cert_fetcher::fetch_session::fetch_session(boost::asio::io_context& io_context,
                                           std::string host,
                                           const std::uint16_t port,
                                           std::string sni,
                                           const fingerprint_type fingerprint,
                                           const std::string& trace_id,
                                           const std::uint32_t connect_timeout_sec,
                                           const std::uint32_t read_timeout_sec,
                                           const std::uint32_t write_timeout_sec)
    : io_context_(io_context),
      socket_(io_context_),
      host_(std::move(host)),
      port_(port),
      sni_(std::move(sni)),
      fingerprint_(fingerprint),
      connect_timeout_sec_(connect_timeout_sec),
      read_timeout_sec_(read_timeout_sec),
      write_timeout_sec_(write_timeout_sec)
{
    ctx_.trace_id(trace_id);
    ctx_.target_host(host_);
    ctx_.target_port(port);
    ctx_.sni(sni_);
}

boost::asio::awaitable<std::expected<fetch_result, fetch_error>> cert_fetcher::fetch_session::run()
{
    LOG_CTX_INFO(ctx_, "{} starting fetch fingerprint {}", mux::log_event::kCert, fingerprint_name(fingerprint_));

    if (const auto ec = co_await connect(); ec)
    {
        co_return make_error("connect", ec.message());
    }

    if (const auto ec = co_await perform_handshake_start(); ec)
    {
        co_return make_error("handshake_start", ec.message());
    }

    if (!(co_await collect_site_material()))
    {
        co_return make_error("collect_site_material", "certificate not found");
    }

    observed_material_.fetched_at_unix_seconds = mux::timeout_io::now_second();
    co_return fetch_result{.material = std::move(observed_material_)};
}

boost::asio::awaitable<boost::system::error_code> cert_fetcher::fetch_session::connect()
{
    boost::asio::ip::tcp::resolver resolver(io_context_);
    const auto timeout_sec = connect_timeout_sec_;
    boost::system::error_code ec;
    const auto resolve_res = co_await mux::timeout_io::wait_resolve_with_timeout(resolver, host_, std::to_string(port_), timeout_sec, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} stage resolve target {}:{} error {}", mux::log_event::kCert, host_, port_, ec.message());
        co_return ec;
    }

    if (resolve_res.begin() == resolve_res.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_CTX_ERROR(ctx_, "{} stage resolve target {}:{} error {}", mux::log_event::kCert, host_, port_, ec.message());
        co_return ec;
    }

    boost::system::error_code last_ec = boost::asio::error::host_unreachable;
    for (const auto& endpoint : resolve_res)
    {
        if (socket_.is_open())
        {
            boost::system::error_code close_ec;
            socket_.close(close_ec);
        }
        boost::system::error_code open_ec;
        socket_.open(endpoint.endpoint().protocol(), open_ec);
        if (open_ec)
        {
            last_ec = open_ec;
            continue;
        }
        co_await mux::timeout_io::wait_connect_with_timeout(socket_, endpoint.endpoint(), timeout_sec, last_ec);
        if (!last_ec)
        {
            co_return boost::system::error_code{};
        }
    }

    LOG_CTX_ERROR(ctx_, "{} stage connect target {}:{} error {}", mux::log_event::kCert, host_, port_, last_ec.message());
    co_return last_ec;
}

boost::asio::awaitable<boost::system::error_code> cert_fetcher::fetch_session::perform_handshake_start()
{
    std::vector<std::uint8_t> client_random(32);
    std::vector<std::uint8_t> session_id(32);
    if (!init_handshake_material(client_random, session_id))
    {
        co_return boost::asio::error::operation_aborted;
    }

    auto spec = fingerprint_factory::get(fingerprint_);
    auto ch = client_hello_builder::build(
        spec,
        session_id,
        client_random,
        std::vector<std::uint8_t>(client_public_, client_public_ + 32),
        {},
        sni_);
    if (ch.empty())
    {
        LOG_CTX_ERROR(ctx_, "{} invalid client hello for sni '{}' fingerprint {}", mux::log_event::kCert, sni_, fingerprint_name(fingerprint_));
        co_return boost::asio::error::invalid_argument;
    }

    if (const auto write_ec = co_await send_client_hello_record(ch); write_ec)
    {
        co_return write_ec;
    }

    trans_.update(ch);

    auto [read_ec, sh_body] = co_await read_record_plaintext();
    if (read_ec)
    {
        co_return read_ec;
    }
    if (!validate_server_hello_body(sh_body))
    {
        co_return boost::asio::error::fault;
    }

    co_return process_server_hello(sh_body);
}

bool cert_fetcher::fetch_session::init_handshake_material(std::vector<std::uint8_t>& client_random, std::vector<std::uint8_t>& session_id)
{
    if (!::tls::crypto_util::generate_x25519_keypair(client_public_, client_private_))
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

boost::asio::awaitable<boost::system::error_code> cert_fetcher::fetch_session::send_client_hello_record(const std::vector<std::uint8_t>& client_hello)
{
    if (client_hello.size() > std::numeric_limits<std::uint16_t>::max())
    {
        LOG_CTX_ERROR(ctx_, "{} client hello too large {}", mux::log_event::kCert, client_hello.size());
        co_return std::make_error_code(std::errc::message_size);
    }

    auto ch_record = ::tls::write_record_header(::tls::kContentTypeHandshake, static_cast<std::uint16_t>(client_hello.size()));
    ch_record.insert(ch_record.end(), client_hello.begin(), client_hello.end());

    boost::system::error_code write_ec;
    const auto write_n = co_await mux::timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(ch_record), write_timeout_sec_, write_ec);
    if (write_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write ch failed {}", mux::log_event::kCert, write_ec.message());
        co_return write_ec;
    }
    if (write_n != ch_record.size())
    {
        LOG_CTX_ERROR(ctx_, "{} write ch short write {} of {}", mux::log_event::kCert, write_n, ch_record.size());
        co_return boost::asio::error::fault;
    }
    co_return boost::system::error_code{};
}

bool cert_fetcher::fetch_session::validate_server_hello_body(const std::vector<std::uint8_t>& sh_body) const
{
    if (!sh_body.empty())
    {
        return true;
    }
    LOG_CTX_ERROR(ctx_, "{} server hello empty", mux::log_event::kCert);
    return false;
}

boost::asio::awaitable<bool> cert_fetcher::fetch_session::collect_site_material()
{
    ::tls::handshake_reassembler assembler;
    std::vector<std::uint8_t> pt_buf(::tls::kMaxTlsPlaintextLen + 256);
    std::vector<std::uint8_t> msg;

    for (int i = 0; i < kMaxHandshakeRecords; ++i)
    {
        boost::system::error_code ec;
        co_await append_next_handshake_record(assembler, pt_buf, i, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} append record failed {}", mux::log_event::kCert, ec.message());
            break;
        }

        const auto consume_res = consume_handshake_messages(assembler, msg, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} consume failed {}", mux::log_event::kCert, ec.message());
            break;
        }
        if (consume_res)
        {
            co_return true;
        }
    }

    if (saw_certificate_)
    {
        LOG_CTX_WARN(ctx_, "{} server finished not observed before fetch stopped", mux::log_event::kCert);
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} certificate not found", mux::log_event::kCert);
    }
    co_return false;
}

boost::asio::awaitable<void> cert_fetcher::fetch_session::append_next_handshake_record(::tls::handshake_reassembler& assembler,
                                                                                       std::vector<std::uint8_t>& pt_buf,
                                                                                       const int record_index,
                                                                                       boost::system::error_code& ec)
{
    ec.clear();
    auto read_res = co_await read_record(pt_buf, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} read record {} failed {}", mux::log_event::kCert, record_index, ec.message());
        co_return;
    }

    auto [type, pt_data] = read_res;

    if (type == ::tls::kContentTypeChangeCipherSpec)
    {
        observed_material_.sends_change_cipher_spec = true;
        co_return;
    }
    if (type != ::tls::kContentTypeHandshake)
    {
        co_return;
    }
    if (!pt_data.empty())
    {
        observed_material_.encrypted_handshake_record_sizes.push_back(static_cast<std::uint16_t>(pt_data.size()));
    }

    assembler.append(pt_data);
    co_return;
}

bool cert_fetcher::fetch_session::consume_handshake_messages(::tls::handshake_reassembler& assembler,
                                                             std::vector<std::uint8_t>& msg,
                                                             boost::system::error_code& ec)
{
    ec.clear();
    while (true)
    {
        const auto next_res = assembler.next(msg, ec);
        if (ec)
        {
            return false;
        }
        if (!next_res)
        {
            break;
        }

        if (process_handshake_message(msg))
        {
            return true;
        }
    }
    return false;
}

bool cert_fetcher::fetch_session::process_handshake_message(const std::vector<std::uint8_t>& msg)
{
    const std::uint8_t msg_type = msg[0];
    const std::uint32_t msg_len =
        (static_cast<std::uint32_t>(msg[1]) << 16) | (static_cast<std::uint32_t>(msg[2]) << 8) | static_cast<std::uint32_t>(msg[3]);
    LOG_CTX_INFO(ctx_, "{} found handshake 0x{:02x} len {}", mux::log_event::kCert, msg_type, msg_len);

    if (msg_type == 0x08)
    {
        if (auto alpn = ::tls::extract_alpn_from_encrypted_extensions(msg); alpn)
        {
            LOG_CTX_INFO(ctx_, "{} learned alpn {}", mux::log_event::kCert, *alpn);
            observed_material_.fingerprint.alpn = *alpn;
        }
        ::tls::handshake_extension_layout encrypted_extensions_layout;
        if (::tls::parse_encrypted_extensions_layout(msg, encrypted_extensions_layout))
        {
            observed_material_.encrypted_extension_types = std::move(encrypted_extensions_layout.types);
            observed_material_.encrypted_extensions_padding_len = encrypted_extensions_layout.padding_len;
        }
        else
        {
            LOG_CTX_WARN(ctx_, "{} parse encrypted extensions layout failed", mux::log_event::kCert);
        }
    }
    else if (msg_type == 0x0b)
    {
        LOG_CTX_INFO(ctx_, "{} found certificate len {}", mux::log_event::kCert, msg_len);
        observed_material_.certificate_message = msg;
        if (!::tls::parse_certificate_chain(msg, observed_material_.certificate_chain))
        {
            LOG_CTX_ERROR(ctx_, "{} parse certificate chain failed", mux::log_event::kCert);
            return false;
        }
        saw_certificate_ = true;
    }
    else if (msg_type == 0x19)
    {
        boost::system::error_code ec;
        std::vector<std::uint8_t> certificate_msg;
        if (!::tls::decompress_certificate_message(msg, kMaxMsgSize, certificate_msg, ec))
        {
            LOG_CTX_ERROR(ctx_, "{} decompress certificate failed {}", mux::log_event::kCert, ec.message());
            return false;
        }
        LOG_CTX_INFO(ctx_,
                     "{} found compressed certificate len {} decompressed_len {}",
                     mux::log_event::kCert,
                     msg_len,
                     certificate_msg.size());
        observed_material_.certificate_message = std::move(certificate_msg);
        if (!::tls::parse_certificate_chain(observed_material_.certificate_message, observed_material_.certificate_chain))
        {
            LOG_CTX_ERROR(ctx_, "{} parse decompressed certificate chain failed", mux::log_event::kCert);
            return false;
        }
        saw_certificate_ = true;
    }
    else if (msg_type == 0x14)
    {
        LOG_CTX_INFO(ctx_, "{} observed server finished", mux::log_event::kCert);
        saw_server_finished_ = true;
    }

    trans_.update(msg);
    return saw_certificate_ && saw_server_finished_;
}

boost::system::error_code cert_fetcher::fetch_session::process_server_hello(const std::vector<std::uint8_t>& sh_body)
{
    std::vector<std::uint8_t> sh_real;
    if (!::tls::extract_handshake_message(sh_body, sh_real))
    {
        LOG_CTX_ERROR(ctx_, "{} server hello too short {}", mux::log_event::kCert, sh_body.size());
        return boost::asio::error::fault;
    }

    std::uint16_t cipher_suite = 0;
    if (auto cs = ::tls::extract_cipher_suite_from_server_hello(sh_real); cs)
    {
        cipher_suite = *cs;
        observed_material_.fingerprint.cipher_suite = *cs;
    }
    else
    {
        return boost::asio::error::fault;
    }
    ::tls::handshake_extension_layout server_hello_layout;
    if (::tls::parse_server_hello_extension_layout(sh_real, server_hello_layout))
    {
        observed_material_.server_hello_extension_types = std::move(server_hello_layout.types);
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} parse server hello extensions failed", mux::log_event::kCert);
    }
    if (auto ks = ::tls::extract_server_key_share(sh_real); ks)
    {
        observed_material_.key_share_groups = {ks->group};
    }

    trans_.update(sh_real);

    const auto suite = ::tls::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_CTX_ERROR(ctx_, "{} unsupported cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);
        return boost::asio::error::no_protocol_option;
    }
    LOG_CTX_INFO(ctx_, "{} selected tls13 cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);

    trans_.set_protocol_hash(suite->md);
    return derive_server_record_protection(sh_real, *suite, trans_, client_private_, ctx_, negotiated_cipher_, dec_key_, dec_iv_);
}

boost::asio::awaitable<std::pair<boost::system::error_code, std::vector<std::uint8_t>>> cert_fetcher::fetch_session::read_record_plaintext()
{
    std::uint32_t ccs_count = 0;
    for (;;)
    {
        std::uint8_t head[5];
        boost::system::error_code ec;
        const auto n = co_await mux::timeout_io::wait_read_with_timeout(socket_, boost::asio::buffer(head), read_timeout_sec_, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} read header failed {}", mux::log_event::kCert, ec.message());
            co_return std::make_pair(ec, std::vector<std::uint8_t>{});
        }
        if (n != sizeof(head))
        {
            LOG_CTX_ERROR(ctx_, "{} short read header {} of {}", mux::log_event::kCert, n, sizeof(head));
            co_return std::make_pair(boost::asio::error::fault, std::vector<std::uint8_t>{});
        }

        const auto len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(head[3]) << 8) | static_cast<std::uint16_t>(head[4]));
        boost::system::error_code len_ec;
        validate_record_length(len, len_ec);
        if (len_ec)
        {
            LOG_CTX_ERROR(ctx_, "{} plaintext record too large {}", mux::log_event::kCert, len);
            co_return std::make_pair(len_ec, std::vector<std::uint8_t>{});
        }

        std::vector<std::uint8_t> body(len);
        boost::system::error_code ec2;
        const auto n2 = co_await mux::timeout_io::wait_read_with_timeout(socket_, boost::asio::buffer(body), read_timeout_sec_, ec2);
        if (ec2)
        {
            LOG_CTX_ERROR(ctx_, "{} read body failed {}", mux::log_event::kCert, ec2.message());
            co_return std::make_pair(ec2, std::vector<std::uint8_t>{});
        }
        if (n2 != body.size())
        {
            LOG_CTX_ERROR(ctx_, "{} short read body {} of {}", mux::log_event::kCert, n2, body.size());
            co_return std::make_pair(boost::asio::error::fault, std::vector<std::uint8_t>{});
        }

        if (head[0] == ::tls::kContentTypeChangeCipherSpec)
        {
            if (len != 1 || body[0] != 0x01)
            {
                LOG_CTX_ERROR(ctx_, "{} invalid tls13 compat ccs len {}", mux::log_event::kCert, len);
                co_return std::make_pair(boost::asio::error::invalid_argument, std::vector<std::uint8_t>{});
            }
            if (ccs_count >= kMaxTlsCompatCcsRecords)
            {
                LOG_CTX_ERROR(ctx_, "{} too many tls13 compat ccs before server hello {}", mux::log_event::kCert, ccs_count);
                co_return std::make_pair(std::make_error_code(std::errc::bad_message), std::vector<std::uint8_t>{});
            }

            ++ccs_count;
            observed_material_.sends_change_cipher_spec = true;
            LOG_CTX_DEBUG(ctx_, "{} skip tls13 compat ccs before server hello count {}", mux::log_event::kCert, ccs_count);
            continue;
        }

        if (head[0] != ::tls::kContentTypeHandshake)
        {
            LOG_CTX_ERROR(ctx_, "{} expected handshake type {}", mux::log_event::kCert, head[0]);
            co_return std::make_pair(boost::asio::error::fault, std::vector<std::uint8_t>{});
        }

        co_return std::make_pair(boost::system::error_code{}, std::move(body));
    }
}

void cert_fetcher::fetch_session::validate_record_length(const std::uint16_t len, boost::system::error_code& ec)
{
    ec.clear();
    if (len <= kMaxEncryptedRecordLen)
    {
        return;
    }
    ec = std::make_error_code(std::errc::message_size);
}

boost::asio::awaitable<void> cert_fetcher::fetch_session::read_record_body(const std::uint16_t len,
                                                                           std::vector<std::uint8_t>& rec,
                                                                           boost::system::error_code& ec)
{
    ec.clear();
    rec.assign(len, 0);
    const auto body_n = co_await mux::timeout_io::wait_read_with_timeout(socket_, boost::asio::buffer(rec), read_timeout_sec_, ec);
    if (ec)
    {
        co_return;
    }
    if (body_n != len)
    {
        LOG_CTX_ERROR(ctx_, "{} short read record body {} of {}", mux::log_event::kCert, body_n, len);
        ec = boost::asio::error::fault;
        co_return;
    }
    co_return;
}

std::pair<std::uint8_t, std::span<std::uint8_t>> cert_fetcher::fetch_session::decrypt_application_record(const std::uint8_t head[5],
                                                                                                          const std::vector<std::uint8_t>& rec,
                                                                                                          std::vector<std::uint8_t>& pt_buf,
                                                                                                          boost::system::error_code& ec)
{
    auto ciphertext_record = build_encrypted_record_bytes(head, rec);
    std::uint8_t type = 0;
    const auto decrypted = ::tls::record_layer::decrypt_record(decrypt_ctx_, negotiated_cipher_, dec_key_, dec_iv_, seq_++, ciphertext_record, pt_buf, type, ec);
    if (ec)
    {
        return {};
    }
    const std::size_t pt_len = decrypted;
    return std::make_pair(type, std::span<std::uint8_t>(pt_buf.data(), pt_len));
}

std::pair<std::uint8_t, std::span<std::uint8_t>> cert_fetcher::fetch_session::handle_record_by_content_type(const std::uint8_t head[5],
                                                                                                             const std::vector<std::uint8_t>& rec,
                                                                                                             std::vector<std::uint8_t>& pt_buf,
                                                                                                             boost::system::error_code& ec)
{
    ec.clear();
    switch (head[0])
    {
        case ::tls::kContentTypeChangeCipherSpec:
            return copy_plaintext_record(pt_buf, rec);

        case ::tls::kContentTypeApplicationData:
            return decrypt_application_record(head, rec, pt_buf, ec);

        case ::tls::kContentTypeAlert:
            LOG_CTX_WARN(ctx_, "{} received plaintext alert", mux::log_event::kCert);
            ec = boost::asio::error::connection_reset;
            return {};

        default:
            ec = boost::asio::error::invalid_argument;
            return {};
    }
}
boost::asio::awaitable<std::pair<std::uint8_t, std::span<std::uint8_t>>> cert_fetcher::fetch_session::read_record(std::vector<std::uint8_t>& pt_buf,
                                                                                                                   boost::system::error_code& ec)
{
    ec.clear();
    std::uint8_t head[5];
    const auto n = co_await mux::timeout_io::wait_read_with_timeout(socket_, boost::asio::buffer(head), read_timeout_sec_, ec);
    if (ec)
    {
        co_return std::pair<std::uint8_t, std::span<std::uint8_t>>{};
    }
    if (n != sizeof(head))
    {
        LOG_CTX_ERROR(ctx_, "{} short read record header {} of {}", mux::log_event::kCert, n, sizeof(head));
        ec = boost::asio::error::fault;
        co_return std::pair<std::uint8_t, std::span<std::uint8_t>>{};
    }

    const auto len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(head[3]) << 8) | static_cast<std::uint16_t>(head[4]));
    validate_record_length(len, ec);
    if (ec)
    {
        co_return std::pair<std::uint8_t, std::span<std::uint8_t>>{};
    }

    std::vector<std::uint8_t> rec;
    co_await read_record_body(len, rec, ec);
    if (ec)
    {
        co_return std::pair<std::uint8_t, std::span<std::uint8_t>>{};
    }
    co_return handle_record_by_content_type(head, rec, pt_buf, ec);
}

std::expected<fetch_result, fetch_error> cert_fetcher::fetch_session::make_error(std::string stage, std::string reason) const
{
    return std::unexpected(fetch_error{.stage = std::move(stage), .reason = std::move(reason)});
}

}    // namespace reality
