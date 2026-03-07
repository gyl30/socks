#include <array>
#include <cctype>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <expected>
#include <optional>
#include <limits>
#include <algorithm>
#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/errc.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "ch_parser.h"
#include "constants.h"
#include "net_utils.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "timeout_io.h"
#include "transcript.h"
#include "crypto_util.h"
#include "log_context.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "reality_core.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_cipher_suite.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "client_tunnel_pool.h"
#include "reality_fingerprint.h"
#include "tls_record_validation.h"

namespace mux
{

namespace
{

constexpr std::size_t kMaxHandshakeBufferSize = 1024L * 1024;
constexpr std::uint32_t kMaxHandshakeMessageSize = static_cast<std::uint32_t>(kMaxHandshakeBufferSize - 4);
constexpr std::uint32_t kMaxTlsCompatCcsRecords = 8;
constexpr std::uint32_t kReconnectBaseDelayMs = 200;
constexpr std::uint32_t kReconnectMaxDelayMs = 10000;
constexpr std::uint32_t kReconnectStableDurationMs = 30000;
constexpr std::chrono::milliseconds kTunnelPollInterval(200);

reality::fingerprint_type parse_fingerprint_type(const std::string& name)
{
    struct fp_entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const fp_entry kFps[] = {
        {.name = "chrome", .type = reality::fingerprint_type::kChrome120},
        {.name = "chrome_120", .type = reality::fingerprint_type::kChrome120},
        {.name = "firefox", .type = reality::fingerprint_type::kFirefox120},
        {.name = "firefox_120", .type = reality::fingerprint_type::kFirefox120},
        {.name = "ios", .type = reality::fingerprint_type::kIOS14},
        {.name = "ios_14", .type = reality::fingerprint_type::kIOS14},
        {.name = "android", .type = reality::fingerprint_type::kAndroid11OkHttp},
        {.name = "android_11_okhttp", .type = reality::fingerprint_type::kAndroid11OkHttp},
    };

    for (const auto& entry : kFps)
    {
        if (name == entry.name)
        {
            return entry.type;
        }
    }
    return kFps[0].type;
}

bool read_u24_field(const std::vector<std::uint8_t>& data, const std::size_t pos, std::uint32_t& value)
{
    if (pos + 3 > data.size())
    {
        return false;
    }
    value =
        (static_cast<std::uint32_t>(data[pos]) << 16) | (static_cast<std::uint32_t>(data[pos + 1]) << 8) | static_cast<std::uint32_t>(data[pos + 2]);
    return true;
}

bool read_u16_field(const std::vector<std::uint8_t>& data, const std::size_t pos, std::uint16_t& value)
{
    if (pos + 2 > data.size())
    {
        return false;
    }
    value = static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[pos]) << 8U) | static_cast<std::uint16_t>(data[pos + 1]));
    return true;
}

std::optional<std::vector<std::uint8_t>> extract_first_cert_der(const std::vector<std::uint8_t>& cert_msg);

bool is_certificate_message_header_valid(const std::vector<std::uint8_t>& cert_msg)
{
    if (cert_msg.size() < 8)
    {
        return false;
    }
    if (cert_msg[0] != 0x0b)
    {
        return false;
    }
    std::uint32_t msg_len = 0;
    if (!read_u24_field(cert_msg, 1, msg_len))
    {
        return false;
    }
    return cert_msg.size() == static_cast<std::size_t>(msg_len) + 4U;
}

bool read_u24_and_advance(const std::vector<std::uint8_t>& data, std::size_t& pos, std::uint32_t& value)
{
    if (!read_u24_field(data, pos, value))
    {
        return false;
    }
    pos += 3;
    return true;
}

bool parse_first_certificate_range(const std::vector<std::uint8_t>& cert_msg, std::size_t& cert_start, std::size_t& cert_len)
{
    if (!is_certificate_message_header_valid(cert_msg))
    {
        return false;
    }

    std::size_t pos = 4;
    if (pos >= cert_msg.size())
    {
        return false;
    }
    const std::uint8_t request_context_len = cert_msg[pos];
    pos += 1;
    if (pos + request_context_len > cert_msg.size())
    {
        return false;
    }
    pos += request_context_len;

    std::uint32_t list_len = 0;
    if (!read_u24_and_advance(cert_msg, pos, list_len))
    {
        return false;
    }
    const auto list_len_size = static_cast<std::size_t>(list_len);
    if (pos + list_len_size > cert_msg.size())
    {
        return false;
    }
    const auto list_end = pos + list_len_size;
    if (list_end != cert_msg.size())
    {
        return false;
    }

    std::uint32_t parsed_cert_len = 0;
    if (!read_u24_and_advance(cert_msg, pos, parsed_cert_len))
    {
        return false;
    }
    const auto parsed_cert_len_size = static_cast<std::size_t>(parsed_cert_len);
    if (parsed_cert_len_size == 0)
    {
        return false;
    }
    if (pos + parsed_cert_len_size > list_end)
    {
        return false;
    }
    if (pos + parsed_cert_len_size + 2 > list_end)
    {
        return false;
    }

    const auto first_cert_start = pos;
    pos += parsed_cert_len_size;
    std::uint16_t first_ext_len = 0;
    if (!read_u16_field(cert_msg, pos, first_ext_len))
    {
        return false;
    }
    pos += 2;
    if (pos + first_ext_len > list_end)
    {
        return false;
    }
    pos += first_ext_len;

    cert_start = first_cert_start;
    cert_len = parsed_cert_len_size;
    while (pos < list_end)
    {
        std::uint32_t next_cert_len = 0;
        if (!read_u24_and_advance(cert_msg, pos, next_cert_len))
        {
            return false;
        }
        const auto next_cert_len_size = static_cast<std::size_t>(next_cert_len);
        if (next_cert_len_size == 0)
        {
            return false;
        }
        if (pos + next_cert_len_size + 2 > list_end)
        {
            return false;
        }

        pos += next_cert_len_size;

        std::uint16_t next_ext_len = 0;
        if (!read_u16_field(cert_msg, pos, next_ext_len))
        {
            return false;
        }
        pos += 2;
        if (pos + next_ext_len > list_end)
        {
            return false;
        }
        pos += next_ext_len;
    }
    return pos == list_end;
}

bool read_handshake_message_header(const std::vector<std::uint8_t>& handshake_buffer,
                                   const std::size_t offset,
                                   std::uint8_t& msg_type,
                                   std::uint32_t& msg_len)
{
    if (offset > handshake_buffer.size() || handshake_buffer.size() - offset < 4)
    {
        return false;
    }
    msg_type = handshake_buffer[offset];
    msg_len = (static_cast<std::uint32_t>(handshake_buffer[offset + 1]) << 16) | (static_cast<std::uint32_t>(handshake_buffer[offset + 2]) << 8) |
              static_cast<std::uint32_t>(handshake_buffer[offset + 3]);
    return true;
}

struct handshake_validation_state
{
    bool encrypted_extensions_checked = false;
    bool cert_checked = false;
    bool cert_verify_checked = false;
    bool cert_verify_signature_checked = false;
    bool reality_cert_verified = false;
    const client_hello_info* client_hello = nullptr;
    reality::openssl_ptrs::evp_pkey_ptr server_pub_key = nullptr;
};

bool client_offers_alpn(const client_hello_info& client_hello, const std::string& alpn)
{
    return std::find(client_hello.alpn_protocols.begin(), client_hello.alpn_protocols.end(), alpn) != client_hello.alpn_protocols.end();
}

void validate_encrypted_extensions_message(const std::vector<std::uint8_t>& msg_data,
                                           const client_hello_info& client_hello,
                                           boost::system::error_code& ec)
{
    ec.clear();
    const auto encrypted_extensions = reality::parse_encrypted_extensions(msg_data);
    if (!encrypted_extensions.has_value())
    {
        LOG_ERROR("encrypted extensions parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!encrypted_extensions->has_alpn)
    {
        return;
    }
    if (client_hello.alpn_protocols.empty())
    {
        LOG_ERROR("server advertised unrequested alpn");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!client_offers_alpn(client_hello, encrypted_extensions->alpn))
    {
        LOG_ERROR("server selected unadvertised alpn {}", encrypted_extensions->alpn);
        ec = boost::asio::error::invalid_argument;
        return;
    }
}

void verify_reality_bound_certificate(const std::vector<std::uint8_t>& cert_der,
                                      const std::vector<std::uint8_t>& auth_key,
                                      handshake_validation_state& validation_state,
                                      boost::system::error_code& ec)
{
    ec.clear();
    auto server_pub_key = reality::crypto_util::extract_pubkey_from_cert(cert_der, ec);
    if (ec || server_pub_key == nullptr)
    {
        LOG_ERROR("extract server pubkey failed");
        if (!ec)
        {
            ec = boost::asio::error::invalid_argument;
        }
        return;
    }
    if (EVP_PKEY_base_id(server_pub_key.get()) != EVP_PKEY_ED25519)
    {
        LOG_ERROR("server certificate pubkey is not ed25519");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    auto raw_pub_key = reality::crypto_util::extract_raw_public_key(server_pub_key.get(), ec);
    if (ec)
    {
        return;
    }
    auto cert_signature = reality::crypto_util::extract_certificate_signature(cert_der, ec);
    if (ec)
    {
        return;
    }
    auto expected_signature = reality::crypto_util::hmac_sha512(auth_key, raw_pub_key, ec);
    if (ec)
    {
        return;
    }
    if (expected_signature.size() != cert_signature.size() ||
        CRYPTO_memcmp(expected_signature.data(), cert_signature.data(), expected_signature.size()) != 0)
    {
        LOG_ERROR("server certificate reality binding mismatch");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    validation_state.server_pub_key = std::move(server_pub_key);
    validation_state.reality_cert_verified = true;
    return;
}

void load_server_public_key_from_certificate(const std::vector<std::uint8_t>& msg_data,
                                             const std::vector<std::uint8_t>& auth_key,
                                             handshake_validation_state& validation_state,
                                             boost::system::error_code& ec)
{
    ec.clear();
    LOG_DEBUG("received certificate message size {}", msg_data.size());
    if (validation_state.cert_checked)
    {
        return;
    }

    const auto cert_der = extract_first_cert_der(msg_data);
    if (!cert_der.has_value())
    {
        LOG_ERROR("certificate message parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    verify_reality_bound_certificate(*cert_der, auth_key, validation_state, ec);
    if (ec)
    {
        return;
    }

    validation_state.cert_checked = true;
    return;
}

void verify_server_certificate_verify_message(const std::vector<std::uint8_t>& msg_data,
                                              const reality::transcript& trans,
                                              handshake_validation_state& validation_state,
                                              boost::system::error_code& ec)
{
    ec.clear();
    if (!validation_state.cert_checked)
    {
        LOG_ERROR("certificate verify received before certificate");
        ec = boost::asio::error::invalid_argument;
        return;
    }

    const auto cert_verify = reality::parse_certificate_verify(msg_data);
    if (!cert_verify.has_value())
    {
        LOG_ERROR("certificate verify parse failed");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!reality::is_supported_certificate_verify_scheme(cert_verify->scheme))
    {
        LOG_ERROR("unsupported certificate verify scheme {:x}", cert_verify->scheme);
        ec = boost::asio::error::no_protocol_option;
        return;
    }

    if (validation_state.server_pub_key != nullptr)
    {
        const auto transcript_hash = trans.finish();
        reality::crypto_util::verify_tls13_signature(
            validation_state.server_pub_key.get(), cert_verify->scheme, transcript_hash, cert_verify->signature, ec);
        if (ec)
        {
            LOG_DEBUG("certificate verify signature check failed code {} message {}", ec.value(), ec.message());
        }
        else
        {
            validation_state.cert_verify_signature_checked = true;
        }
    }

    validation_state.cert_verify_checked = true;
    return;
}

void verify_server_finished_message(const std::vector<std::uint8_t>& msg_data,
                                    const reality::handshake_keys& hs_keys,
                                    const EVP_MD* md,
                                    const reality::transcript& trans,
                                    boost::system::error_code& ec)
{
    ec.clear();
    const std::uint32_t msg_len =
        (static_cast<std::uint32_t>(msg_data[1]) << 16) | (static_cast<std::uint32_t>(msg_data[2]) << 8) | static_cast<std::uint32_t>(msg_data[3]);

    const auto expected_verify_data =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("server finished verify derive failed {}", ec.message());
        return;
    }

    if (expected_verify_data.size() != msg_len)
    {
        LOG_ERROR("server finished verify size mismatch {} {}", expected_verify_data.size(), msg_len);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    if (CRYPTO_memcmp(msg_data.data() + 4, expected_verify_data.data(), expected_verify_data.size()) != 0)
    {
        LOG_ERROR("server finished verify mismatch");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    return;
}

std::optional<std::vector<std::uint8_t>> extract_first_cert_der(const std::vector<std::uint8_t>& cert_msg)
{
    std::size_t cert_start = 0;
    std::size_t cert_len = 0;
    if (!parse_first_certificate_range(cert_msg, cert_start, cert_len))
    {
        return std::nullopt;
    }
    std::vector<std::uint8_t> cert(cert_msg.begin() + static_cast<std::ptrdiff_t>(cert_start),
                                   cert_msg.begin() + static_cast<std::ptrdiff_t>(cert_start + cert_len));
    return cert;
}

struct encrypted_record
{
    std::uint8_t content_type = 0;
    std::vector<std::uint8_t> ciphertext;
};

boost::asio::awaitable<encrypted_record> read_encrypted_record(boost::asio::ip::tcp::socket& socket,
                                                               const std::uint32_t timeout_sec,
                                                               boost::system::error_code& ec)
{
    ec.clear();
    std::array<std::uint8_t, 5> record_header{};
    auto read_size = co_await timeout_io::wait_read_with_timeout(socket, boost::asio::buffer(record_header), timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("error reading record header {}", ec.message());
        co_return encrypted_record{};
    }

    if (read_size != record_header.size())
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("short read record header {} of {}", read_size, record_header.size());
        co_return encrypted_record{};
    }

    const auto record_body_size = static_cast<std::uint16_t>((record_header[3] << 8) | record_header[4]);
    constexpr std::size_t kMaxRecordBodySize = reality::kMaxTlsPlaintextLen + 256;
    if (record_body_size > kMaxRecordBodySize)
    {
        LOG_ERROR("record body too large {}", record_body_size);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return encrypted_record{};
    }
    std::vector<std::uint8_t> record_body(record_body_size);
    read_size = co_await timeout_io::wait_read_with_timeout(socket, boost::asio::buffer(record_body), timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("error reading record payload {}", ec.message());
        co_return encrypted_record{};
    }
    if (read_size != record_body_size)
    {
        ec = boost::asio::error::fault;
        LOG_ERROR("short read record payload {} of {}", read_size, record_body_size);
        co_return encrypted_record{};
    }
    if (record_header[0] == reality::kContentTypeChangeCipherSpec)
    {
        const std::uint8_t ccs_body = record_body_size == 1 ? record_body[0] : 0;
        if (!reality::is_valid_tls13_compat_ccs(record_header, ccs_body))
        {
            LOG_ERROR("invalid tls13 compat ccs len {} body {}", record_body_size, ccs_body);
            ec = boost::asio::error::invalid_argument;
            co_return encrypted_record{};
        }
    }
    else if (record_header[0] != reality::kContentTypeApplicationData)
    {
        LOG_ERROR("unexpected encrypted record type {}", static_cast<int>(record_header[0]));
        ec = boost::asio::error::invalid_argument;
        co_return encrypted_record{};
    }

    std::vector<std::uint8_t> ciphertext(record_header.size() + record_body_size);
    std::memcpy(ciphertext.data(), record_header.data(), record_header.size());
    std::memcpy(ciphertext.data() + record_header.size(), record_body.data(), record_body_size);
    co_return encrypted_record{.content_type = record_header[0], .ciphertext = std::move(ciphertext)};
}

void handle_handshake_message(const std::uint8_t msg_type,
                              const std::vector<std::uint8_t>& msg_data,
                              const std::vector<std::uint8_t>& auth_key,
                              handshake_validation_state& validation_state,
                              bool& handshake_fin,
                              const reality::handshake_keys& hs_keys,
                              const EVP_MD* md,
                              reality::transcript& trans,
                              boost::system::error_code& ec)
{
    ec.clear();
    if (msg_type == 0x08)
    {
        if (validation_state.encrypted_extensions_checked || validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected encrypted extensions order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (validation_state.client_hello == nullptr)
        {
            LOG_ERROR("missing client hello for encrypted extensions");
            ec = boost::asio::error::fault;
            return;
        }
        validate_encrypted_extensions_message(msg_data, *validation_state.client_hello, ec);
        if (ec)
        {
            return;
        }
        validation_state.encrypted_extensions_checked = true;
        return;
    }
    if (msg_type == 0x0b)
    {
        if (!validation_state.encrypted_extensions_checked)
        {
            LOG_ERROR("certificate received before encrypted extensions");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (validation_state.cert_checked || validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected certificate message order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        load_server_public_key_from_certificate(msg_data, auth_key, validation_state, ec);
        return;
    }
    else if (msg_type == 0x0f)
    {
        if (validation_state.cert_verify_checked || handshake_fin)
        {
            LOG_ERROR("unexpected certificate verify message order");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        verify_server_certificate_verify_message(msg_data, trans, validation_state, ec);
        return;
    }
    else if (msg_type == 0x14)
    {
        if (handshake_fin)
        {
            LOG_ERROR("duplicate server finished");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        if (!validation_state.cert_verify_checked)
        {
            LOG_ERROR("server finished before certificate verify");
            ec = boost::asio::error::invalid_argument;
            return;
        }
        verify_server_finished_message(msg_data, hs_keys, md, trans, ec);
        if (ec)
        {
            return;
        }
        handshake_fin = true;
        return;
    }
    LOG_ERROR("unexpected handshake message type {}", msg_type);
    ec = boost::asio::error::invalid_argument;
}

std::size_t consume_handshake_buffer(std::vector<std::uint8_t>& handshake_buffer,
                                     const std::vector<std::uint8_t>& auth_key,
                                     handshake_validation_state& validation_state,
                                     bool& handshake_fin,
                                     const reality::handshake_keys& hs_keys,
                                     const EVP_MD* md,
                                     reality::transcript& trans,
                                     boost::system::error_code& ec)
{
    ec.clear();
    std::size_t offset = 0;
    while (offset <= handshake_buffer.size() && handshake_buffer.size() - offset >= 4)
    {
        std::uint8_t msg_type = 0;
        std::uint32_t msg_len = 0;
        if (!read_handshake_message_header(handshake_buffer, offset, msg_type, msg_len))
        {
            break;
        }
        if (msg_len > kMaxHandshakeMessageSize)
        {
            LOG_ERROR("handshake message too large {}", msg_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return 0;
        }

        const auto full_msg_len = static_cast<std::size_t>(msg_len) + 4;
        if (handshake_buffer.size() - offset < full_msg_len)
        {
            break;
        }

        const auto msg_begin = handshake_buffer.begin() + static_cast<std::ptrdiff_t>(offset);
        const auto msg_end = msg_begin + static_cast<std::ptrdiff_t>(full_msg_len);
        const std::vector<std::uint8_t> msg_data(msg_begin, msg_end);
        handle_handshake_message(msg_type, msg_data, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
        if (ec)
        {
            return 0;
        }
        trans.update(msg_data);
        offset += full_msg_len;
    }
    return offset;
}

void consume_handshake_plaintext(const std::vector<std::uint8_t>& plaintext,
                                 std::vector<std::uint8_t>& handshake_buffer,
                                 const std::vector<std::uint8_t>& auth_key,
                                 handshake_validation_state& validation_state,
                                 bool& handshake_fin,
                                 const reality::handshake_keys& hs_keys,
                                 const EVP_MD* md,
                                 reality::transcript& trans,
                                 boost::system::error_code& ec)
{
    ec.clear();
    if (plaintext.size() > kMaxHandshakeBufferSize || handshake_buffer.size() > kMaxHandshakeBufferSize - plaintext.size())
    {
        LOG_ERROR("handshake buffer too large {} {}", handshake_buffer.size(), plaintext.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    handshake_buffer.insert(handshake_buffer.end(), plaintext.begin(), plaintext.end());
    const auto consumed = consume_handshake_buffer(handshake_buffer, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
    if (ec)
    {
        return;
    }
    auto consumed_bytes = static_cast<uint32_t>(consumed);
    handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + consumed_bytes);
    return;
}

void validate_server_handshake_chain(const handshake_validation_state& validation_state,
                                     const std::string& sni,
                                     boost::system::error_code& ec)
{
    ec.clear();
    if (!validation_state.cert_checked || !validation_state.cert_verify_checked)
    {
        LOG_ERROR("server auth chain incomplete");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.reality_cert_verified)
    {
        auto& stats = statistics::instance();
        stats.inc_cert_verify_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kCertVerify, sni);
        LOG_ERROR("server certificate reality binding verification failed");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    if (!validation_state.cert_verify_signature_checked)
    {
        auto& stats = statistics::instance();
        stats.inc_cert_verify_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kCertVerify, sni);
        LOG_ERROR("server certificate verify signature check failed");
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }
    return;
}

boost::asio::awaitable<std::vector<std::uint8_t>> read_handshake_record_body(boost::asio::ip::tcp::socket& socket,
                                                                             const char* step,
                                                                             const std::uint32_t timeout_sec,
                                                                             boost::system::error_code& ec)
{
    ec.clear();
    const auto handshake_start_ms = timeout_io::now_ms();
    auto read_exact = [&](const boost::asio::mutable_buffer& buffer) -> boost::asio::awaitable<bool>
    {
        auto* data = static_cast<std::uint8_t*>(buffer.data());
        const auto size = buffer.size();
        std::size_t total_read = 0;
        while (total_read < size)
        {
            const auto read_timeout = timeout_io::remaining_timeout_seconds(handshake_start_ms, timeout_sec, ec);
            if (ec)
            {
                co_return false;
            }
            const auto read_size =
                co_await timeout_io::wait_read_with_timeout(socket, boost::asio::buffer(data + total_read, size - total_read), read_timeout, ec);
            if (ec)
            {
                co_return false;
            }
            if (read_size == 0)
            {
                ec = boost::asio::error::eof;
                co_return false;
            }
            total_read += read_size;
        }
        co_return true;
    };

    std::vector<std::uint8_t> handshake_data;
    while (true)
    {
        std::array<std::uint8_t, 5> header = {};
        if (!(co_await read_exact(boost::asio::buffer(header))))
        {
            LOG_ERROR("error reading {} header {}", step, ec.message());
            co_return std::vector<std::uint8_t>{};
        }
        if (header[0] != reality::kContentTypeHandshake)
        {
            LOG_ERROR("unexpected record type for {} {}", step, header[0]);
            ec = boost::asio::error::invalid_argument;
            co_return std::vector<std::uint8_t>{};
        }

        const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
        if (body_len > reality::kMaxTlsPlaintextLen)
        {
            LOG_ERROR("oversized {} body {}", step, body_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return std::vector<std::uint8_t>{};
        }

        std::vector<std::uint8_t> body(body_len);
        if (!(co_await read_exact(boost::asio::buffer(body))))
        {
            LOG_ERROR("error reading {} body {}", step, ec.message());
            co_return std::vector<std::uint8_t>{};
        }
        handshake_data.insert(handshake_data.end(), body.begin(), body.end());

        if (handshake_data.size() < 4)
        {
            continue;
        }
        if (handshake_data[0] != 0x02)
        {
            LOG_ERROR("unexpected handshake type for {} {}", step, handshake_data[0]);
            ec = boost::asio::error::invalid_argument;
            co_return std::vector<std::uint8_t>{};
        }

        const auto msg_len = (static_cast<std::uint32_t>(handshake_data[1]) << 16) | (static_cast<std::uint32_t>(handshake_data[2]) << 8) |
                             static_cast<std::uint32_t>(handshake_data[3]);
        if (msg_len > kMaxHandshakeMessageSize)
        {
            LOG_ERROR("oversized {} message {}", step, msg_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return std::vector<std::uint8_t>{};
        }

        const auto total_len = static_cast<std::size_t>(msg_len) + 4;
        if (handshake_data.size() < total_len)
        {
            continue;
        }
        if (handshake_data.size() != total_len)
        {
            ec = boost::asio::error::invalid_argument;
            LOG_ERROR("unexpected extra bytes in {} {}", step, handshake_data.size() - total_len);
            co_return std::vector<std::uint8_t>{};
        }
        co_return handshake_data;
    }
}

std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> derive_client_auth_key_material(const std::uint8_t* private_key,
                                                                                                 const std::vector<std::uint8_t>& server_pub_key,
                                                                                                 boost::system::error_code& ec)
{
    ec.clear();
    auto shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), server_pub_key, ec);
    LOG_DEBUG("using server pub key size {}", server_pub_key.size());
    if (ec)
    {
        return {};
    }

    std::vector<std::uint8_t> client_random(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }

    const std::vector<std::uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto reality_label_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    auto pseudo_random_key = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }
    auto auth_key = reality::crypto_util::hkdf_expand(pseudo_random_key, reality_label_info, 16, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }
    LOG_DEBUG("client auth material ready random {} bytes eph pub {} bytes", client_random.size(), 32);
    return std::make_pair(std::move(client_random), std::move(auth_key));
}

void build_client_hello_with_placeholder_sid(const reality::fingerprint_spec& spec,
                                             const std::vector<std::uint8_t>& client_random,
                                             const std::uint8_t* public_key,
                                             const std::vector<std::uint8_t>& x25519_mlkem768_key_share,
                                             const std::string& sni,
                                             std::vector<std::uint8_t>& hello_body,
                                             std::uint32_t& absolute_sid_offset,
                                             boost::system::error_code& ec)
{
    ec.clear();
    const std::vector<std::uint8_t> placeholder_session_id(32, 0);
    hello_body = reality::client_hello_builder::build(
        spec,
        placeholder_session_id,
        client_random,
        std::vector<std::uint8_t>(public_key, public_key + 32),
        x25519_mlkem768_key_share,
        sni);
    if (hello_body.empty())
    {
        LOG_ERROR("generated client hello body invalid for configured sni");
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (hello_body.size() > std::numeric_limits<std::uint16_t>::max())
    {
        LOG_ERROR("generated client hello body too large {}", hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    const client_hello_info ch_info = ch_parser::parse(hello_body);
    if (ch_info.sid_offset == 0)
    {
        LOG_ERROR("generated client hello session id offset invalid {}", ch_info.sid_offset);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }

    absolute_sid_offset = ch_info.sid_offset;
    if (absolute_sid_offset + 32 > hello_body.size())
    {
        LOG_ERROR("session id offset out of bounds {} {}", absolute_sid_offset, hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    return;
}

std::vector<std::uint8_t> encrypt_client_session_id(const std::vector<std::uint8_t>& auth_key,
                                                    const std::vector<std::uint8_t>& client_random,
                                                    const std::array<std::uint8_t, reality::kAuthPayloadLen>& payload,
                                                    const std::vector<std::uint8_t>& hello_body,
                                                    boost::system::error_code& ec)
{
    ec.clear();
    auto sid = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                  auth_key,
                                                  std::vector<std::uint8_t>(client_random.begin() + constants::auth::kSaltLen, client_random.end()),
                                                  std::vector<std::uint8_t>(payload.begin(), payload.end()),
                                                  hello_body,
                                                  ec);
    if (ec || sid.size() != 32)
    {
        LOG_ERROR("auth encryption failed ct size {}", sid.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }
    return sid;
}

struct authenticated_client_hello
{
    std::vector<std::uint8_t> hello_body;
    std::vector<std::uint8_t> auth_key;
    client_hello_info hello_info;
};

authenticated_client_hello build_authenticated_client_hello(const std::uint8_t* public_key,
                                                            const std::uint8_t* private_key,
                                                            const std::vector<std::uint8_t>& x25519_mlkem768_key_share,
                                                            const std::vector<std::uint8_t>& server_pub_key,
                                                            const std::vector<std::uint8_t>& short_id_bytes,
                                                            const std::array<std::uint8_t, 3>& client_ver,
                                                            const reality::fingerprint_spec& spec,
                                                            const std::string& sni,
                                                            boost::system::error_code& ec)
{
    ec.clear();
    auto auth_material = derive_client_auth_key_material(private_key, server_pub_key, ec);
    if (ec)
    {
        return {};
    }
    auto [client_random, auth_key] = std::move(auth_material);

    const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const auto now = static_cast<std::uint32_t>(now_seconds);
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    if (!reality::build_auth_payload(short_id_bytes, client_ver, now, payload))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<std::uint8_t> hello_body;
    std::uint32_t absolute_sid_offset = 0;
    build_client_hello_with_placeholder_sid(spec, client_random, public_key, x25519_mlkem768_key_share, sni, hello_body, absolute_sid_offset, ec);
    if (ec)
    {
        return {};
    }

    auto sid = encrypt_client_session_id(auth_key, client_random, payload, hello_body, ec);
    if (ec)
    {
        return {};
    }

    std::memcpy(hello_body.data() + absolute_sid_offset, sid.data(), 32);
    auto hello_info = ch_parser::parse(hello_body);
    return authenticated_client_hello{
        .hello_body = std::move(hello_body),
        .auth_key = std::move(auth_key),
        .hello_info = std::move(hello_info),
    };
}

reality::fingerprint_spec select_fingerprint_spec(const std::optional<reality::fingerprint_type>& fingerprint_type)
{
    if (fingerprint_type.has_value())
    {
        return reality::fingerprint_factory::get(*fingerprint_type);
    }

    static const std::array<reality::fingerprint_type, 4> kFingerprintCandidates = {
        reality::fingerprint_type::kChrome120,
        reality::fingerprint_type::kFirefox120,
        reality::fingerprint_type::kIOS14,
        reality::fingerprint_type::kAndroid11OkHttp,
    };
    static thread_local std::mt19937 fp_gen(std::random_device{}());
    std::uniform_int_distribution<std::size_t> fp_dist(0, kFingerprintCandidates.size() - 1);
    return reality::fingerprint_factory::get(kFingerprintCandidates[fp_dist(fp_gen)]);
}

void insert_hybrid_supported_group(reality::fingerprint_spec& spec)
{
    for (const auto& ext_ptr : spec.extensions)
    {
        auto groups = std::dynamic_pointer_cast<reality::supported_groups_blueprint>(ext_ptr);
        if (groups == nullptr)
        {
            continue;
        }
        auto& values = groups->groups();
        if (std::ranges::find(values, reality::tls_consts::group::kX25519MLKEM768) != values.end())
        {
            return;
        }

        const auto x25519_it = std::ranges::find(values, reality::tls_consts::group::kX25519);
        if (x25519_it != values.end())
        {
            values.insert(x25519_it, reality::tls_consts::group::kX25519MLKEM768);
            return;
        }
        values.insert(values.begin(), reality::tls_consts::group::kX25519MLKEM768);
        return;
    }
}

void insert_hybrid_key_share(reality::fingerprint_spec& spec)
{
    for (const auto& ext_ptr : spec.extensions)
    {
        auto key_share = std::dynamic_pointer_cast<reality::key_share_blueprint>(ext_ptr);
        if (key_share == nullptr)
        {
            continue;
        }
        auto& values = key_share->key_shares();
        const auto exists = std::ranges::any_of(values, [](const reality::key_share_blueprint::key_share_entry& entry) {
            return entry.group == reality::tls_consts::group::kX25519MLKEM768;
        });
        if (exists)
        {
            return;
        }

        const auto x25519_it = std::ranges::find_if(values, [](const reality::key_share_blueprint::key_share_entry& entry) {
            return entry.group == reality::tls_consts::group::kX25519;
        });
        const reality::key_share_blueprint::key_share_entry hybrid_entry{
            .group = reality::tls_consts::group::kX25519MLKEM768,
            .data = {},
        };
        if (x25519_it != values.end())
        {
            values.insert(x25519_it, hybrid_entry);
            return;
        }
        values.insert(values.begin(), hybrid_entry);
        return;
    }
}

void enable_hybrid_key_share(reality::fingerprint_spec& spec)
{
    insert_hybrid_supported_group(spec);
    insert_hybrid_key_share(spec);
}

struct handshake_traffic_keys
{
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
};

handshake_traffic_keys derive_handshake_traffic_keys(const reality::handshake_keys& hs_keys,
                                                     const std::uint16_t cipher_suite,
                                                     const EVP_MD* negotiated_md,
                                                     boost::system::error_code& ec)
{
    ec.clear();
    const std::size_t key_len = (cipher_suite == 0x1302 || cipher_suite == 0x1303) ? constants::crypto::kKeyLen256 : constants::crypto::kKeyLen128;
    constexpr std::size_t iv_len = constants::crypto::kIvLen;
    auto c_hs = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, negotiated_md);
    if (ec)
    {
        return {};
    }
    auto s_hs = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, negotiated_md);
    if (ec)
    {
        return {};
    }
    return handshake_traffic_keys{.c_hs_keys = std::move(c_hs), .s_hs_keys = std::move(s_hs)};
}

void prepare_server_hello_crypto(const std::vector<std::uint8_t>& sh_data,
                                 const client_hello_info& client_hello,
                                 reality::transcript& trans,
                                 reality::server_hello_info& server_hello,
                                 std::uint16_t& cipher_suite,
                                 const EVP_MD*& md,
                                 const EVP_CIPHER*& cipher,
                                 boost::system::error_code& ec)
{
    ec.clear();
    trans.update(sh_data);
    const auto parsed_server_hello = reality::parse_server_hello(sh_data);
    if (!parsed_server_hello.has_value())
    {
        LOG_ERROR("bad server hello");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    server_hello = *parsed_server_hello;
    if (!server_hello.has_supported_version)
    {
        LOG_ERROR("server hello missing supported version");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.supported_version != reality::tls_consts::kVer13)
    {
        LOG_ERROR("server hello selected invalid tls version {:x}", server_hello.supported_version);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.legacy_version != reality::tls_consts::kVer12)
    {
        LOG_ERROR("server hello legacy version invalid {:x}", server_hello.legacy_version);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.session_id != client_hello.session_id)
    {
        LOG_ERROR("server hello session id mismatch");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.compression_method != 0x00)
    {
        LOG_ERROR("server hello compression method invalid {:x}", server_hello.compression_method);
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (server_hello.has_forbidden_tls13_extension)
    {
        LOG_ERROR("server hello has forbidden tls13 extension");
        ec = boost::asio::error::invalid_argument;
        return;
    }
    if (!server_hello.has_key_share)
    {
        LOG_ERROR("bad server hello key share");
        ec = boost::asio::error::invalid_argument;
        return;
    }

    cipher_suite = server_hello.cipher_suite;
    const auto suite = reality::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_ERROR("unsupported server hello cipher suite {:x}", cipher_suite);
        ec = boost::asio::error::no_protocol_option;
        return;
    }
    if (std::find(client_hello.cipher_suites.begin(), client_hello.cipher_suites.end(), cipher_suite) == client_hello.cipher_suites.end())
    {
        LOG_ERROR("server hello selected unoffered cipher suite {:x}", cipher_suite);
        ec = boost::asio::error::invalid_argument;
        return;
    }

    md = suite->md;
    cipher = suite->cipher;
    trans.set_protocol_hash(md);
    return;
}

std::vector<std::uint8_t> derive_server_hello_shared_secret(const std::uint8_t* private_key,
                                                            const std::vector<std::uint8_t>& mlkem768_private_key,
                                                            const std::uint16_t key_share_group,
                                                            const std::vector<std::uint8_t>& key_share_data,
                                                            boost::system::error_code& ec)
{
    ec.clear();
    if (key_share_group == reality::tls_consts::group::kX25519)
    {
        if (key_share_data.size() != 32)
        {
            LOG_ERROR("invalid x25519 key share length {}", key_share_data.size());
            ec = boost::asio::error::invalid_argument;
            return {};
        }

        auto hs_shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), key_share_data, ec);
        if (ec)
        {
            LOG_ERROR("handshake shared secret failed {}", ec.message());
            return {};
        }
        return hs_shared;
    }
    if (key_share_group != reality::tls_consts::group::kX25519MLKEM768)
    {
        LOG_ERROR("unsupported key share group {}", key_share_group);
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    if (key_share_data.size() != reality::kMlkem768CiphertextSize + 32)
    {
        LOG_ERROR("invalid x25519 mlkem768 key share length {}", key_share_data.size());
        ec = boost::asio::error::invalid_argument;
        return {};
    }
    if (mlkem768_private_key.empty())
    {
        LOG_ERROR("missing mlkem768 private key");
        ec = boost::asio::error::operation_not_supported;
        return {};
    }

    const std::vector<std::uint8_t> ciphertext(
        key_share_data.begin(), key_share_data.begin() + static_cast<std::ptrdiff_t>(reality::kMlkem768CiphertextSize));
    auto mlkem768_shared = reality::crypto_util::mlkem768_decapsulate(mlkem768_private_key, ciphertext, ec);
    if (ec)
    {
        LOG_ERROR("mlkem768 decapsulate failed {}", ec.message());
        return {};
    }

    const std::vector<std::uint8_t> peer_pub(key_share_data.end() - 32, key_share_data.end());
    auto x25519_shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), peer_pub, ec);
    if (ec)
    {
        LOG_ERROR("x25519 derive failed {}", ec.message());
        return {};
    }

    mlkem768_shared.insert(mlkem768_shared.end(), x25519_shared.begin(), x25519_shared.end());
    return mlkem768_shared;
}

boost::asio::awaitable<void> process_handshake_record(
    boost::asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
    const std::vector<std::uint8_t>& auth_key,
    reality::transcript& trans,
    const EVP_CIPHER* cipher,
    std::vector<std::uint8_t>& handshake_buffer,
    handshake_validation_state& validation_state,
    bool& handshake_fin,
    const reality::handshake_keys& hs_keys,
    const EVP_MD* md,
    std::uint64_t& seq,
    std::uint32_t& tls13_compat_ccs_count,
    const std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    ec.clear();
    const auto record = co_await read_encrypted_record(socket, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (record.content_type == reality::kContentTypeChangeCipherSpec)
    {
        if (tls13_compat_ccs_count >= kMaxTlsCompatCcsRecords)
        {
            LOG_ERROR("received too many tls13 compat ccs records {}", tls13_compat_ccs_count);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        tls13_compat_ccs_count++;
        LOG_DEBUG("received change cipher spec skip count {}", tls13_compat_ccs_count);
        co_return;
    }

    std::uint8_t type = 0;
    auto plaintext = reality::tls_record_layer::decrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, record.ciphertext, type, ec);
    if (ec)
    {
        LOG_ERROR("error decrypting record {}", ec.message());
        co_return;
    }
    if (type == reality::kContentTypeAlert)
    {
        LOG_ERROR("received alert during handshake");
        ec = boost::asio::error::eof;
        co_return;
    }
    if (type != reality::kContentTypeHandshake)
    {
        LOG_ERROR("unexpected record content type during handshake {}", type);
        ec = boost::asio::error::invalid_argument;
        co_return;
    }

    consume_handshake_plaintext(plaintext, handshake_buffer, auth_key, validation_state, handshake_fin, hs_keys, md, trans, ec);
    co_return;
}

void prepare_socket_for_connect(boost::asio::ip::tcp::socket& socket,
                                const boost::asio::ip::tcp::endpoint& endpoint,
                                const std::uint32_t mark,
                                boost::system::error_code& ec)
{
    if (socket.is_open())
    {
        ec = socket.close(ec);
    }
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        return;
    }
    if (mark != 0)
    {
        net::set_socket_mark(socket.native_handle(), mark, ec);
        if (ec)
        {
            LOG_WARN("set mark failed {}", ec.message());
        }
    }
}

}    // namespace

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg, task_group& group)
    : sni_(cfg.reality.sni),
      remote_host_(cfg.outbound.host),
      remote_port_(std::to_string(cfg.outbound.port)),
      cfg_(cfg),
      group_(group),
      pool_(pool),
      max_handshake_records_(cfg.limits.max_handshake_records),
      tunnel_pool_(cfg.limits.max_connections)
{
    boost::algorithm::unhex(cfg.reality.public_key, std::back_inserter(server_pub_key_));
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(short_id_bytes_));
    fingerprint_type_ = parse_fingerprint_type(cfg.reality.fingerprint);
}

void client_tunnel_pool::start()
{
    LOG_INFO("client pool starting target {} port {} with {} connections", remote_host_, remote_port_, cfg_.limits.max_connections);

    auto self = shared_from_this();

    for (std::uint32_t i = 0; i < cfg_.limits.max_connections; ++i)
    {
        boost::asio::io_context& io = pool_.get_io_context();
        boost::asio::co_spawn(
            io,
            [this, i, io = &io, self]() -> boost::asio::awaitable<void> { co_await connect_remote_loop(i, *io); },
            group_.adapt(boost::asio::detached));
    }
}

std::shared_ptr<mux_tunnel_impl> client_tunnel_pool::select_tunnel()
{
    std::lock_guard<std::mutex> lock(tunnel_mutex_);
    if (tunnel_pool_.empty())
    {
        return nullptr;
    }

    const auto pool_size = tunnel_pool_.size();
    const auto start_index = static_cast<std::size_t>(next_tunnel_index_.fetch_add(1, std::memory_order_relaxed) % pool_size);
    for (std::size_t i = 0; i < pool_size; ++i)
    {
        const auto slot = (start_index + i) % pool_size;
        const auto tunnel = tunnel_pool_[slot];
        if (tunnel == nullptr)
        {
            continue;
        }
        const auto connection = tunnel->connection();
        if (connection == nullptr || !connection->is_active())
        {
            continue;
        }
        return tunnel;
    }

    return nullptr;
}

boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl>> client_tunnel_pool::wait_for_tunnel(boost::asio::io_context& io_context,
                                                                                              boost::system::error_code& ec)
{
    ec.clear();
    const auto start_ms = timeout_io::now_ms();
    const auto connect_timeout_ms = timeout_io::timeout_seconds_to_milliseconds(cfg_.timeout.connect);
    boost::asio::steady_timer retry_timer(io_context);
    for (;;)
    {
        const auto tunnel = select_tunnel();
        if (tunnel != nullptr)
        {
            co_return tunnel;
        }

        if (connect_timeout_ms != 0 && timeout_io::now_ms() - start_ms >= connect_timeout_ms)
        {
            ec = boost::asio::error::timed_out;
            co_return nullptr;
        }

        retry_timer.expires_after(kTunnelPollInterval);
        const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            ec = wait_ec;
            co_return nullptr;
        }
    }
}

std::uint32_t client_tunnel_pool::next_session_id() { return next_session_id_.fetch_add(1, std::memory_order_relaxed); }

std::shared_ptr<mux_tunnel_impl> client_tunnel_pool::build_tunnel(boost::asio::ip::tcp::socket socket,
                                                                  boost::asio::io_context& io_context,
                                                                  const std::uint32_t cid,
                                                                  const handshake_result& handshake_ret,
                                                                  const std::string& trace_id) const
{
    const std::size_t key_len = (handshake_ret.cipher_suite == 0x1302 || handshake_ret.cipher_suite == 0x1303) ? constants::crypto::kKeyLen256
                                                                                                               : constants::crypto::kKeyLen128;
    boost::system::error_code ec;
    auto c_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.c_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);
    if (ec)
    {
        LOG_ERROR("derive app traffic keys failed");
        return nullptr;
    }
    auto s_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.s_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);
    if (ec)
    {
        LOG_ERROR("derive app traffic keys failed");
        return nullptr;
    }

    reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second, handshake_ret.cipher);
    return std::make_shared<mux_tunnel_impl>(std::move(socket), io_context, std::move(re), cfg_, group_, cid, trace_id);
}

boost::asio::awaitable<client_tunnel_pool::handshake_result>
client_tunnel_pool::perform_reality_handshake_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                           const connection_context& ctx,
                                                           boost::system::error_code& ec) const
{
    ec.clear();
    if (!socket)
    {
        statistics::instance().inc_client_tunnel_pool_handshake_errors();
        LOG_CTX_ERROR(ctx, "{} stage=handshake target={}:{} error=invalid_socket", log_event::kHandshake, remote_host_, remote_port_);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        co_return handshake_result{};
    }
    auto handshake_res = co_await perform_reality_handshake(*socket, ctx, ec);
    if (ec)
    {
        auto& stats = statistics::instance();
        stats.inc_client_tunnel_pool_handshake_errors();
        LOG_CTX_ERROR(ctx, "{} stage=handshake target={}:{} error={}", log_event::kHandshake, remote_host_, remote_port_, ec.message());
    }
    co_return handshake_res;
}

boost::asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index, boost::asio::io_context& io_context)
{
    boost::system::error_code ec;
    static thread_local std::mt19937 reconnect_gen(std::random_device{}());
    std::uint32_t retry_delay_ms = kReconnectBaseDelayMs;
    const auto wait_before_retry = [&](const connection_context& ctx, const char* stage) -> boost::asio::awaitable<void>
    {
        std::uniform_int_distribution<std::uint32_t> jitter_dist(0, retry_delay_ms / 4);
        const auto sleep_ms = retry_delay_ms + jitter_dist(reconnect_gen);
        LOG_CTX_WARN(ctx, "{} stage={} retry_backoff={}ms", log_event::kConnInit, stage, sleep_ms);

        boost::asio::steady_timer retry_timer(io_context);
        retry_timer.expires_after(std::chrono::milliseconds(sleep_ms));
        const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec && wait_ec != boost::asio::error::operation_aborted)
        {
            LOG_CTX_WARN(ctx, "{} stage={} retry_backoff_wait_failed {}", log_event::kConnInit, stage, wait_ec.message());
        }
        retry_delay_ms = std::min(retry_delay_ms * 2, kReconnectMaxDelayMs);
        co_return;
    };

    while (true)
    {
        const std::uint32_t cid = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(cid);
        LOG_CTX_INFO(ctx, "{} init conn {}/{} to {} {}", log_event::kConnInit, index + 1, cfg_.limits.max_connections, remote_host_, remote_port_);
        // step 1 create sockst
        const auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
        // step 2 connect remote
        co_await tcp_connect_remote(io_context, *socket, ctx, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx, "{} stage=connect target={}:{} error={}", log_event::kConnInit, remote_host_, remote_port_, ec.message());
            co_await wait_before_retry(ctx, "connect");
            continue;
        }
        // step 3 handshake
        auto handshake_ret = co_await perform_reality_handshake_with_timeout(socket, ctx, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx, "{} handshake error {}", log_event::kHandshake, ec.message());
            co_await wait_before_retry(ctx, "handshake");
            continue;
        }

        LOG_CTX_INFO(ctx,
                     "{} handshake success cipher 0x{:04x} key_share_group=0x{:04x} {}",
                     log_event::kHandshake,
                     handshake_ret.cipher_suite,
                     handshake_ret.key_share_group,
                     reality::named_group_name(handshake_ret.key_share_group));
        // step 4 build tunnel
        auto tunnel = build_tunnel(std::move(*socket), io_context, cid, handshake_ret, ctx.trace_id());
        if (tunnel == nullptr)
        {
            LOG_CTX_ERROR(ctx, "{} build tunnel failed", log_event::kHandshake);
            co_await wait_before_retry(ctx, "build_tunnel");
            continue;
        }
        // step 5 tunnel run
        tunnel->run();
        const auto tunnel_start_ms = timeout_io::now_ms();

        {
            std::lock_guard<std::mutex> lock(tunnel_mutex_);
            if (index < tunnel_pool_.size())
            {
                tunnel_pool_[index] = tunnel;
            }
        }

        while (true)
        {
            boost::asio::steady_timer hold_timer(io_context);
            hold_timer.expires_after(std::chrono::seconds(1));
            const auto [wait_ec] = co_await hold_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (wait_ec)
            {
                break;
            }

            const auto connection = tunnel->connection();
            if (connection == nullptr || !connection->is_active())
            {
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(tunnel_mutex_);
            if (index < tunnel_pool_.size() && tunnel_pool_[index] == tunnel)
            {
                tunnel_pool_[index].reset();
            }
        }

        const auto tunnel_alive_ms = timeout_io::now_ms() - tunnel_start_ms;
        if (tunnel_alive_ms >= kReconnectStableDurationMs)
        {
            retry_delay_ms = kReconnectBaseDelayMs;
            continue;
        }
        LOG_CTX_WARN(ctx, "{} stage=tunnel_closed short_lived={}ms backoff_before_retry", log_event::kConnInit, tunnel_alive_ms);
        co_await wait_before_retry(ctx, "tunnel_closed");
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

boost::asio::awaitable<void> client_tunnel_pool::tcp_connect_remote(boost::asio::io_context& io_context,
                                                                    boost::asio::ip::tcp::socket& socket,
                                                                    const connection_context& ctx,
                                                                    boost::system::error_code& ec) const
{
    const auto timeout_sec = cfg_.timeout.connect;
    boost::asio::ip::tcp::resolver resolver(io_context);
    const auto resolve_endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver, remote_host_, remote_port_, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }

    for (const auto& entry : resolve_endpoints)
    {
        const auto endpoint = entry.endpoint();
        const auto connect_mark = cfg_.tproxy.enabled ? cfg_.tproxy.mark : 0U;
        prepare_socket_for_connect(socket, endpoint, connect_mark, ec);
        if (ec)
        {
            continue;
        }
        co_await timeout_io::wait_connect_with_timeout(socket, endpoint, timeout_sec, ec);
        if (!ec)
        {
            co_return;
        }
    }

    auto& stats = statistics::instance();
    if (ec == boost::asio::error::timed_out)
    {
        stats.inc_client_tunnel_pool_connect_timeouts();
        LOG_CTX_ERROR(ctx, "{} stage=connect target={}:{} timeout={}s", log_event::kConnInit, remote_host_, remote_port_, timeout_sec);
    }
    else
    {
        stats.inc_client_tunnel_pool_connect_errors();
        LOG_CTX_ERROR(ctx, "{} stage=connect target={}:{} error={}", log_event::kConnInit, remote_host_, remote_port_, ec.message());
    }
    co_return;
}

boost::asio::awaitable<client_tunnel_pool::handshake_result> client_tunnel_pool::perform_reality_handshake(
    boost::asio::ip::tcp::socket& socket, const connection_context& ctx, boost::system::error_code& ec) const
{
    ec.clear();
    std::uint8_t public_key[32];
    std::uint8_t private_key[32];
    std::vector<std::uint8_t> mlkem768_public_key;
    std::vector<std::uint8_t> mlkem768_private_key;
    std::vector<std::uint8_t> x25519_mlkem768_key_share;

    if (!reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        co_return handshake_result{};
    }
    if (!reality::crypto_util::generate_mlkem768_keypair(mlkem768_public_key, mlkem768_private_key, ec))
    {
        co_return handshake_result{};
    }
    x25519_mlkem768_key_share = mlkem768_public_key;
    x25519_mlkem768_key_share.insert(x25519_mlkem768_key_share.end(), public_key, public_key + 32);

    const std::shared_ptr<void> defer_cleanse(nullptr, [&](void*) {
        OPENSSL_cleanse(private_key, 32);
        if (!mlkem768_private_key.empty())
        {
            OPENSSL_cleanse(mlkem768_private_key.data(), mlkem768_private_key.size());
        }
    });

    auto spec = select_fingerprint_spec(fingerprint_type_);
    enable_hybrid_key_share(spec);
    LOG_CTX_INFO(ctx,
                 "{} client_hello key_share_offer group=0x{:04x} {} hybrid_share_len={} mlkem768_pub_len={}",
                 log_event::kHandshake,
                 reality::tls_consts::group::kX25519MLKEM768,
                 reality::named_group_name(reality::tls_consts::group::kX25519MLKEM768),
                 x25519_mlkem768_key_share.size(),
                 mlkem768_public_key.size());
    reality::transcript trans;
    std::vector<std::uint8_t> auth_key;
    client_hello_info client_hello;
    co_await generate_and_send_client_hello(
        socket, public_key, private_key, x25519_mlkem768_key_share, spec, trans, auth_key, client_hello, ec);
    if (ec)
    {
        co_return handshake_result{};
    }

    const auto server_hello_result = co_await process_server_hello(socket, private_key, mlkem768_private_key, client_hello, trans, ctx, ec);
    if (ec)
    {
        co_return handshake_result{};
    }

    const auto hs_keys =
        derive_handshake_traffic_keys(server_hello_result.hs_keys, server_hello_result.cipher_suite, server_hello_result.negotiated_md, ec);
    if (ec)
    {
        co_return handshake_result{};
    }

    auto app_secrets = co_await handshake_read_loop(socket,
                                                    hs_keys.s_hs_keys,
                                                    server_hello_result.hs_keys,
                                                    auth_key,
                                                    client_hello,
                                                    sni_,
                                                    trans,
                                                    server_hello_result.negotiated_cipher,
                                                    server_hello_result.negotiated_md,
                                                    max_handshake_records_,
                                                    cfg_.timeout.read,
                                                    ec);
    if (ec)
    {
        co_return handshake_result{};
    }
    auto [c_app_secret, s_app_secret] = std::move(app_secrets);

    co_await send_client_finished(socket,
                                  hs_keys.c_hs_keys,
                                  server_hello_result.hs_keys.client_handshake_traffic_secret,
                                  trans,
                                  server_hello_result.negotiated_cipher,
                                  server_hello_result.negotiated_md,
                                  cfg_.timeout.write,
                                  ec);
    if (ec)
    {
        co_return handshake_result{};
    }

    handshake_result result{.c_app_secret = std::move(c_app_secret),
                            .s_app_secret = std::move(s_app_secret),
                            .cipher_suite = server_hello_result.cipher_suite,
                            .key_share_group = server_hello_result.key_share_group,
                            .md = server_hello_result.negotiated_md,
                            .cipher = server_hello_result.negotiated_cipher};
    co_return result;
}

boost::asio::awaitable<void> client_tunnel_pool::generate_and_send_client_hello(
    boost::asio::ip::tcp::socket& socket,
    const std::uint8_t* public_key,
    const std::uint8_t* private_key,
    const std::vector<std::uint8_t>& x25519_mlkem768_key_share,
    const reality::fingerprint_spec& spec,
    reality::transcript& trans,
    std::vector<std::uint8_t>& auth_key,
    client_hello_info& client_hello,
    boost::system::error_code& ec) const
{
    ec.clear();
    std::array<std::uint8_t, 3> client_ver_{1, 0, 0};
    auto client_hello_result = build_authenticated_client_hello(
        public_key, private_key, x25519_mlkem768_key_share, server_pub_key_, short_id_bytes_, client_ver_, spec, sni_, ec);
    if (ec)
    {
        co_return;
    }
    const auto& hello_body = client_hello_result.hello_body;
    if (hello_body.size() > std::numeric_limits<std::uint16_t>::max())
    {
        LOG_ERROR("client hello too large {}", hello_body.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return;
    }

    auto client_hello_record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    client_hello_record.insert(client_hello_record.end(), hello_body.begin(), hello_body.end());
    const auto write_size = co_await timeout_io::wait_write_with_timeout(socket, boost::asio::buffer(client_hello_record), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("error sending client hello {}", ec.message());
        co_return;
    }
    if (write_size != client_hello_record.size())
    {
        LOG_ERROR("short write client hello {} of {}", write_size, client_hello_record.size());
        ec = boost::asio::error::fault;
        co_return;
    }
    LOG_DEBUG("sending client hello record size {}", client_hello_record.size());
    auth_key = std::move(client_hello_result.auth_key);
    client_hello = std::move(client_hello_result.hello_info);
    trans.update(hello_body);
    co_return;
}

boost::asio::awaitable<client_tunnel_pool::server_hello_res> client_tunnel_pool::process_server_hello(
    boost::asio::ip::tcp::socket& socket,
    const std::uint8_t* private_key,
    const std::vector<std::uint8_t>& mlkem768_private_key,
    const client_hello_info& client_hello,
    reality::transcript& trans,
    const connection_context& ctx,
    boost::system::error_code& ec) const
{
    ec.clear();
    const auto sh_data = co_await read_handshake_record_body(socket, "server hello", cfg_.timeout.read, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }
    LOG_DEBUG("server hello received size {}", sh_data.size());

    reality::server_hello_info server_hello;
    std::uint16_t cipher_suite = 0;
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    prepare_server_hello_crypto(sh_data, client_hello, trans, server_hello, cipher_suite, md, cipher, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }

    LOG_DEBUG("rx server hello size {}", sh_data.size());
    LOG_CTX_INFO(ctx,
                 "{} server_hello key_share_group=0x{:04x} {} key_share_len={}",
                 log_event::kHandshake,
                 server_hello.key_share.group,
                 reality::named_group_name(server_hello.key_share.group),
                 server_hello.key_share.data.size());

    auto handshake_shared_secret =
        derive_server_hello_shared_secret(private_key, mlkem768_private_key, server_hello.key_share.group, server_hello.key_share.data, ec);
    if (ec)
    {
        co_return server_hello_res{};
    }

    auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(handshake_shared_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive handshake keys failed {}", ec.message());
        co_return server_hello_res{};
    }

    co_return server_hello_res{
        .hs_keys = hs_keys,
        .negotiated_md = md,
        .negotiated_cipher = cipher,
        .cipher_suite = cipher_suite,
        .key_share_group = server_hello.key_share.group};
}

boost::asio::awaitable<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>
client_tunnel_pool::handshake_read_loop(boost::asio::ip::tcp::socket& socket,
                                        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
                                        const reality::handshake_keys& hs_keys,
                                        const std::vector<std::uint8_t>& auth_key,
                                        const client_hello_info& client_hello,
                                        const std::string& sni,
                                        reality::transcript& trans,
                                        const EVP_CIPHER* cipher,
                                        const EVP_MD* md,
                                        const std::uint32_t max_handshake_records,
                                        const std::uint32_t read_timeout_sec,
                                        boost::system::error_code& ec)
{
    ec.clear();
    bool handshake_fin = false;
    handshake_validation_state validation_state;
    validation_state.client_hello = &client_hello;
    std::uint64_t seq = 0;
    std::uint32_t tls13_compat_ccs_count = 0;
    std::uint32_t handshake_record_count = 0;
    std::vector<std::uint8_t> handshake_buffer;

    while (!handshake_fin)
    {
        if (handshake_record_count >= max_handshake_records)
        {
            LOG_ERROR("too many handshake records {} limit {}", handshake_record_count, max_handshake_records);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{};
        }
        co_await process_handshake_record(socket,
                                          s_hs_keys,
                                          auth_key,
                                          trans,
                                          cipher,
                                          handshake_buffer,
                                          validation_state,
                                          handshake_fin,
                                          hs_keys,
                                          md,
                                          seq,
                                          tls13_compat_ccs_count,
                                          read_timeout_sec,
                                          ec);
        if (ec)
        {
            co_return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{};
        }
        handshake_record_count++;
    }

    validate_server_handshake_chain(validation_state, sni, ec);
    if (ec)
    {
        co_return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{};
    }

    auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive app secrets failed {}", ec.message());
        co_return std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{};
    }
    co_return app_sec;
}

boost::asio::awaitable<void> client_tunnel_pool::send_client_finished(
    boost::asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
    const std::vector<std::uint8_t>& c_hs_secret,
    const reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md,
    const std::uint32_t write_timeout_sec,
    boost::system::error_code& ec)
{
    ec.clear();
    auto fin_verify = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), md, ec);
    if (ec)
    {
        co_return;
    }
    const auto fin_msg = reality::construct_finished(fin_verify);
    auto fin_rec =
        reality::tls_record_layer::encrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, fin_msg, reality::kContentTypeHandshake, ec);
    if (ec)
    {
        co_return;
    }

    std::vector<std::uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    out_flight.insert(out_flight.end(), fin_rec.begin(), fin_rec.end());

    const auto write_res = co_await timeout_io::wait_write_with_timeout(socket, boost::asio::buffer(out_flight), write_timeout_sec, ec);
    if (ec)
    {
        LOG_ERROR("send client finished flight error {}", ec.message());
        co_return;
    }
    LOG_DEBUG("sending client finished flight size {}", write_res);
    co_return;
}

}    // namespace mux
