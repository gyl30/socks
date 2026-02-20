// NOLINTBEGIN(misc-include-cleaner)
#include <openssl/types.h>
#include <array>
#include <atomic>
#include <boost/asio/co_spawn.hpp>    // NOLINT(misc-include-cleaner): required for co_spawn declarations.
#include <boost/system/error_code.hpp>
#include <boost/system/detail/errc.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <expected>
#include <optional>
#include <algorithm>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>
#include "reality_core.h"
#include "context_pool.h"
#include "mux_tunnel.h"

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "ch_parser.h"
#include "constants.h"
#include "net_utils.h"
#include "timeout_io.h"
#include "crypto_util.h"
#include "log_context.h"
#include "statistics.h"
#include "transcript.h"
#include "reality_auth.h"
#include "stop_dispatch.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_cipher_suite.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "client_tunnel_pool.h"
#include "reality_fingerprint.h"

namespace mux
{

namespace
{

template <typename t>
[[nodiscard]] std::shared_ptr<t> atomic_load_shared(const std::shared_ptr<t>& slot)
{
    return std::atomic_load_explicit(&slot, std::memory_order_acquire);
}

template <typename t>
void atomic_store_shared(std::shared_ptr<t>& slot, std::shared_ptr<t> value)
{
    std::atomic_store_explicit(&slot, std::move(value), std::memory_order_release);
}

template <typename t>
[[nodiscard]] std::shared_ptr<t> atomic_exchange_shared(std::shared_ptr<t>& slot)
{
    return std::atomic_exchange_explicit(&slot, std::shared_ptr<t>{}, std::memory_order_acq_rel);
}

template <typename t>
bool atomic_clear_if_match(std::shared_ptr<t>& slot, const std::shared_ptr<t>& expected_value)
{
    auto expected = expected_value;
    return std::atomic_compare_exchange_strong_explicit(
        &slot, &expected, std::shared_ptr<t>{}, std::memory_order_acq_rel, std::memory_order_acquire);
}

bool parse_hex_to_bytes(const std::string& hex, std::vector<std::uint8_t>& out, const std::size_t max_len, const char* label)
{
    out.clear();
    if (hex.empty())
    {
        return true;
    }
    if (hex.size() % 2 != 0)
    {
        LOG_ERROR("{} hex length invalid", label);
        return false;
    }
    out = reality::crypto_util::hex_to_bytes(hex);
    if (out.empty())
    {
        LOG_ERROR("{} hex decode failed", label);
        return false;
    }
    if (max_len > 0 && out.size() > max_len)
    {
        LOG_ERROR("{} length {} exceeds max {}", label, out.size(), max_len);
        return false;
    }
    return true;
}

std::string normalize_fingerprint_name(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (const char c : input)
    {
        if (c == '-' || c == ' ')
        {
            out.push_back('_');
            continue;
        }
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool parse_fingerprint_type(const std::string& input, std::optional<reality::fingerprint_type>& out)
{
    out.reset();
    if (input.empty())
    {
        return true;
    }

    const auto name = normalize_fingerprint_name(input);
    if (name == "random")
    {
        return true;
    }

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
            out = entry.type;
            return true;
        }
    }

    return false;
}

bool read_u24_field(const std::vector<std::uint8_t>& data, const std::size_t pos, std::uint32_t& value)
{
    if (pos + 3 > data.size())
    {
        return false;
    }
    value = (static_cast<std::uint32_t>(data[pos]) << 16)
          | (static_cast<std::uint32_t>(data[pos + 1]) << 8)
          | static_cast<std::uint32_t>(data[pos + 2]);
    return true;
}

std::optional<std::vector<std::uint8_t>> extract_first_cert_der(const std::vector<std::uint8_t>& cert_msg);

bool is_certificate_message_header_valid(const std::vector<std::uint8_t>& cert_msg)
{
    if (cert_msg.size() < 11)
    {
        return false;
    }
    return cert_msg[0] == 0x0b;
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

    std::size_t pos = 5;
    std::uint32_t list_len = 0;
    if (!read_u24_and_advance(cert_msg, pos, list_len))
    {
        return false;
    }
    if (pos + list_len > cert_msg.size())
    {
        return false;
    }

    std::uint32_t parsed_cert_len = 0;
    if (!read_u24_and_advance(cert_msg, pos, parsed_cert_len))
    {
        return false;
    }
    if (pos + parsed_cert_len > cert_msg.size())
    {
        return false;
    }

    cert_start = pos;
    cert_len = static_cast<std::size_t>(parsed_cert_len);
    return true;
}

bool read_handshake_message_bounds(const std::vector<std::uint8_t>& handshake_buffer,
                                   const std::uint32_t offset,
                                   std::uint8_t& msg_type,
                                   std::uint32_t& msg_len)
{
    if (offset + 4 > handshake_buffer.size())
    {
        return false;
    }
    msg_type = handshake_buffer[offset];
    msg_len = (static_cast<std::uint32_t>(handshake_buffer[offset + 1]) << 16)
            | (static_cast<std::uint32_t>(handshake_buffer[offset + 2]) << 8)
            | static_cast<std::uint32_t>(handshake_buffer[offset + 3]);
    return offset + 4 + msg_len <= handshake_buffer.size();
}

struct handshake_validation_state
{
    bool cert_checked = false;
    bool cert_verify_checked = false;
    bool cert_verify_signature_checked = false;
    reality::openssl_ptrs::evp_pkey_ptr server_pub_key = nullptr;
};

std::expected<void, boost::system::error_code> load_server_public_key_from_certificate(const std::vector<std::uint8_t>& msg_data,
                                                                             handshake_validation_state& validation_state)
{
    LOG_DEBUG("received certificate message size {}", msg_data.size());
    if (validation_state.cert_checked)
    {
        return {};
    }

    const auto cert_der = extract_first_cert_der(msg_data);
    if (!cert_der.has_value())
    {
        LOG_ERROR("certificate message parse failed");
        return std::unexpected(boost::asio::error::invalid_argument);
    }

    auto server_pub_key = reality::crypto_util::extract_pubkey_from_cert(*cert_der);
    if (server_pub_key && *server_pub_key != nullptr)
    {
        validation_state.server_pub_key = std::move(*server_pub_key);
    }
    else
    {
        LOG_DEBUG("extract server pubkey skipped");
    }

    validation_state.cert_checked = true;
    return {};
}

std::expected<void, boost::system::error_code> verify_server_certificate_verify_message(const std::vector<std::uint8_t>& msg_data,
                                                                              const reality::transcript& trans,
                                                                              handshake_validation_state& validation_state)
{
    if (!validation_state.cert_checked)
    {
        LOG_ERROR("certificate verify received before certificate");
        return std::unexpected(boost::asio::error::invalid_argument);
    }

    const auto cert_verify = reality::parse_certificate_verify(msg_data);
    if (!cert_verify.has_value())
    {
        LOG_ERROR("certificate verify parse failed");
        return std::unexpected(boost::asio::error::invalid_argument);
    }
    if (!reality::is_supported_certificate_verify_scheme(cert_verify->scheme))
    {
        LOG_ERROR("unsupported certificate verify scheme {:x}", cert_verify->scheme);
        return std::unexpected(boost::asio::error::no_protocol_option);
    }

    if (validation_state.server_pub_key != nullptr)
    {
        const auto transcript_hash = trans.finish();
        auto verify_result = reality::crypto_util::verify_tls13_signature(validation_state.server_pub_key.get(), transcript_hash, cert_verify->signature);
        if (!verify_result)
        {
            LOG_WARN("certificate verify signature check skipped code {}", verify_result.error().value());
        }
        else
        {
            validation_state.cert_verify_signature_checked = true;
        }
    }

    validation_state.cert_verify_checked = true;
    return {};
}

std::expected<void, boost::system::error_code> verify_server_finished_message(const std::vector<std::uint8_t>& msg_data,
                                                                               const reality::handshake_keys& hs_keys,
                                                                               const EVP_MD* md,
                                                                               const reality::transcript& trans)
{
    // handshake_read_loop only calls this helper after message type and bounds validation.
    const std::uint32_t msg_len = (static_cast<std::uint32_t>(msg_data[1]) << 16)
                                | (static_cast<std::uint32_t>(msg_data[2]) << 8)
                                | static_cast<std::uint32_t>(msg_data[3]);

    const auto expected_verify_data =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), md);
    if (!expected_verify_data)
    {
        LOG_ERROR("server finished verify derive failed {}", expected_verify_data.error().message());
        return std::unexpected(expected_verify_data.error());
    }

    if (expected_verify_data->size() != msg_len)
    {
        LOG_ERROR("server finished verify size mismatch {} {}", expected_verify_data->size(), msg_len);
        return std::unexpected(boost::asio::error::invalid_argument);
    }

    if (CRYPTO_memcmp(msg_data.data() + 4, expected_verify_data->data(), expected_verify_data->size()) != 0)
    {
        LOG_ERROR("server finished verify mismatch");
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::permission_denied));
    }
    return {};
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

boost::asio::awaitable<std::expected<encrypted_record, boost::system::error_code>> read_encrypted_record(boost::asio::ip::tcp::socket& socket)
{
    std::array<std::uint8_t, 5> record_header{};
    auto [read_header_ec, read_header_size] =
        co_await boost::asio::async_read(socket, boost::asio::buffer(record_header), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (read_header_ec)
    {
        LOG_ERROR("error reading record header {}", read_header_ec.message());
        co_return std::unexpected(read_header_ec);
    }

    if (read_header_size != record_header.size())
    {
        const auto ec = boost::asio::error::fault;
        LOG_ERROR("short read record header {} of {}", read_header_size, record_header.size());
        co_return std::unexpected(ec);
    }

    const auto record_body_size = static_cast<std::uint16_t>((record_header[3] << 8) | record_header[4]);
    std::vector<std::uint8_t> record_body(record_body_size);
    auto [read_body_ec, read_body_size] =
        co_await boost::asio::async_read(socket, boost::asio::buffer(record_body), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (read_body_ec)
    {
        LOG_ERROR("error reading record payload {}", read_body_ec.message());
        co_return std::unexpected(read_body_ec);
    }
    if (read_body_size != record_body_size)
    {
        const auto ec = boost::asio::error::fault;
        LOG_ERROR("short read record payload {} of {}", read_body_size, record_body_size);
        co_return std::unexpected(ec);
    }

    std::vector<std::uint8_t> ciphertext(record_header.size() + record_body_size);
    std::memcpy(ciphertext.data(), record_header.data(), record_header.size());
    std::memcpy(ciphertext.data() + record_header.size(), record_body.data(), record_body_size);
    co_return encrypted_record{.content_type = record_header[0], .ciphertext = std::move(ciphertext)};
}

std::expected<void, boost::system::error_code> handle_handshake_message(const std::uint8_t msg_type,
                                                                         const std::vector<std::uint8_t>& msg_data,
                                                                         handshake_validation_state& validation_state,
                                                                         bool& handshake_fin,
                                                                         const reality::handshake_keys& hs_keys,
                                                                         const EVP_MD* md,
                                                                         reality::transcript& trans)
{
    if (msg_type == 0x0b)
    {
        if (const auto res = load_server_public_key_from_certificate(msg_data, validation_state); !res)
        {
            return std::unexpected(res.error());
        }
    }
    else if (msg_type == 0x0f)
    {
        if (const auto res = verify_server_certificate_verify_message(msg_data, trans, validation_state); !res)
        {
            return std::unexpected(res.error());
        }
    }
    else if (msg_type == 0x14)
    {
        if (!validation_state.cert_verify_checked)
        {
            LOG_ERROR("server finished before certificate verify");
            return std::unexpected(boost::asio::error::invalid_argument);
        }
        if (const auto res = verify_server_finished_message(msg_data, hs_keys, md, trans); !res)
        {
            return std::unexpected(res.error());
        }
        handshake_fin = true;
    }
    return {};
}

std::expected<std::uint32_t, boost::system::error_code> consume_handshake_buffer(std::vector<std::uint8_t>& handshake_buffer,
                                                                                  handshake_validation_state& validation_state,
                                                                                  bool& handshake_fin,
                                                                                  const reality::handshake_keys& hs_keys,
                                                                                  const EVP_MD* md,
                                                                                  reality::transcript& trans)
{
    std::uint32_t offset = 0;
    while (offset + 4 <= handshake_buffer.size())
    {
        std::uint8_t msg_type = 0;
        std::uint32_t msg_len = 0;
        if (!read_handshake_message_bounds(handshake_buffer, offset, msg_type, msg_len))
        {
            break;
        }

        const std::vector<std::uint8_t> msg_data(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len);
        if (const auto res = handle_handshake_message(msg_type, msg_data, validation_state, handshake_fin, hs_keys, md, trans); !res)
        {
            return std::unexpected(res.error());
        }
        trans.update(msg_data);
        offset += 4 + msg_len;
    }
    return offset;
}

std::expected<void, boost::system::error_code> consume_handshake_plaintext(const std::vector<std::uint8_t>& plaintext,
                                                                            std::vector<std::uint8_t>& handshake_buffer,
                                                                            handshake_validation_state& validation_state,
                                                                            bool& handshake_fin,
                                                                            const reality::handshake_keys& hs_keys,
                                                                            const EVP_MD* md,
                                                                            reality::transcript& trans)
{
    handshake_buffer.insert(handshake_buffer.end(), plaintext.begin(), plaintext.end());
    const auto consumed = consume_handshake_buffer(handshake_buffer, validation_state, handshake_fin, hs_keys, md, trans);
    if (!consumed)
    {
        return std::unexpected(consumed.error());
    }
    handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + *consumed);
    return {};
}

std::expected<void, boost::system::error_code> validate_server_handshake_chain(const handshake_validation_state& validation_state,
                                                                                const bool strict_cert_verify,
                                                                                const std::string& sni)
{
    if (!validation_state.cert_checked || !validation_state.cert_verify_checked)
    {
        LOG_ERROR("server auth chain incomplete");
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::permission_denied));
    }
    if (strict_cert_verify && !validation_state.cert_verify_signature_checked)
    {
        auto& stats = statistics::instance();
        stats.inc_cert_verify_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kCertVerify, sni);
        LOG_ERROR("server certificate verify signature required possible cert key mismatch");
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::permission_denied));
    }
    if (!strict_cert_verify && !validation_state.cert_verify_signature_checked)
    {
        LOG_DEBUG("server certificate verify signature unchecked");
    }
    return {};
}

boost::asio::awaitable<std::expected<std::vector<std::uint8_t>, boost::system::error_code>> read_handshake_record_body(boost::asio::ip::tcp::socket& socket,
                                                                                                                         const char* step)
{
    std::uint8_t header[5];
    auto [read_header_ec, read_header_n] = co_await boost::asio::async_read(socket, boost::asio::buffer(header, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (read_header_ec)
    {
        LOG_ERROR("error reading {} header {}", step, read_header_ec.message());
        co_return std::unexpected(read_header_ec);
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    std::vector<std::uint8_t> body(body_len);
    auto [read_body_ec, read_body_n] = co_await boost::asio::async_read(socket, boost::asio::buffer(body), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (read_body_ec)
    {
        LOG_ERROR("error reading {} body {}", step, read_body_ec.message());
        co_return std::unexpected(read_body_ec);
    }
    if (read_body_n != body_len)
    {
        const auto ec = boost::asio::error::fault;
        LOG_ERROR("short read {} body {} of {}", step, read_body_n, body_len);
        co_return std::unexpected(ec);
    }

    co_return body;
}

std::expected<std::uint16_t, boost::system::error_code> parse_server_hello_cipher_suite(const std::vector<std::uint8_t>& sh_data)
{
    std::size_t pos = 4 + 2 + 32;
    if (pos >= sh_data.size())
    {
        const boost::system::error_code ec = boost::asio::error::fault;
        LOG_ERROR("bad server hello {}", ec.message());
        return std::unexpected(ec);
    }

    const std::uint8_t sid_len = sh_data[pos];
    pos += 1 + sid_len;
    if (pos + 2 > sh_data.size())
    {
        const boost::system::error_code ec = boost::asio::error::fault;
        LOG_ERROR("bad server hello session data {}", ec.message());
        return std::unexpected(ec);
    }

    const auto cipher_suite = static_cast<std::uint16_t>((sh_data[pos] << 8) | sh_data[pos + 1]);
    return cipher_suite;
}

std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> derive_client_auth_key_material(
    const std::uint8_t* private_key,
    const std::vector<std::uint8_t>& server_pub_key)
{
    auto shared_result = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), server_pub_key);
    LOG_DEBUG("using server pub key size {}", server_pub_key.size());
    if (!shared_result)
    {
        return std::unexpected(shared_result.error());
    }

    std::vector<std::uint8_t> client_random(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    }

    const std::vector<std::uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto reality_label_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    auto pseudo_random_key_result = reality::crypto_util::hkdf_extract(salt, *shared_result, EVP_sha256());
    if (!pseudo_random_key_result)
    {
        return std::unexpected(pseudo_random_key_result.error());
    }
    auto auth_key_result = reality::crypto_util::hkdf_expand(*pseudo_random_key_result, reality_label_info, 16, EVP_sha256());
    if (!auth_key_result)
    {
        return std::unexpected(auth_key_result.error());
    }
    LOG_DEBUG("client auth material ready random {} bytes eph pub {} bytes", client_random.size(), 32);
    return std::make_pair(std::move(client_random), std::move(*auth_key_result));
}

bool build_client_hello_with_placeholder_sid(const reality::fingerprint_spec& spec,
                                             const std::vector<std::uint8_t>& client_random,
                                             const std::uint8_t* public_key,
                                             const std::string& sni,
                                             std::vector<std::uint8_t>& hello_body,
                                             std::uint32_t& absolute_sid_offset)
{
    const std::vector<std::uint8_t> placeholder_session_id(32, 0);
    hello_body = reality::client_hello_builder::build(
        spec, placeholder_session_id, client_random, std::vector<std::uint8_t>(public_key, public_key + 32), sni);

    std::vector<std::uint8_t> dummy_record =
        reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    dummy_record.insert(dummy_record.end(), hello_body.begin(), hello_body.end());

    const client_hello_info ch_info = ch_parser::parse(dummy_record);
    if (ch_info.sid_offset < 5)
    {
        LOG_ERROR("generated client hello session id offset invalid {}", ch_info.sid_offset);
        return false;
    }

    absolute_sid_offset = ch_info.sid_offset - 5;
    if (absolute_sid_offset + 32 > hello_body.size())
    {
        LOG_ERROR("session id offset out of bounds {} {}", absolute_sid_offset, hello_body.size());
        return false;
    }
    return true;
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> encrypt_client_session_id(
    const std::vector<std::uint8_t>& auth_key,
    const std::vector<std::uint8_t>& client_random,
    const std::array<std::uint8_t, reality::kAuthPayloadLen>& payload,
    const std::vector<std::uint8_t>& hello_body)
{
    auto sid_result = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                             auth_key,
                                             std::vector<std::uint8_t>(client_random.begin() + constants::auth::kSaltLen, client_random.end()),
                                             std::vector<std::uint8_t>(payload.begin(), payload.end()),
                                             hello_body);
    if (!sid_result || sid_result->size() != 32)
    {
        LOG_ERROR("auth encryption failed ct size {}", sid_result ? sid_result->size() : 0);
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    }
    return std::move(*sid_result);
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> build_authenticated_client_hello(
    const std::uint8_t* public_key,
    const std::uint8_t* private_key,
    const std::vector<std::uint8_t>& server_pub_key,
    const std::vector<std::uint8_t>& short_id_bytes,
    const std::array<std::uint8_t, 3>& client_ver,
    const reality::fingerprint_spec& spec,
    const std::string& sni)
{
    auto auth_material_result = derive_client_auth_key_material(private_key, server_pub_key);
    if (!auth_material_result)
    {
        return std::unexpected(auth_material_result.error());
    }
    auto [client_random, auth_key] = std::move(*auth_material_result);

    const auto now_seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const std::uint32_t now = static_cast<std::uint32_t>(now_seconds);
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    if (!reality::build_auth_payload(short_id_bytes, client_ver, now, payload))
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
    }

    std::vector<std::uint8_t> hello_body;
    std::uint32_t absolute_sid_offset = 0;
    if (!build_client_hello_with_placeholder_sid(spec, client_random, public_key, sni, hello_body, absolute_sid_offset))
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
    }

    auto sid_result = encrypt_client_session_id(auth_key, client_random, payload, hello_body);
    if (!sid_result)
    {
        return std::unexpected(sid_result.error());
    }

    std::memcpy(hello_body.data() + absolute_sid_offset, sid_result->data(), 32);
    return hello_body;
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

struct handshake_traffic_keys
{
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
};

std::expected<handshake_traffic_keys, boost::system::error_code> derive_handshake_traffic_keys(const reality::handshake_keys& hs_keys,
                                                                                                const std::uint16_t cipher_suite,
                                                                                                const EVP_MD* negotiated_md)
{
    const std::size_t key_len =
        (cipher_suite == 0x1302 || cipher_suite == 0x1303) ? constants::crypto::kKeyLen256 : constants::crypto::kKeyLen128;
    constexpr std::size_t iv_len = constants::crypto::kIvLen;
    auto c_hs = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, key_len, iv_len, negotiated_md);
    auto s_hs = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, key_len, iv_len, negotiated_md);
    if (!c_hs || !s_hs)
    {
        return std::unexpected(c_hs ? s_hs.error() : c_hs.error());
    }
    return handshake_traffic_keys{
        .c_hs_keys = std::move(*c_hs),
        .s_hs_keys = std::move(*s_hs)};
}

std::expected<void, boost::system::error_code> prepare_server_hello_crypto(const std::vector<std::uint8_t>& sh_data,
                                 reality::transcript& trans,
                                 std::uint16_t& cipher_suite,
                                 const EVP_MD*& md,
                                 const EVP_CIPHER*& cipher)
{
    trans.update(sh_data);
    const auto parse_suite_res = parse_server_hello_cipher_suite(sh_data);
    if (!parse_suite_res)
    {
        return std::unexpected(parse_suite_res.error());
    }
    cipher_suite = *parse_suite_res;
    const auto suite = reality::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_ERROR("unsupported server hello cipher suite {:x}", cipher_suite);
        return std::unexpected(boost::asio::error::no_protocol_option);
    }

    md = suite->md;
    cipher = suite->cipher;
    trans.set_protocol_hash(md);
    return {};
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> derive_server_hello_shared_secret(
    const std::uint8_t* private_key,
    const std::uint16_t key_share_group,
    const std::vector<std::uint8_t>& key_share_data)
{
    if (key_share_group != reality::tls_consts::group::kX25519)
    {
        LOG_ERROR("unsupported key share group {}", key_share_group);
        return std::unexpected(boost::asio::error::no_protocol_option);
    }
    if (key_share_data.size() != 32)
    {
        LOG_ERROR("invalid x25519 key share length {}", key_share_data.size());
        return std::unexpected(boost::asio::error::invalid_argument);
    }

    auto hs_shared_result = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), key_share_data);
    if (!hs_shared_result)
    {
        LOG_ERROR("handshake shared secret failed {}", hs_shared_result.error().message());
        return std::unexpected(hs_shared_result.error());
    }
    return std::move(*hs_shared_result);
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> process_handshake_record(boost::asio::ip::tcp::socket& socket,
                                               const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
                                               reality::transcript& trans,
                                               const EVP_CIPHER* cipher,
                                               std::vector<std::uint8_t>& handshake_buffer,
                                               handshake_validation_state& validation_state,
                                               bool& handshake_fin,
                                               const reality::handshake_keys& hs_keys,
                                               const EVP_MD* md,
                                               std::uint64_t& seq)
{
    const auto record_res = co_await read_encrypted_record(socket);
    if (!record_res)
    {
        co_return std::unexpected(record_res.error());
    }
    const auto& record = *record_res;
    if (record.content_type == reality::kContentTypeChangeCipherSpec)
    {
        LOG_DEBUG("received change cipher spec skip");
        co_return std::expected<void, boost::system::error_code>{};
    }

    std::uint8_t type = 0;
    auto plaintext_result = reality::tls_record_layer::decrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, record.ciphertext, type);
    if (!plaintext_result)
    {
        LOG_ERROR("error decrypting record {}", plaintext_result.error().message());
        co_return std::unexpected(plaintext_result.error());
    }
    if (type != reality::kContentTypeHandshake)
    {
        co_return std::expected<void, boost::system::error_code>{};
    }

    if (const auto consume_res =
            consume_handshake_plaintext(*plaintext_result, handshake_buffer, validation_state, handshake_fin, hs_keys, md, trans);
        !consume_res)
    {
        co_return std::unexpected(consume_res.error());
    }
    co_return std::expected<void, boost::system::error_code>{};
}

boost::asio::awaitable<std::expected<boost::asio::ip::tcp::resolver::results_type, boost::system::error_code>> resolve_remote_endpoints(boost::asio::io_context& io_context,
                                                                                                 const std::string& remote_host,
                                                                                                 const std::string& remote_port,
                                                                                                 const std::uint32_t timeout_sec,
                                                                                                 const connection_context& ctx)
{
    boost::asio::ip::tcp::resolver resolver(io_context);
    const auto resolve_res = co_await timeout_io::async_resolve_with_timeout(resolver, remote_host, remote_port, timeout_sec);
    if (resolve_res.timed_out)
    {
        statistics::instance().inc_client_tunnel_pool_resolve_timeouts();
        LOG_CTX_ERROR(
            ctx, "{} stage=resolve target={}:{} timeout={}s", log_event::kConnInit, remote_host, remote_port, timeout_sec);
        co_return std::unexpected(boost::asio::error::timed_out);
    }
    if (!resolve_res.ok)
    {
        statistics::instance().inc_client_tunnel_pool_resolve_errors();
        LOG_CTX_ERROR(
            ctx, "{} stage=resolve target={}:{} error={}", log_event::kConnInit, remote_host, remote_port, resolve_res.ec.message());
        co_return std::unexpected(resolve_res.ec);
    }
    co_return resolve_res.endpoints;
}

std::expected<void, boost::system::error_code> prepare_socket_for_connect(boost::asio::ip::tcp::socket& socket,
                                const boost::asio::ip::tcp::endpoint& endpoint,
                                const std::uint32_t mark)
{
    boost::system::error_code socket_ec;
    if (socket.is_open())
    {
        socket_ec = socket.close(socket_ec);
    }
    socket_ec = socket.open(endpoint.protocol(), socket_ec);
    if (socket_ec)
    {
        return std::unexpected(socket_ec);
    }
    if (mark != 0)
    {
        if (auto set_mark_result = net::set_socket_mark(socket.native_handle(), mark); !set_mark_result)
        {
            LOG_WARN("set mark failed {}", set_mark_result.error().message());
        }
    }
    return {};
}

void log_tcp_connect_success(const boost::asio::ip::tcp::socket& socket, const boost::asio::ip::tcp::endpoint& endpoint)
{
    boost::system::error_code local_ep_ec;
    const auto local_ep = socket.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_DEBUG("tcp connected endpoint {}", endpoint.address().to_string());
        return;
    }
    LOG_DEBUG("tcp connected {} <-> {}", local_ep.address().to_string(), endpoint.address().to_string());
}

}    // namespace

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg, const std::uint32_t mark)
    : mark_(mark),
      remote_host_(cfg.outbound.host),
      remote_port_(std::to_string(cfg.outbound.port)),
      sni_(cfg.reality.sni),
      strict_cert_verify_(cfg.reality.strict_cert_verify),
      pool_(pool),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    server_pub_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.public_key);
    if (server_pub_key_.size() != 32)
    {
        LOG_ERROR("server public key length invalid {}", server_pub_key_.size());
        auth_config_valid_ = false;
    }
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id") && auth_config_valid_;
    if (!parse_fingerprint_type(cfg.reality.fingerprint, fingerprint_type_))
    {
        LOG_ERROR("fingerprint invalid");
        auth_config_valid_ = false;
    }
}

void client_tunnel_pool::start()
{
    stop_.store(false, std::memory_order_release);
    if (!auth_config_valid_)
    {
        LOG_ERROR("invalid reality auth config");
        stop_.store(true, std::memory_order_release);
        return;
    }

    LOG_INFO("client pool starting target {} port {} with {} connections", remote_host_, remote_port_, limits_config_.max_connections);
    const auto normalized_max_connections = normalize_max_connections(limits_config_.max_connections);
    if (normalized_max_connections != limits_config_.max_connections)
    {
        LOG_WARN("max connections is 0 using 1");
    }
    limits_config_.max_connections = normalized_max_connections;
    tunnel_pool_.resize(limits_config_.max_connections);
    pending_sockets_.resize(limits_config_.max_connections);
    tunnel_io_contexts_.resize(limits_config_.max_connections, nullptr);

    for (std::uint32_t i = 0; i < limits_config_.max_connections; ++i)
    {
        auto* io_context = &pool_.get_io_context();
        tunnel_io_contexts_[i] = io_context;
        boost::asio::co_spawn(
            *io_context,
            [this, i, io_context, self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await connect_remote_loop(i, *io_context); },
            boost::asio::detached);
    }
}

void client_tunnel_pool::close_pending_socket(const std::size_t index, std::shared_ptr<boost::asio::ip::tcp::socket> pending_socket)
{
    auto* io_context = (index < tunnel_io_contexts_.size()) ? tunnel_io_contexts_[index] : nullptr;
    if (io_context != nullptr)
    {
        detail::dispatch_cleanup_or_run_inline(
            *io_context,
            [pending_socket = std::move(pending_socket)]()
            {
                boost::system::error_code ec;
                ec = pending_socket->cancel(ec);
                ec = pending_socket->close(ec);
            },
            detail::dispatch_timeout_policy::kRunInline);
        return;
    }

    boost::system::error_code ec;
    ec = pending_socket->cancel(ec);
    ec = pending_socket->close(ec);
}

void client_tunnel_pool::release_all_pending_sockets()
{
    for (std::size_t i = 0; i < pending_sockets_.size(); ++i)
    {
        auto pending_socket = atomic_exchange_shared(pending_sockets_[i]);
        if (pending_socket == nullptr)
        {
            continue;
        }
        close_pending_socket(i, std::move(pending_socket));
    }
}

void client_tunnel_pool::release_all_tunnels()
{
    for (auto& tunnel : tunnel_pool_)
    {
        auto current_tunnel = atomic_exchange_shared(tunnel);
        if (current_tunnel != nullptr && current_tunnel->connection() != nullptr)
        {
            current_tunnel->connection()->release_resources();
        }
    }
}

void client_tunnel_pool::stop()
{
    LOG_INFO("client pool stopping closing resources");
    stop_.store(true, std::memory_order_release);
    release_all_pending_sockets();
    release_all_tunnels();
}

std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> client_tunnel_pool::select_tunnel()
{
    if (tunnel_pool_.empty())
    {
        return nullptr;
    }

    const auto start_index = next_tunnel_index_.fetch_add(1, std::memory_order_relaxed);
    for (std::size_t i = 0; i < tunnel_pool_.size(); ++i)
    {
        const std::size_t idx = (start_index + i) % tunnel_pool_.size();
        const auto tunnel = atomic_load_shared(tunnel_pool_[idx]);
        if (tunnel != nullptr && tunnel->connection() != nullptr && tunnel->connection()->is_open())
        {
            return tunnel;
        }
    }

    return nullptr;
}

std::uint32_t client_tunnel_pool::next_session_id() { return next_session_id_++; }

std::shared_ptr<boost::asio::ip::tcp::socket> client_tunnel_pool::create_pending_socket(boost::asio::io_context& io_context, const std::uint32_t index)
{
    const auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    if (index < pending_sockets_.size())
    {
        atomic_store_shared(pending_sockets_[index], socket);
    }
    return socket;
}

void client_tunnel_pool::clear_pending_socket_if_match(const std::uint32_t index, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
{
    if (index >= pending_sockets_.size())
    {
        return;
    }
    atomic_clear_if_match(pending_sockets_[index], socket);
}

bool client_tunnel_pool::publish_tunnel(const std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel)
{
    if (index >= tunnel_pool_.size())
    {
        return false;
    }
    if (stop_.load(std::memory_order_acquire))
    {
        return false;
    }

    atomic_store_shared(tunnel_pool_[index], tunnel);
    if (stop_.load(std::memory_order_acquire))
    {
        atomic_clear_if_match(tunnel_pool_[index], tunnel);
        return false;
    }
    return true;
}

void client_tunnel_pool::clear_tunnel_if_match(const std::uint32_t index,
                                               const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel)
{
    if (index >= tunnel_pool_.size())
    {
        return;
    }
    atomic_clear_if_match(tunnel_pool_[index], tunnel);
}

std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> client_tunnel_pool::build_tunnel(boost::asio::ip::tcp::socket socket,
                                                                                           boost::asio::io_context& io_context,
                                                                                           const std::uint32_t cid,
                                                                                           const handshake_result& handshake_ret,
                                                                                           const std::string& trace_id) const
{
    const std::size_t key_len = (handshake_ret.cipher_suite == 0x1302 || handshake_ret.cipher_suite == 0x1303) ? constants::crypto::kKeyLen256
                                                                                                                   : constants::crypto::kKeyLen128;
    auto c_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.c_app_secret, key_len, constants::crypto::kIvLen, handshake_ret.md);
    auto s_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.s_app_secret, key_len, constants::crypto::kIvLen, handshake_ret.md);
    if (!c_app_keys || !s_app_keys)
    {
        LOG_ERROR("derive app traffic keys failed");
        return nullptr;
    }

    reality_engine re(s_app_keys->first,
                      s_app_keys->second,
                      c_app_keys->first,
                      c_app_keys->second,
                      handshake_ret.cipher);
    return std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        std::move(socket), io_context, std::move(re), true, cid, trace_id, timeout_config_, limits_config_, heartbeat_config_);
}

boost::asio::awaitable<void> client_tunnel_pool::handle_connection_failure(const std::uint32_t index,
                                                                    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                    const boost::system::error_code& ec,
                                                                    const char* stage,
                                                                    const connection_context& ctx,
                                                                    boost::asio::io_context& io_context)
{
    clear_pending_socket_if_match(index, socket);
    LOG_CTX_ERROR(ctx,
                  "{} stage={} target={}:{} error={} retry_in={}s",
                  log_event::kConnClose,
                  stage,
                  remote_host_,
                  remote_port_,
                  ec.message(),
                  constants::net::kRetryIntervalSec);
    co_await wait_remote_retry(io_context);
}

boost::asio::awaitable<bool> client_tunnel_pool::establish_tunnel_for_connection(
    const std::uint32_t index,
    boost::asio::io_context& io_context,
    const std::uint32_t cid,
    const std::string& trace_id,
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel)
{
    boost::system::error_code ec;
    connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.conn_id(cid);
    if (const auto res = co_await tcp_connect(io_context, *socket, ctx); !res)
    {
        ec = res.error();
        co_await handle_connection_failure(index, socket, ec, "connect", ctx, io_context);
        co_return false;
    }

    const auto handshake_res = co_await perform_reality_handshake_with_timeout(socket, ctx);
    if (!handshake_res)
    {
        ec = handshake_res.error();
        co_await handle_connection_failure(index, socket, ec, "handshake", ctx, io_context);
        co_return false;
    }
    const auto& handshake_ret = *handshake_res;

    LOG_CTX_INFO(ctx, "{} handshake success cipher 0x{:04x}", log_event::kHandshake, handshake_ret.cipher_suite);

    tunnel = build_tunnel(std::move(*socket), io_context, cid, handshake_ret, trace_id);
    if (tunnel == nullptr)
    {
        const auto derive_ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        co_await handle_connection_failure(index, socket, derive_ec, "derive app keys", ctx, io_context);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<std::expected<client_tunnel_pool::handshake_result, boost::system::error_code>> client_tunnel_pool::perform_reality_handshake_with_timeout(
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) const
{
    const connection_context ctx;
    co_return co_await perform_reality_handshake_with_timeout(socket, ctx);
}

boost::asio::awaitable<std::expected<client_tunnel_pool::handshake_result, boost::system::error_code>> client_tunnel_pool::perform_reality_handshake_with_timeout(
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
    const connection_context& ctx) const
{
    if (!socket)
    {
        statistics::instance().inc_client_tunnel_pool_handshake_errors();
        LOG_CTX_ERROR(
            ctx, "{} stage=handshake target={}:{} error=invalid_socket", log_event::kHandshake, remote_host_, remote_port_);
        co_return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
    }
    const auto timeout_sec = timeout_config_.read;
    auto timeout_state = timeout_io::arm_socket_timeout(socket, std::chrono::seconds(timeout_sec), "handshake");

    auto handshake_res = co_await perform_reality_handshake(*socket);
    if (timeout_io::disarm_timeout(timeout_state))
    {
        statistics::instance().inc_client_tunnel_pool_handshake_timeouts();
        LOG_CTX_ERROR(
            ctx, "{} stage=handshake target={}:{} timeout={}s", log_event::kHandshake, remote_host_, remote_port_, timeout_sec);
        co_return std::unexpected(boost::asio::error::timed_out);
    }
    if (!handshake_res)
    {
        auto& stats = statistics::instance();
        if (handshake_res.error() == boost::asio::error::timed_out)
        {
            stats.inc_client_tunnel_pool_handshake_timeouts();
            LOG_CTX_ERROR(
                ctx, "{} stage=handshake target={}:{} timeout={}s", log_event::kHandshake, remote_host_, remote_port_, timeout_sec);
        }
        else
        {
            stats.inc_client_tunnel_pool_handshake_errors();
            LOG_CTX_ERROR(
                ctx,
                "{} stage=handshake target={}:{} error={}",
                log_event::kHandshake,
                remote_host_,
                remote_port_,
                handshake_res.error().message());
        }
    }
    co_return handshake_res;
}

boost::asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index, boost::asio::io_context& io_context)
{
    while (!stop_.load(std::memory_order_acquire))
    {
        const std::uint32_t cid = next_conn_id_++;
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(cid);
        LOG_CTX_INFO(ctx,
                     "{} initiating connection {}/{} to {} {}",
                     log_event::kConnInit,
                     index + 1,
                     limits_config_.max_connections,
                     remote_host_,
                     remote_port_);

        const auto socket = create_pending_socket(io_context, index);
        std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel;
        if (!co_await establish_tunnel_for_connection(index, io_context, cid, ctx.trace_id(), socket, tunnel))
        {
            continue;
        }

        const auto action = prepare_tunnel_for_run(index, socket, tunnel);
        if (action == connect_loop_action::kStopLoop)
        {
            break;
        }
        if (action == connect_loop_action::kRetryLater)
        {
            co_await wait_remote_retry(io_context);
            continue;
        }

        co_await tunnel->run();

        clear_tunnel_if_match(index, tunnel);
        clear_pending_socket_if_match(index, socket);

        co_await wait_remote_retry(io_context);
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

client_tunnel_pool::connect_loop_action client_tunnel_pool::prepare_tunnel_for_run(
    const std::uint32_t index,
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
    const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel)
{
    if (stop_.load(std::memory_order_acquire))
    {
        clear_pending_socket_if_match(index, socket);
        return connect_loop_action::kStopLoop;
    }

    if (const auto connection = tunnel->connection(); connection != nullptr)
    {
        connection->mark_started_for_external_calls();
    }
    if (!publish_tunnel(index, tunnel))
    {
        clear_pending_socket_if_match(index, socket);
        if (const auto connection = tunnel->connection(); connection != nullptr)
        {
            connection->release_resources();
        }
        if (stop_.load(std::memory_order_acquire))
        {
            return connect_loop_action::kStopLoop;
        }
        return connect_loop_action::kRetryLater;
    }

    clear_pending_socket_if_match(index, socket);
    return connect_loop_action::kRunTunnel;
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> client_tunnel_pool::tcp_connect(boost::asio::io_context& io_context,
                                                                                       boost::asio::ip::tcp::socket& socket) const
{
    const connection_context ctx;
    co_return co_await tcp_connect(io_context, socket, ctx);
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> client_tunnel_pool::tcp_connect(boost::asio::io_context& io_context,
                                                                                       boost::asio::ip::tcp::socket& socket,
                                                                                       const connection_context& ctx) const
{
    const auto timeout_sec = timeout_config_.read;
    const auto resolve_endpoints = co_await resolve_remote_endpoints(io_context, remote_host_, remote_port_, timeout_sec, ctx);
    if (!resolve_endpoints)
    {
        co_return std::unexpected(resolve_endpoints.error());
    }

    boost::system::error_code last_ec = boost::asio::error::host_unreachable;

    for (const auto& entry : resolve_endpoints.value())
    {
        const auto endpoint = entry.endpoint();

        if (const auto res = prepare_socket_for_connect(socket, endpoint, mark_); !res)
        {
            last_ec = res.error();
            continue;
        }
        if (const auto res = co_await try_connect_endpoint(socket, endpoint); res)
        {
            co_return std::expected<void, boost::system::error_code>{};
        }
        else
        {
            last_ec = res.error();
        }
    }

    auto& stats = statistics::instance();
    if (last_ec == boost::asio::error::timed_out)
    {
        stats.inc_client_tunnel_pool_connect_timeouts();
        LOG_CTX_ERROR(
            ctx, "{} stage=connect target={}:{} timeout={}s", log_event::kConnInit, remote_host_, remote_port_, timeout_sec);
    }
    else
    {
        stats.inc_client_tunnel_pool_connect_errors();
        LOG_CTX_ERROR(
            ctx, "{} stage=connect target={}:{} error={}", log_event::kConnInit, remote_host_, remote_port_, last_ec.message());
    }
    co_return std::unexpected(last_ec);
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> client_tunnel_pool::try_connect_endpoint(boost::asio::ip::tcp::socket& socket,
                                                               const boost::asio::ip::tcp::endpoint& endpoint) const
{
    const auto timeout_sec = timeout_config_.read;
    const auto connect_res = co_await timeout_io::async_connect_with_timeout(socket, endpoint, timeout_sec, "connect");
    if (connect_res.timed_out)
    {
        co_return std::unexpected(boost::asio::error::timed_out);
    }
    if (!connect_res.ok)
    {
        co_return std::unexpected(connect_res.ec);
    }

    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("set no delay failed {}", ec.message());
    }
    log_tcp_connect_success(socket, endpoint);
    co_return std::expected<void, boost::system::error_code>{};
}

boost::asio::awaitable<std::expected<client_tunnel_pool::handshake_result, boost::system::error_code>> client_tunnel_pool::perform_reality_handshake(boost::asio::ip::tcp::socket& socket) const
{
    std::uint8_t public_key[32];
    std::uint8_t private_key[32];

    if (!reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        co_return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    }

    const std::shared_ptr<void> defer_cleanse(nullptr, [&](void*) { OPENSSL_cleanse(private_key, 32); });

    const auto spec = select_fingerprint_spec(fingerprint_type_);
    reality::transcript trans;
    if (const auto res = co_await generate_and_send_client_hello(socket, public_key, private_key, spec, trans); !res)
    {
        co_return std::unexpected(res.error());
    }

    const auto server_hello_result = co_await process_server_hello(socket, private_key, trans);
    if (!server_hello_result)
    {
        co_return std::unexpected(server_hello_result.error());
    }

    const auto handshake_traffic_keys_result =
        derive_handshake_traffic_keys(server_hello_result->hs_keys, server_hello_result->cipher_suite, server_hello_result->negotiated_md);
    if (!handshake_traffic_keys_result)
    {
        co_return std::unexpected(handshake_traffic_keys_result.error());
    }
    const auto& hs_keys = *handshake_traffic_keys_result;

    auto handshake_read_result = co_await handshake_read_loop(socket,
                                                              hs_keys.s_hs_keys,
                                                              server_hello_result->hs_keys,
                                                              strict_cert_verify_,
                                                              sni_,
                                                              trans,
                                                              server_hello_result->negotiated_cipher,
                                                              server_hello_result->negotiated_md);
    if (!handshake_read_result)
    {
        co_return std::unexpected(handshake_read_result.error());
    }
    auto [c_app_secret, s_app_secret] = std::move(*handshake_read_result);

    if (const auto res = co_await send_client_finished(
            socket,
            hs_keys.c_hs_keys,
            server_hello_result->hs_keys.client_handshake_traffic_secret,
            trans,
            server_hello_result->negotiated_cipher,
            server_hello_result->negotiated_md);
        !res)
    {
        co_return std::unexpected(res.error());
    }

    handshake_result result{
        .c_app_secret = std::move(c_app_secret),
        .s_app_secret = std::move(s_app_secret),
        .cipher_suite = server_hello_result->cipher_suite,
        .md = server_hello_result->negotiated_md,
        .cipher = server_hello_result->negotiated_cipher};
    co_return result;
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> client_tunnel_pool::generate_and_send_client_hello(boost::asio::ip::tcp::socket& socket,
                                                                                                                           const std::uint8_t* public_key,
                                                                                                                           const std::uint8_t* private_key,
                                                                                                                           const reality::fingerprint_spec& spec,
                                                                                                                           reality::transcript& trans) const
{
    auto client_hello_body_result = build_authenticated_client_hello(public_key, private_key, server_pub_key_, short_id_bytes_, client_ver_, spec, sni_);
    if (!client_hello_body_result)
    {
        co_return std::unexpected(client_hello_body_result.error());
    }
    const auto& hello_body = *client_hello_body_result;

    auto client_hello_record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    client_hello_record.insert(client_hello_record.end(), hello_body.begin(), hello_body.end());

    auto [write_ec, write_size] =
        co_await boost::asio::async_write(socket, boost::asio::buffer(client_hello_record), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (write_ec)
    {
        LOG_ERROR("error sending client hello {}", write_ec.message());
        co_return std::unexpected(write_ec);
    }
    if (write_size != client_hello_record.size())
    {
        LOG_ERROR("short write client hello {} of {}", write_size, client_hello_record.size());
        co_return std::unexpected(boost::asio::error::fault);
    }
    LOG_DEBUG("sending client hello record size {}", client_hello_record.size());
    trans.update(hello_body);
    co_return std::expected<void, boost::system::error_code>{};
}

boost::asio::awaitable<std::expected<client_tunnel_pool::server_hello_res, boost::system::error_code>> client_tunnel_pool::process_server_hello(boost::asio::ip::tcp::socket& socket,
                                                                                                                         const std::uint8_t* private_key,
                                                                                                                         reality::transcript& trans)
{
    const auto server_hello_data_result = co_await read_handshake_record_body(socket, "server hello");
    if (!server_hello_data_result)
    {
        co_return std::unexpected(server_hello_data_result.error());
    }
    const auto& sh_data = *server_hello_data_result;
    LOG_DEBUG("server hello received size {}", sh_data.size());

    std::uint16_t cipher_suite = 0;
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    if (const auto res = prepare_server_hello_crypto(sh_data, trans, cipher_suite, md, cipher); !res)
    {
        co_return std::unexpected(res.error());
    }

    const auto key_share = reality::extract_server_key_share(sh_data);
    LOG_DEBUG("rx server hello size {}", sh_data.size());
    if (!key_share.has_value())
    {
        LOG_ERROR("bad server hello key share");
        co_return std::unexpected(boost::asio::error::invalid_argument);
    }

    auto handshake_shared_secret_result = derive_server_hello_shared_secret(private_key, key_share->group, key_share->data);
    if (!handshake_shared_secret_result)
    {
        co_return std::unexpected(handshake_shared_secret_result.error());
    }

    auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(*handshake_shared_secret_result, trans.finish(), md);
    if (!hs_keys)
    {
        LOG_ERROR("derive handshake keys failed {}", hs_keys.error().message());
        co_return std::unexpected(hs_keys.error());
    }

    co_return server_hello_res{.hs_keys = *hs_keys, .negotiated_md = md, .negotiated_cipher = cipher, .cipher_suite = cipher_suite};
}

boost::asio::awaitable<std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code>> client_tunnel_pool::handshake_read_loop(
    boost::asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
    const reality::handshake_keys& hs_keys,
    const bool strict_cert_verify,
    const std::string& sni,
    reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md)
{
    bool handshake_fin = false;
    handshake_validation_state validation_state;
    std::uint64_t seq = 0;
    std::vector<std::uint8_t> handshake_buffer;

    while (!handshake_fin)
    {
        if (const auto res = co_await process_handshake_record(
                socket, s_hs_keys, trans, cipher, handshake_buffer, validation_state, handshake_fin, hs_keys, md, seq); !res)
        {
            co_return std::unexpected(res.error());
        }
    }

    if (const auto res = validate_server_handshake_chain(validation_state, strict_cert_verify, sni); !res)
    {
        co_return std::unexpected(res.error());
    }

    auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md);
    if (!app_sec)
    {
        LOG_ERROR("derive app secrets failed {}", app_sec.error().message());
        co_return std::unexpected(app_sec.error());
    }
    co_return *app_sec;
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> client_tunnel_pool::send_client_finished(boost::asio::ip::tcp::socket& socket,
                                                                   const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                                   const std::vector<std::uint8_t>& c_hs_secret,
                                                                   const reality::transcript& trans,
                                                                   const EVP_CIPHER* cipher,
                                                                   const EVP_MD* md)
{
    auto fin_verify_result = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), md);
    if (!fin_verify_result)
    {
        co_return std::unexpected(fin_verify_result.error());
    }
    const auto fin_msg = reality::construct_finished(*fin_verify_result);
    auto fin_rec_result =
        reality::tls_record_layer::encrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, fin_msg, reality::kContentTypeHandshake);
    if (!fin_rec_result)
    {
        co_return std::unexpected(fin_rec_result.error());
    }

    std::vector<std::uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    out_flight.insert(out_flight.end(), fin_rec_result->begin(), fin_rec_result->end());

    auto [write_error, write_len] = co_await boost::asio::async_write(socket, boost::asio::buffer(out_flight), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (write_error)
    {
        LOG_ERROR("send client finished flight error {}", write_error.message());
        co_return std::unexpected(write_error);
    }
    LOG_DEBUG("sending client finished flight size {}", out_flight.size());
    co_return std::expected<void, boost::system::error_code>{};
}

boost::asio::awaitable<void> client_tunnel_pool::wait_remote_retry(boost::asio::io_context& io_context)
{
    if (stop_.load(std::memory_order_acquire))
    {
        co_return;
    }
    boost::asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(constants::net::kRetryIntervalSec));
    const auto [ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("remote retry timer error {}", ec.message());
    }
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
