#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
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
#include <system_error>

#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/connect.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

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
#include "statistics.h"
#include "net_utils.h"
#include "transcript.h"
#include "crypto_util.h"
#include "log_context.h"
#include "reality_auth.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_cipher_suite.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "stop_dispatch.h"
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
        {"chrome", reality::fingerprint_type::kChrome120},
        {"chrome_120", reality::fingerprint_type::kChrome120},
        {"firefox", reality::fingerprint_type::kFirefox120},
        {"firefox_120", reality::fingerprint_type::kFirefox120},
        {"ios", reality::fingerprint_type::kIOS14},
        {"ios_14", reality::fingerprint_type::kIOS14},
        {"android", reality::fingerprint_type::kAndroid11OkHttp},
        {"android_11_okhttp", reality::fingerprint_type::kAndroid11OkHttp},
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
    value = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
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
    msg_len = (handshake_buffer[offset + 1] << 16) | (handshake_buffer[offset + 2] << 8) | handshake_buffer[offset + 3];
    return offset + 4 + msg_len <= handshake_buffer.size();
}

struct handshake_validation_state
{
    bool cert_checked = false;
    bool cert_verify_checked = false;
    bool cert_verify_signature_checked = false;
    reality::openssl_ptrs::evp_pkey_ptr server_pub_key = nullptr;
};

std::expected<void, std::error_code> load_server_public_key_from_certificate(const std::vector<std::uint8_t>& msg_data,
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
        return std::unexpected(asio::error::invalid_argument);
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

std::expected<void, std::error_code> verify_server_certificate_verify_message(const std::vector<std::uint8_t>& msg_data,
                                                                              const reality::transcript& trans,
                                                                              handshake_validation_state& validation_state)
{
    if (!validation_state.cert_checked)
    {
        LOG_ERROR("certificate verify received before certificate");
        return std::unexpected(asio::error::invalid_argument);
    }

    const auto cert_verify = reality::parse_certificate_verify(msg_data);
    if (!cert_verify.has_value())
    {
        LOG_ERROR("certificate verify parse failed");
        return std::unexpected(asio::error::invalid_argument);
    }
    if (!reality::is_supported_certificate_verify_scheme(cert_verify->scheme))
    {
        LOG_ERROR("unsupported certificate verify scheme {:x}", cert_verify->scheme);
        return std::unexpected(asio::error::no_protocol_option);
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

std::expected<void, std::error_code> verify_server_finished_message(const std::vector<std::uint8_t>& msg_data,
                                                                    const reality::handshake_keys& hs_keys,
                                                                    const EVP_MD* md,
                                                                    const reality::transcript& trans)
{
    // handshake_read_loop only calls this helper after message type and bounds validation.
    const std::uint32_t msg_len = (msg_data[1] << 16) | (msg_data[2] << 8) | msg_data[3];

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
        return std::unexpected(asio::error::invalid_argument);
    }

    if (CRYPTO_memcmp(msg_data.data() + 4, expected_verify_data->data(), expected_verify_data->size()) != 0)
    {
        LOG_ERROR("server finished verify mismatch");
        return std::unexpected(std::make_error_code(std::errc::permission_denied));
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

asio::awaitable<std::expected<encrypted_record, std::error_code>> read_encrypted_record(asio::ip::tcp::socket& socket)
{
    std::uint8_t rh[5];
    auto [re3, rn3] = co_await asio::async_read(socket, asio::buffer(rh, 5), asio::as_tuple(asio::use_awaitable));
    if (re3)
    {
        LOG_ERROR("error reading record header {}", re3.message());
        co_return std::unexpected(re3);
    }

    const auto n = static_cast<std::uint16_t>((rh[3] << 8) | rh[4]);
    std::vector<std::uint8_t> rec(n);
    auto [re4, rn4] = co_await asio::async_read(socket, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
    if (re4)
    {
        LOG_ERROR("error reading record payload {}", re4.message());
        co_return std::unexpected(re4);
    }
    if (rn4 != n)
    {
        const auto ec = asio::error::fault;
        LOG_ERROR("short read record payload {} of {}", rn4, n);
        co_return std::unexpected(ec);
    }

    std::vector<std::uint8_t> ciphertext(5 + n);
    std::memcpy(ciphertext.data(), rh, 5);
    std::memcpy(ciphertext.data() + 5, rec.data(), n);
    co_return encrypted_record{.content_type = rh[0], .ciphertext = std::move(ciphertext)};
}

std::expected<void, std::error_code> consume_handshake_plaintext(const std::vector<std::uint8_t>& plaintext,
                                                                 std::vector<std::uint8_t>& handshake_buffer,
                                                                 handshake_validation_state& validation_state,
                                                                 bool& handshake_fin,
                                                                 const reality::handshake_keys& hs_keys,
                                                                 const EVP_MD* md,
                                                                 reality::transcript& trans)
{
    handshake_buffer.insert(handshake_buffer.end(), plaintext.begin(), plaintext.end());
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
                return std::unexpected(asio::error::invalid_argument);
            }
            if (const auto res = verify_server_finished_message(msg_data, hs_keys, md, trans); !res)
            {
                return std::unexpected(res.error());
            }
            handshake_fin = true;
        }

        trans.update(msg_data);
        offset += 4 + msg_len;
    }

    handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + offset);
    return {};
}

asio::awaitable<std::expected<std::vector<std::uint8_t>, std::error_code>> read_handshake_record_body(asio::ip::tcp::socket& socket,
                                                                                                        const char* step)
{
    std::uint8_t header[5];
    auto [read_header_ec, read_header_n] = co_await asio::async_read(socket, asio::buffer(header, 5), asio::as_tuple(asio::use_awaitable));
    if (read_header_ec)
    {
        LOG_ERROR("error reading {} header {}", step, read_header_ec.message());
        co_return std::unexpected(read_header_ec);
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    std::vector<std::uint8_t> body(body_len);
    auto [read_body_ec, read_body_n] = co_await asio::async_read(socket, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    if (read_body_ec)
    {
        LOG_ERROR("error reading {} body {}", step, read_body_ec.message());
        co_return std::unexpected(read_body_ec);
    }
    if (read_body_n != body_len)
    {
        const auto ec = asio::error::fault;
        LOG_ERROR("short read {} body {} of {}", step, read_body_n, body_len);
        co_return std::unexpected(ec);
    }

    co_return body;
}

std::expected<std::uint16_t, std::error_code> parse_server_hello_cipher_suite(const std::vector<std::uint8_t>& sh_data)
{
    std::size_t pos = 4 + 2 + 32;
    if (pos >= sh_data.size())
    {
        const std::error_code ec = asio::error::fault;
        LOG_ERROR("bad server hello {}", ec.message());
        return std::unexpected(ec);
    }

    const std::uint8_t sid_len = sh_data[pos];
    pos += 1 + sid_len;
    if (pos + 2 > sh_data.size())
    {
        const std::error_code ec = asio::error::fault;
        LOG_ERROR("bad server hello session data {}", ec.message());
        return std::unexpected(ec);
    }

    const auto cipher_suite = static_cast<std::uint16_t>((sh_data[pos] << 8) | sh_data[pos + 1]);
    return cipher_suite;
}

std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, std::error_code> derive_client_auth_key_material(
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
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }

    const std::vector<std::uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    auto prk = reality::crypto_util::hkdf_extract(salt, *shared_result, EVP_sha256());
    if (!prk)
    {
        return std::unexpected(prk.error());
    }
    auto auth_key_result = reality::crypto_util::hkdf_expand(*prk, r_info, 16, EVP_sha256());
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
        LOG_ERROR("generated client hello session id offset is invalid: {}", ch_info.sid_offset);
        return false;
    }

    absolute_sid_offset = ch_info.sid_offset - 5;
    if (absolute_sid_offset + 32 > hello_body.size())
    {
        LOG_ERROR("session id offset out of bounds: {} / {}", absolute_sid_offset, hello_body.size());
        return false;
    }
    return true;
}

std::expected<std::vector<std::uint8_t>, std::error_code> encrypt_client_session_id(
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
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    return std::move(*sid_result);
}

std::expected<std::vector<std::uint8_t>, std::error_code> build_authenticated_client_hello(
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

    const std::uint32_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    if (!reality::build_auth_payload(short_id_bytes, client_ver, now, payload))
    {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    std::vector<std::uint8_t> hello_body;
    std::uint32_t absolute_sid_offset = 0;
    if (!build_client_hello_with_placeholder_sid(spec, client_random, public_key, sni, hello_body, absolute_sid_offset))
    {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
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

std::expected<handshake_traffic_keys, std::error_code> derive_handshake_traffic_keys(const reality::handshake_keys& hs_keys,
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

std::expected<void, std::error_code> prepare_server_hello_crypto(const std::vector<std::uint8_t>& sh_data,
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
        return std::unexpected(asio::error::no_protocol_option);
    }

    md = suite->md;
    cipher = suite->cipher;
    trans.set_protocol_hash(md);
    return {};
}

std::expected<std::vector<std::uint8_t>, std::error_code> derive_server_hello_shared_secret(
    const std::uint8_t* private_key,
    const std::uint16_t key_share_group,
    const std::vector<std::uint8_t>& key_share_data)
{
    if (key_share_group != reality::tls_consts::group::kX25519)
    {
        LOG_ERROR("unsupported key share group {}", key_share_group);
        return std::unexpected(asio::error::no_protocol_option);
    }
    if (key_share_data.size() != 32)
    {
        LOG_ERROR("invalid x25519 key share length {}", key_share_data.size());
        return std::unexpected(asio::error::invalid_argument);
    }

    auto hs_shared_result = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), key_share_data);
    if (!hs_shared_result)
    {
        LOG_ERROR("handshake shared secret failed {}", hs_shared_result.error().message());
        return std::unexpected(hs_shared_result.error());
    }
    return std::move(*hs_shared_result);
}

asio::awaitable<std::expected<void, std::error_code>> process_handshake_record(asio::ip::tcp::socket& socket,
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
        co_return std::expected<void, std::error_code>{};
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
        co_return std::expected<void, std::error_code>{};
    }

    if (const auto consume_res =
            consume_handshake_plaintext(*plaintext_result, handshake_buffer, validation_state, handshake_fin, hs_keys, md, trans);
        !consume_res)
    {
        co_return std::unexpected(consume_res.error());
    }
    co_return std::expected<void, std::error_code>{};
}

asio::awaitable<std::expected<asio::ip::tcp::resolver::results_type, std::error_code>> resolve_remote_endpoints(asio::io_context& io_context,
                                                                                                 const std::string& remote_host,
                                                                                                 const std::string& remote_port)
{
    asio::ip::tcp::resolver resolver(io_context);
    auto [resolve_error, resolve_endpoints] = co_await resolver.async_resolve(remote_host, remote_port, asio::as_tuple(asio::use_awaitable));
    if (resolve_error)
    {
        LOG_ERROR("resolve {} failed {}", remote_host, resolve_error.message());
        co_return std::unexpected(resolve_error);
    }
    co_return resolve_endpoints;
}

std::expected<void, std::error_code> prepare_socket_for_connect(asio::ip::tcp::socket& socket,
                                const asio::ip::tcp::endpoint& endpoint,
                                const std::uint32_t mark)
{
    std::error_code socket_ec;
    if (socket.is_open())
    {
        socket.close(socket_ec);
    }
    socket_ec = socket.open(endpoint.protocol(), socket_ec);
    if (socket_ec)
    {
        return std::unexpected(socket_ec);
    }
    if (mark != 0)
    {
        if (auto r = net::set_socket_mark(socket.native_handle(), mark); !r)
        {
            LOG_WARN("set mark failed {}", r.error().message());
        }
    }
    return {};
}

void log_tcp_connect_success(const asio::ip::tcp::socket& socket, const asio::ip::tcp::endpoint& endpoint)
{
    std::error_code local_ep_ec;
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
        asio::co_spawn(
            *io_context,
            [this, i, io_context, self = shared_from_this()]() -> asio::awaitable<void> { co_await connect_remote_loop(i, *io_context); },
            asio::detached);
    }
}

void client_tunnel_pool::close_pending_socket(const std::size_t index, std::shared_ptr<asio::ip::tcp::socket> pending_socket)
{
    auto* io_context = (index < tunnel_io_contexts_.size()) ? tunnel_io_contexts_[index] : nullptr;
    if (io_context != nullptr)
    {
        detail::dispatch_cleanup_or_run_inline(
            *io_context,
            [pending_socket = std::move(pending_socket)]()
            {
                std::error_code ec;
                pending_socket->cancel(ec);
                pending_socket->close(ec);
            },
            detail::dispatch_timeout_policy::kRunInline);
        return;
    }

    std::error_code ec;
    pending_socket->cancel(ec);
    pending_socket->close(ec);
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

std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> client_tunnel_pool::select_tunnel()
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

std::shared_ptr<asio::ip::tcp::socket> client_tunnel_pool::create_pending_socket(asio::io_context& io_context, const std::uint32_t index)
{
    const auto socket = std::make_shared<asio::ip::tcp::socket>(io_context);
    if (index < pending_sockets_.size())
    {
        atomic_store_shared(pending_sockets_[index], socket);
    }
    return socket;
}

void client_tunnel_pool::clear_pending_socket_if_match(const std::uint32_t index, const std::shared_ptr<asio::ip::tcp::socket>& socket)
{
    if (index >= pending_sockets_.size())
    {
        return;
    }
    atomic_clear_if_match(pending_sockets_[index], socket);
}

bool client_tunnel_pool::publish_tunnel(const std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel)
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
                                               const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel)
{
    if (index >= tunnel_pool_.size())
    {
        return;
    }
    atomic_clear_if_match(tunnel_pool_[index], tunnel);
}

std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> client_tunnel_pool::build_tunnel(asio::ip::tcp::socket socket,
                                                                                           asio::io_context& io_context,
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
    return std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(
        std::move(socket), io_context, std::move(re), true, cid, trace_id, timeout_config_, limits_config_, heartbeat_config_);
}

asio::awaitable<void> client_tunnel_pool::handle_connection_failure(const std::uint32_t index,
                                                                    const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                                                    const std::error_code& ec,
                                                                    const char* stage,
                                                                    asio::io_context& io_context)
{
    clear_pending_socket_if_match(index, socket);
    LOG_ERROR("{} failed {} retry in {}s", stage, ec.message(), constants::net::kRetryIntervalSec);
    co_await wait_remote_retry(io_context);
}

asio::awaitable<bool> client_tunnel_pool::establish_tunnel_for_connection(
    const std::uint32_t index,
    asio::io_context& io_context,
    const std::uint32_t cid,
    const std::string& trace_id,
    const std::shared_ptr<asio::ip::tcp::socket>& socket,
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel)
{
    std::error_code ec;
    if (const auto res = co_await tcp_connect(io_context, *socket); !res)
    {
        ec = res.error();
        co_await handle_connection_failure(index, socket, ec, "connect", io_context);
        co_return false;
    }

    const auto handshake_res = co_await perform_reality_handshake_with_timeout(socket, io_context);
    if (!handshake_res)
    {
        ec = handshake_res.error();
        co_await handle_connection_failure(index, socket, ec, "handshake", io_context);
        co_return false;
    }
    const auto& handshake_ret = *handshake_res;

    connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.conn_id(cid);
    LOG_CTX_INFO(ctx, "{} handshake success cipher 0x{:04x}", log_event::kHandshake, handshake_ret.cipher_suite);

    tunnel = build_tunnel(std::move(*socket), io_context, cid, handshake_ret, trace_id);
    if (tunnel == nullptr)
    {
        const auto derive_ec = std::make_error_code(std::errc::protocol_error);
        co_await handle_connection_failure(index, socket, derive_ec, "derive app keys", io_context);
        co_return false;
    }
    co_return true;
}

asio::awaitable<std::expected<client_tunnel_pool::handshake_result, std::error_code>> client_tunnel_pool::perform_reality_handshake_with_timeout(
    const std::shared_ptr<asio::ip::tcp::socket>& socket,
    asio::io_context& io_context) const
{
    const auto timeout_sec = std::max<std::uint32_t>(1, timeout_config_.read);
    auto timer = std::make_shared<asio::steady_timer>(io_context);
    auto timeout_triggered = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(std::chrono::seconds(timeout_sec));
    timer->async_wait(
        [socket, timeout_triggered](const std::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timeout_triggered->store(true, std::memory_order_release);
            std::error_code cancel_ec;
            socket->cancel(cancel_ec);
            if (cancel_ec && cancel_ec != asio::error::bad_descriptor)
            {
                LOG_WARN("cancel handshake socket failed {}", cancel_ec.message());
            }

            std::error_code close_ec;
            close_ec = socket->close(close_ec);
            if (close_ec && close_ec != asio::error::bad_descriptor)
            {
                LOG_WARN("close handshake socket failed {}", close_ec.message());
            }
        });

    auto handshake_res = co_await perform_reality_handshake(*socket);
    const auto cancelled = timer->cancel();
    (void)cancelled;
    if (timeout_triggered->load(std::memory_order_acquire))
    {
        LOG_ERROR("reality handshake timeout {}s", timeout_sec);
        co_return std::unexpected(asio::error::timed_out);
    }
    co_return handshake_res;
}

asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index, asio::io_context& io_context)
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
        std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel;
        if (!co_await establish_tunnel_for_connection(index, io_context, cid, ctx.trace_id(), socket, tunnel))
        {
            continue;
        }

        if (stop_.load(std::memory_order_acquire))
        {
            clear_pending_socket_if_match(index, socket);
            break;
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
                break;
            }
            co_await wait_remote_retry(io_context);
            continue;
        }
        clear_pending_socket_if_match(index, socket);

        co_await tunnel->run();

        clear_tunnel_if_match(index, tunnel);
        clear_pending_socket_if_match(index, socket);

        co_await wait_remote_retry(io_context);
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

asio::awaitable<std::expected<void, std::error_code>> client_tunnel_pool::tcp_connect(asio::io_context& io_context, asio::ip::tcp::socket& socket) const
{
    const auto resolve_endpoints = co_await resolve_remote_endpoints(io_context, remote_host_, remote_port_);
    if (!resolve_endpoints)
    {
        co_return std::unexpected(resolve_endpoints.error());
    }

    std::error_code last_ec = asio::error::host_unreachable;

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
            co_return std::expected<void, std::error_code>{};
        }
        else
        {
            last_ec = res.error();
        }
    }

    LOG_ERROR("connect {} failed {}", remote_host_, last_ec.message());
    co_return std::unexpected(last_ec);
}

asio::awaitable<std::expected<void, std::error_code>> client_tunnel_pool::try_connect_endpoint(asio::ip::tcp::socket& socket,
                                                               const asio::ip::tcp::endpoint& endpoint) const
{
    auto [conn_error] = co_await socket.async_connect(endpoint, asio::as_tuple(asio::use_awaitable));
    if (conn_error)
    {
        co_return std::unexpected(conn_error);
    }

    std::error_code ec;
    ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("set no delay failed {}", ec.message());
    }
    log_tcp_connect_success(socket, endpoint);
    co_return std::expected<void, std::error_code>{};
}

asio::awaitable<std::expected<client_tunnel_pool::handshake_result, std::error_code>> client_tunnel_pool::perform_reality_handshake(asio::ip::tcp::socket& socket) const
{
    std::uint8_t public_key[32];
    std::uint8_t private_key[32];

    if (!reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        co_return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }

    const std::shared_ptr<void> defer_cleanse(nullptr, [&](void*) { OPENSSL_cleanse(private_key, 32); });

    const auto spec = select_fingerprint_spec(fingerprint_type_);
    reality::transcript trans;
    if (const auto res = co_await generate_and_send_client_hello(socket, public_key, private_key, spec, trans); !res)
    {
        co_return std::unexpected(res.error());
    }

    const auto sh_res = co_await process_server_hello(socket, private_key, trans);
    if (!sh_res)
    {
        co_return std::unexpected(sh_res.error());
    }

    const auto hs_keys_res = derive_handshake_traffic_keys(sh_res->hs_keys, sh_res->cipher_suite, sh_res->negotiated_md);
    if (!hs_keys_res)
    {
        co_return std::unexpected(hs_keys_res.error());
    }
    const auto& hs_keys = *hs_keys_res;

    auto loop_res =
        co_await handshake_read_loop(
            socket, hs_keys.s_hs_keys, sh_res->hs_keys, strict_cert_verify_, sni_, trans, sh_res->negotiated_cipher, sh_res->negotiated_md);
    if (!loop_res)
    {
        co_return std::unexpected(loop_res.error());
    }
    auto [c_app_secret, s_app_secret] = std::move(*loop_res);

    if (const auto res = co_await send_client_finished(
            socket, hs_keys.c_hs_keys, sh_res->hs_keys.client_handshake_traffic_secret, trans, sh_res->negotiated_cipher, sh_res->negotiated_md); !res)
    {
        co_return std::unexpected(res.error());
    }

    handshake_result result{
        .c_app_secret = std::move(c_app_secret),
        .s_app_secret = std::move(s_app_secret),
        .cipher_suite = sh_res->cipher_suite,
        .md = sh_res->negotiated_md,
        .cipher = sh_res->negotiated_cipher};
    co_return result;
}

asio::awaitable<std::expected<void, std::error_code>> client_tunnel_pool::generate_and_send_client_hello(asio::ip::tcp::socket& socket,
                                                                         const std::uint8_t* public_key,
                                                                         const std::uint8_t* private_key,
                                                                         const reality::fingerprint_spec& spec,
                                                                         reality::transcript& trans) const
{
    auto hello_body_res = build_authenticated_client_hello(
            public_key, private_key, server_pub_key_, short_id_bytes_, client_ver_, spec, sni_);
    if (!hello_body_res)
    {
        co_return std::unexpected(hello_body_res.error());
    }
    const auto& hello_body = *hello_body_res;

    auto ch_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    ch_rec.insert(ch_rec.end(), hello_body.begin(), hello_body.end());

    auto [we, wn] = co_await asio::async_write(socket, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_ERROR("error sending client hello {}", we.message());
        co_return std::unexpected(we);
    }
    LOG_DEBUG("sending client hello record size {}", ch_rec.size());
    trans.update(hello_body);
    co_return std::expected<void, std::error_code>{};
}

asio::awaitable<std::expected<client_tunnel_pool::server_hello_res, std::error_code>> client_tunnel_pool::process_server_hello(asio::ip::tcp::socket& socket,
                                                                                               const std::uint8_t* private_key,
                                                                                               reality::transcript& trans)
{
    const auto sh_data_res = co_await read_handshake_record_body(socket, "server hello");
    if (!sh_data_res)
    {
        co_return std::unexpected(sh_data_res.error());
    }
    const auto& sh_data = *sh_data_res;
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
        co_return std::unexpected(asio::error::invalid_argument);
    }

    auto hs_shared_res = derive_server_hello_shared_secret(private_key, key_share->group, key_share->data);
    if (!hs_shared_res)
    {
        co_return std::unexpected(hs_shared_res.error());
    }

    auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(*hs_shared_res, trans.finish(), md);
    if (!hs_keys)
    {
        LOG_ERROR("derive handshake keys failed {}", hs_keys.error().message());
        co_return std::unexpected(hs_keys.error());
    }

    co_return server_hello_res{.ok = true, .hs_keys = *hs_keys, .negotiated_md = md, .negotiated_cipher = cipher, .cipher_suite = cipher_suite};
}

asio::awaitable<std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, std::error_code>> client_tunnel_pool::handshake_read_loop(
    asio::ip::tcp::socket& socket,
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

    if (!validation_state.cert_checked || !validation_state.cert_verify_checked)
    {
        LOG_ERROR("server auth chain incomplete");
        co_return std::unexpected(std::make_error_code(std::errc::permission_denied));
    }
    if (strict_cert_verify && !validation_state.cert_verify_signature_checked)
    {
        auto& stats = statistics::instance();
        stats.inc_cert_verify_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kCertVerify, sni);
        LOG_ERROR("server certificate verify signature required possible cert key mismatch");
        co_return std::unexpected(std::make_error_code(std::errc::permission_denied));
    }
    if (!strict_cert_verify && !validation_state.cert_verify_signature_checked)
    {
        LOG_DEBUG("server certificate verify signature unchecked");
    }

    auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md);
    if (!app_sec)
    {
        LOG_ERROR("derive app secrets failed {}", app_sec.error().message());
        co_return std::unexpected(app_sec.error());
    }
    co_return *app_sec;
}

asio::awaitable<std::expected<void, std::error_code>> client_tunnel_pool::send_client_finished(asio::ip::tcp::socket& socket,
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

    auto [write_error, write_len] = co_await asio::async_write(socket, asio::buffer(out_flight), asio::as_tuple(asio::use_awaitable));
    if (write_error)
    {
        LOG_ERROR("send client finished flight error {}", write_error.message());
        co_return std::unexpected(write_error);
    }
    LOG_DEBUG("sending client finished flight size {}", out_flight.size());
    co_return std::expected<void, std::error_code>{};
}

asio::awaitable<void> client_tunnel_pool::wait_remote_retry(asio::io_context& io_context)
{
    if (stop_.load(std::memory_order_acquire))
    {
        co_return;
    }
    asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(constants::net::kRetryIntervalSec));
    const auto [ec] = co_await retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("remote retry timer error {}", ec.message());
    }
}

}    // namespace mux
