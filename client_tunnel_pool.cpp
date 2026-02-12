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
}

#include "log.h"
#include "config.h"
#include "ch_parser.h"
#include "constants.h"
#include "net_utils.h"
#include "transcript.h"
#include "crypto_util.h"
#include "log_context.h"
#include "reality_auth.h"
#include "reality_engine.h"
#include "reality_messages.h"
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

bool validate_certificate_message_once(const std::vector<std::uint8_t>& msg_data, bool& cert_checked, std::error_code& ec)
{
    LOG_DEBUG("received certificate message size {}", msg_data.size());
    if (cert_checked)
    {
        return true;
    }

    cert_checked = true;
    if (extract_first_cert_der(msg_data).has_value())
    {
        return true;
    }
    ec = asio::error::invalid_argument;
    LOG_ERROR("certificate message parse failed");
    return false;
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

asio::awaitable<std::optional<encrypted_record>> read_encrypted_record(asio::ip::tcp::socket& socket, std::error_code& ec)
{
    std::uint8_t rh[5];
    auto [re3, rn3] = co_await asio::async_read(socket, asio::buffer(rh, 5), asio::as_tuple(asio::use_awaitable));
    if (re3)
    {
        ec = re3;
        LOG_ERROR("error reading record header {}", ec.message());
        co_return std::nullopt;
    }

    const auto n = static_cast<std::uint16_t>((rh[3] << 8) | rh[4]);
    std::vector<std::uint8_t> rec(n);
    auto [re4, rn4] = co_await asio::async_read(socket, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
    if (re4)
    {
        ec = re4;
        LOG_ERROR("error reading record payload {}", ec.message());
        co_return std::nullopt;
    }
    if (rn4 != n)
    {
        ec = asio::error::fault;
        LOG_ERROR("short read record payload {} of {}", rn4, n);
        co_return std::nullopt;
    }

    std::vector<std::uint8_t> ciphertext(5 + n);
    std::memcpy(ciphertext.data(), rh, 5);
    std::memcpy(ciphertext.data() + 5, rec.data(), n);
    co_return encrypted_record{.content_type = rh[0], .ciphertext = std::move(ciphertext)};
}

bool consume_handshake_plaintext(const std::vector<std::uint8_t>& plaintext,
                                 std::vector<std::uint8_t>& handshake_buffer,
                                 bool& cert_checked,
                                 bool& handshake_fin,
                                 reality::transcript& trans,
                                 std::error_code& ec)
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
        if (msg_type == 0x0b && !validate_certificate_message_once(msg_data, cert_checked, ec))
        {
            return false;
        }

        trans.update(msg_data);
        if (msg_type == 0x14)
        {
            handshake_fin = true;
        }
        offset += 4 + msg_len;
    }

    handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + offset);
    return true;
}

asio::awaitable<std::optional<std::vector<std::uint8_t>>> read_handshake_record_body(asio::ip::tcp::socket& socket,
                                                                                      const char* step,
                                                                                      std::error_code& ec)
{
    std::uint8_t header[5];
    auto [read_header_ec, read_header_n] = co_await asio::async_read(socket, asio::buffer(header, 5), asio::as_tuple(asio::use_awaitable));
    if (read_header_ec)
    {
        ec = read_header_ec;
        LOG_ERROR("error reading {} header {}", step, ec.message());
        co_return std::nullopt;
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    std::vector<std::uint8_t> body(body_len);
    auto [read_body_ec, read_body_n] = co_await asio::async_read(socket, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    if (read_body_ec)
    {
        ec = read_body_ec;
        LOG_ERROR("error reading {} body {}", step, ec.message());
        co_return std::nullopt;
    }
    if (read_body_n != body_len)
    {
        ec = asio::error::fault;
        LOG_ERROR("short read {} body {} of {}", step, read_body_n, body_len);
        co_return std::nullopt;
    }

    co_return body;
}

bool parse_server_hello_cipher_suite(const std::vector<std::uint8_t>& sh_data, std::uint16_t& cipher_suite, std::error_code& ec)
{
    std::size_t pos = 4 + 2 + 32;
    if (pos >= sh_data.size())
    {
        ec = asio::error::fault;
        LOG_ERROR("bad server hello {}", ec.message());
        return false;
    }

    const std::uint8_t sid_len = sh_data[pos];
    pos += 1 + sid_len;
    if (pos + 2 > sh_data.size())
    {
        ec = asio::error::fault;
        LOG_ERROR("bad server hello session data {}", ec.message());
        return false;
    }

    cipher_suite = static_cast<std::uint16_t>((sh_data[pos] << 8) | sh_data[pos + 1]);
    return true;
}

std::pair<const EVP_MD*, const EVP_CIPHER*> select_negotiated_suite(const std::uint16_t cipher_suite)
{
    if (cipher_suite == 0x1302)
    {
        LOG_DEBUG("cipher suite 1302 used sha384 cipher aes 256 gcm");
        return std::make_pair(EVP_sha384(), EVP_aes_256_gcm());
    }
    if (cipher_suite == 0x1303)
    {
        LOG_DEBUG("cipher suite 1303 used sha256 cipher chacha20 poly1305");
        return std::make_pair(EVP_sha256(), EVP_chacha20_poly1305());
    }

    LOG_DEBUG("cipher suite not found used sha256 cipher aes 128 gcm");
    return std::make_pair(EVP_sha256(), EVP_aes_128_gcm());
}

bool derive_client_auth_key_material(const std::uint8_t* private_key,
                                     const std::vector<std::uint8_t>& server_pub_key,
                                     std::vector<std::uint8_t>& client_random,
                                     std::vector<std::uint8_t>& auth_key,
                                     std::error_code& ec)
{
    const auto shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), server_pub_key, ec);
    LOG_DEBUG("using server pub key size {}", server_pub_key.size());
    if (ec)
    {
        return false;
    }

    client_random.resize(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        return false;
    }

    const std::vector<std::uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    const auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 16, EVP_sha256(), ec);
    if (ec)
    {
        return false;
    }
    LOG_DEBUG("client auth material ready random {} bytes eph pub {} bytes", client_random.size(), 32);
    return true;
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

bool encrypt_client_session_id(const std::vector<std::uint8_t>& auth_key,
                               const std::vector<std::uint8_t>& client_random,
                               const std::array<std::uint8_t, reality::kAuthPayloadLen>& payload,
                               const std::vector<std::uint8_t>& hello_body,
                               std::vector<std::uint8_t>& sid,
                               std::error_code& ec)
{
    sid = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                             auth_key,
                                             std::vector<std::uint8_t>(client_random.begin() + constants::auth::kSaltLen, client_random.end()),
                                             std::vector<std::uint8_t>(payload.begin(), payload.end()),
                                             hello_body,
                                             ec);
    if (ec || sid.size() != 32)
    {
        LOG_ERROR("auth encryption failed ct size {}", sid.size());
        return false;
    }
    return true;
}

bool build_authenticated_client_hello(const std::uint8_t* public_key,
                                      const std::uint8_t* private_key,
                                      const std::vector<std::uint8_t>& server_pub_key,
                                      const std::vector<std::uint8_t>& short_id_bytes,
                                      const std::array<std::uint8_t, 3>& client_ver,
                                      const reality::fingerprint_spec& spec,
                                      const std::string& sni,
                                      std::vector<std::uint8_t>& hello_body,
                                      std::error_code& ec)
{
    std::vector<std::uint8_t> client_random;
    std::vector<std::uint8_t> auth_key;
    if (!derive_client_auth_key_material(private_key, server_pub_key, client_random, auth_key, ec))
    {
        return false;
    }

    const std::uint32_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    if (!reality::build_auth_payload(short_id_bytes, client_ver, now, payload))
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }

    std::uint32_t absolute_sid_offset = 0;
    if (!build_client_hello_with_placeholder_sid(spec, client_random, public_key, sni, hello_body, absolute_sid_offset))
    {
        return false;
    }

    std::vector<std::uint8_t> sid;
    if (!encrypt_client_session_id(auth_key, client_random, payload, hello_body, sid, ec))
    {
        return false;
    }

    std::memcpy(hello_body.data() + absolute_sid_offset, sid.data(), 32);
    return true;
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

handshake_traffic_keys derive_handshake_traffic_keys(const reality::handshake_keys& hs_keys,
                                                     const std::uint16_t cipher_suite,
                                                     const EVP_MD* negotiated_md,
                                                     std::error_code& ec)
{
    const std::size_t key_len =
        (cipher_suite == 0x1302 || cipher_suite == 0x1303) ? constants::crypto::kKeyLen256 : constants::crypto::kKeyLen128;
    constexpr std::size_t iv_len = constants::crypto::kIvLen;
    return handshake_traffic_keys{
        .c_hs_keys =
            reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, negotiated_md),
        .s_hs_keys =
            reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, negotiated_md)};
}

bool prepare_server_hello_crypto(const std::vector<std::uint8_t>& sh_data,
                                 reality::transcript& trans,
                                 std::uint16_t& cipher_suite,
                                 const EVP_MD*& md,
                                 const EVP_CIPHER*& cipher,
                                 std::error_code& ec)
{
    trans.update(sh_data);
    if (!parse_server_hello_cipher_suite(sh_data, cipher_suite, ec))
    {
        return false;
    }
    const auto [selected_md, selected_cipher] = select_negotiated_suite(cipher_suite);
    md = selected_md;
    cipher = selected_cipher;
    trans.set_protocol_hash(md);
    return true;
}

bool derive_server_hello_shared_secret(const std::uint8_t* private_key,
                                       const std::uint16_t key_share_group,
                                       const std::vector<std::uint8_t>& key_share_data,
                                       std::vector<std::uint8_t>& hs_shared,
                                       std::error_code& ec)
{
    if (key_share_group != reality::tls_consts::group::kX25519)
    {
        ec = asio::error::no_protocol_option;
        LOG_ERROR("unsupported key share group {}", key_share_group);
        return false;
    }
    if (key_share_data.size() != 32)
    {
        ec = asio::error::invalid_argument;
        LOG_ERROR("invalid x25519 key share length {}", key_share_data.size());
        return false;
    }

    hs_shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), key_share_data, ec);
    if (ec)
    {
        LOG_ERROR("handshake shared secret failed {}", ec.message());
        return false;
    }
    return true;
}

std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> make_handshake_loop_fail_result()
{
    return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
}

asio::awaitable<bool> process_handshake_record(asio::ip::tcp::socket& socket,
                                               const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
                                               reality::transcript& trans,
                                               const EVP_CIPHER* cipher,
                                               std::vector<std::uint8_t>& handshake_buffer,
                                               bool& cert_checked,
                                               bool& handshake_fin,
                                               std::uint64_t& seq,
                                               std::error_code& ec)
{
    const auto record = co_await read_encrypted_record(socket, ec);
    if (!record.has_value())
    {
        co_return false;
    }
    if (record->content_type == reality::kContentTypeChangeCipherSpec)
    {
        LOG_DEBUG("received change cipher spec skip");
        co_return true;
    }

    std::uint8_t type = 0;
    const auto plaintext = reality::tls_record_layer::decrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, record->ciphertext, type, ec);
    if (ec)
    {
        LOG_ERROR("error decrypting record {}", ec.message());
        co_return false;
    }
    if (type != reality::kContentTypeHandshake)
    {
        co_return true;
    }

    if (!consume_handshake_plaintext(plaintext, handshake_buffer, cert_checked, handshake_fin, trans, ec))
    {
        co_return false;
    }
    co_return true;
}

asio::awaitable<std::optional<asio::ip::tcp::resolver::results_type>> resolve_remote_endpoints(asio::io_context& io_context,
                                                                                                 const std::string& remote_host,
                                                                                                 const std::string& remote_port,
                                                                                                 std::error_code& ec)
{
    asio::ip::tcp::resolver resolver(io_context);
    auto [resolve_error, resolve_endpoints] = co_await resolver.async_resolve(remote_host, remote_port, asio::as_tuple(asio::use_awaitable));
    if (resolve_error)
    {
        ec = resolve_error;
        LOG_ERROR("resolve {} failed {}", remote_host, resolve_error.message());
        co_return std::nullopt;
    }
    co_return resolve_endpoints;
}

bool prepare_socket_for_connect(asio::ip::tcp::socket& socket,
                                const asio::ip::tcp::endpoint& endpoint,
                                const std::uint32_t mark,
                                std::error_code& ec)
{
    std::error_code socket_ec;
    if (socket.is_open())
    {
        socket.close(socket_ec);
    }
    socket_ec = socket.open(endpoint.protocol(), socket_ec);
    if (socket_ec)
    {
        ec = socket_ec;
        return false;
    }
    if (mark != 0)
    {
        std::error_code mark_ec;
        if (!net::set_socket_mark(socket.native_handle(), mark, mark_ec))
        {
            LOG_WARN("set mark failed {}", mark_ec.message());
        }
    }
    return true;
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
      pool_(pool),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    server_pub_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.public_key);
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id");
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

    if (limits_config_.max_connections == 0)
    {
        limits_config_.max_connections = 1;
    }
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
        asio::post(*io_context,
                   [pending_socket = std::move(pending_socket)]()
                   {
                       std::error_code ec;
                       pending_socket->cancel(ec);
                       pending_socket->close(ec);
                   });
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

    if (atomic_load_shared(pending_sockets_[index]) == socket)
    {
        atomic_store_shared(pending_sockets_[index], std::shared_ptr<asio::ip::tcp::socket>{});
    }
}

void client_tunnel_pool::publish_tunnel(const std::uint32_t index, const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel)
{
    if (index < tunnel_pool_.size())
    {
        atomic_store_shared(tunnel_pool_[index], tunnel);
    }
}

void client_tunnel_pool::clear_tunnel_if_match(const std::uint32_t index,
                                               const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel)
{
    if (index >= tunnel_pool_.size())
    {
        return;
    }

    if (atomic_load_shared(tunnel_pool_[index]) == tunnel)
    {
        atomic_store_shared(tunnel_pool_[index], std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>{});
    }
}

std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> client_tunnel_pool::build_tunnel(asio::ip::tcp::socket socket,
                                                                                           asio::io_context& io_context,
                                                                                           const std::uint32_t cid,
                                                                                           const handshake_result& handshake_ret,
                                                                                           const std::string& trace_id) const
{
    const std::size_t key_len = (handshake_ret.cipher_suite == 0x1302 || handshake_ret.cipher_suite == 0x1303) ? constants::crypto::kKeyLen256
                                                                                                                   : constants::crypto::kKeyLen128;
    std::error_code ec;
    const auto c_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.c_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);
    const auto s_app_keys =
        reality::tls_key_schedule::derive_traffic_keys(handshake_ret.s_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);
    if (ec)
    {
        LOG_WARN("derive app traffic keys failed {}", ec.message());
    }

    reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second, handshake_ret.cipher);
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
    if (!co_await tcp_connect(io_context, *socket, ec))
    {
        co_await handle_connection_failure(index, socket, ec, "connect", io_context);
        co_return false;
    }

    auto [handshake_success, handshake_ret] = co_await perform_reality_handshake(*socket, ec);
    if (!handshake_success)
    {
        co_await handle_connection_failure(index, socket, ec, "handshake", io_context);
        co_return false;
    }

    connection_context ctx;
    ctx.trace_id(trace_id);
    ctx.conn_id(cid);
    LOG_CTX_INFO(ctx, "{} handshake success cipher 0x{:04x}", log_event::kHandshake, handshake_ret.cipher_suite);

    tunnel = build_tunnel(std::move(*socket), io_context, cid, handshake_ret, trace_id);
    co_return true;
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

        publish_tunnel(index, tunnel);
        clear_pending_socket_if_match(index, socket);

        co_await tunnel->run();

        clear_tunnel_if_match(index, tunnel);
        clear_pending_socket_if_match(index, socket);

        co_await wait_remote_retry(io_context);
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

asio::awaitable<bool> client_tunnel_pool::tcp_connect(asio::io_context& io_context, asio::ip::tcp::socket& socket, std::error_code& ec) const
{
    const auto resolve_endpoints = co_await resolve_remote_endpoints(io_context, remote_host_, remote_port_, ec);
    if (!resolve_endpoints.has_value())
    {
        co_return false;
    }

    for (const auto& entry : resolve_endpoints.value())
    {
        const auto endpoint = entry.endpoint();

        if (!prepare_socket_for_connect(socket, endpoint, mark_, ec))
        {
            continue;
        }
        if (co_await try_connect_endpoint(socket, endpoint, ec))
        {
            co_return true;
        }
    }

    if (!ec)
    {
        ec = std::make_error_code(std::errc::host_unreachable);
    }
    LOG_ERROR("connect {} failed {}", remote_host_, ec.message());
    co_return false;
}

asio::awaitable<bool> client_tunnel_pool::try_connect_endpoint(asio::ip::tcp::socket& socket,
                                                               const asio::ip::tcp::endpoint& endpoint,
                                                               std::error_code& ec) const
{
    auto [conn_error] = co_await socket.async_connect(endpoint, asio::as_tuple(asio::use_awaitable));
    if (conn_error)
    {
        ec = conn_error;
        co_return false;
    }

    ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("set no delay failed {}", ec.message());
    }
    log_tcp_connect_success(socket, endpoint);
    co_return true;
}

asio::awaitable<std::pair<bool, client_tunnel_pool::handshake_result>> client_tunnel_pool::perform_reality_handshake(asio::ip::tcp::socket& socket,
                                                                                                                     std::error_code& ec) const
{
    const auto fail = []() { return std::make_pair(false, handshake_result{}); };

    std::uint8_t public_key[32];
    std::uint8_t private_key[32];

    if (!reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        co_return fail();
    }

    const std::shared_ptr<void> defer_cleanse(nullptr, [&](void*) { OPENSSL_cleanse(private_key, 32); });

    const auto spec = select_fingerprint_spec(fingerprint_type_);
    reality::transcript trans;
    if (!co_await generate_and_send_client_hello(socket, public_key, private_key, spec, trans, ec))
    {
        co_return fail();
    }

    const auto sh_res = co_await process_server_hello(socket, private_key, trans, ec);
    if (!sh_res.ok)
    {
        co_return fail();
    }

    const auto hs_keys = derive_handshake_traffic_keys(sh_res.hs_keys, sh_res.cipher_suite, sh_res.negotiated_md, ec);

    auto [loop_ok, app_sec] =
        co_await handshake_read_loop(socket, hs_keys.s_hs_keys, sh_res.hs_keys, trans, sh_res.negotiated_cipher, sh_res.negotiated_md, ec);
    if (!loop_ok)
    {
        co_return fail();
    }

    if (!co_await send_client_finished(
            socket, hs_keys.c_hs_keys, sh_res.hs_keys.client_handshake_traffic_secret, trans, sh_res.negotiated_cipher, sh_res.negotiated_md, ec))
    {
        co_return fail();
    }

    handshake_result result{
        .c_app_secret = std::move(app_sec.first),
        .s_app_secret = std::move(app_sec.second),
        .cipher_suite = sh_res.cipher_suite,
        .md = sh_res.negotiated_md,
        .cipher = sh_res.negotiated_cipher};
    co_return std::make_pair(true, std::move(result));
}

asio::awaitable<bool> client_tunnel_pool::generate_and_send_client_hello(asio::ip::tcp::socket& socket,
                                                                         const std::uint8_t* public_key,
                                                                         const std::uint8_t* private_key,
                                                                         const reality::fingerprint_spec& spec,
                                                                         reality::transcript& trans,
                                                                         std::error_code& ec) const
{
    std::vector<std::uint8_t> hello_body;
    if (!build_authenticated_client_hello(
            public_key, private_key, server_pub_key_, short_id_bytes_, client_ver_, spec, sni_, hello_body, ec))
    {
        co_return false;
    }

    auto ch_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    ch_rec.insert(ch_rec.end(), hello_body.begin(), hello_body.end());

    auto [we, wn] = co_await asio::async_write(socket, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        ec = we;
        LOG_ERROR("error sending client hello {}", ec.message());
        co_return false;
    }
    LOG_DEBUG("sending client hello record size {}", ch_rec.size());
    trans.update(hello_body);
    co_return true;
}

asio::awaitable<client_tunnel_pool::server_hello_res> client_tunnel_pool::process_server_hello(asio::ip::tcp::socket& socket,
                                                                                               const std::uint8_t* private_key,
                                                                                               reality::transcript& trans,
                                                                                               std::error_code& ec)
{
    const auto sh_data_opt = co_await read_handshake_record_body(socket, "server hello", ec);
    if (!sh_data_opt.has_value())
    {
        co_return server_hello_res{.ok = false};
    }
    const auto& sh_data = *sh_data_opt;
    LOG_DEBUG("server hello received size {}", sh_data.size());

    std::uint16_t cipher_suite = 0;
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    if (!prepare_server_hello_crypto(sh_data, trans, cipher_suite, md, cipher, ec))
    {
        co_return server_hello_res{.ok = false};
    }

    const auto key_share = reality::extract_server_key_share(sh_data);
    LOG_DEBUG("rx server hello size {}", sh_data.size());
    if (!key_share.has_value())
    {
        ec = asio::error::invalid_argument;
        LOG_ERROR("bad server hello key share {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    std::vector<std::uint8_t> hs_shared;
    if (!derive_server_hello_shared_secret(private_key, key_share->group, key_share->data, hs_shared, ec))
    {
        co_return server_hello_res{.ok = false};
    }

    auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(hs_shared, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive handshake keys failed {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    co_return server_hello_res{.ok = true, .hs_keys = hs_keys, .negotiated_md = md, .negotiated_cipher = cipher, .cipher_suite = cipher_suite};
}

asio::awaitable<std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>> client_tunnel_pool::handshake_read_loop(
    asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
    const reality::handshake_keys& hs_keys,
    reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md,
    std::error_code& ec)
{
    bool handshake_fin = false;
    bool cert_checked = false;
    std::uint64_t seq = 0;
    std::vector<std::uint8_t> handshake_buffer;

    while (!handshake_fin)
    {
        if (!co_await process_handshake_record(socket, s_hs_keys, trans, cipher, handshake_buffer, cert_checked, handshake_fin, seq, ec))
        {
            co_return make_handshake_loop_fail_result();
        }
    }

    const auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md, ec);
    if (ec)
    {
        LOG_ERROR("derive app secrets failed {}", ec.message());
        co_return make_handshake_loop_fail_result();
    }
    co_return std::make_pair(true, app_sec);
}

asio::awaitable<bool> client_tunnel_pool::send_client_finished(asio::ip::tcp::socket& socket,
                                                               const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                               const std::vector<std::uint8_t>& c_hs_secret,
                                                               const reality::transcript& trans,
                                                               const EVP_CIPHER* cipher,
                                                               const EVP_MD* md,
                                                               std::error_code& ec)
{
    const auto fin_verify = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), md, ec);
    const auto fin_msg = reality::construct_finished(fin_verify);
    const auto fin_rec =
        reality::tls_record_layer::encrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, fin_msg, reality::kContentTypeHandshake, ec);

    std::vector<std::uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    out_flight.insert(out_flight.end(), fin_rec.begin(), fin_rec.end());

    auto [write_error, write_len] = co_await asio::async_write(socket, asio::buffer(out_flight), asio::as_tuple(asio::use_awaitable));
    if (write_error)
    {
        ec = write_error;
        LOG_ERROR("send client finished flight error {}", ec.message());
        co_return false;
    }
    LOG_DEBUG("sending client finished flight size {}", out_flight.size());
    co_return true;
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
