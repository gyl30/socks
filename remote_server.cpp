#include <ctime>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <future>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <charconv>
#include <system_error>

#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "ch_parser.h"
#include "constants.h"
#include "statistics.h"
#include "mux_codec.h"
#include "mux_tunnel.h"
#include "crypto_util.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "reality_auth.h"
#include "remote_server.h"
#include "reality_engine.h"
#include "remote_session.h"
#include "remote_udp_session.h"

namespace mux
{

namespace
{

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

bool parse_bracket_dest_target(const std::string& text, std::string& host, std::string& port)
{
    const auto end = text.find(']');
    if (end == std::string::npos)
    {
        return false;
    }
    host = text.substr(1, end - 1);
    if (end + 1 >= text.size() || text[end + 1] != ':')
    {
        return false;
    }
    port = text.substr(end + 2);
    return true;
}

bool parse_plain_dest_target(const std::string& text, std::string& host, std::string& port)
{
    const auto pos = text.rfind(':');
    if (pos == std::string::npos)
    {
        return false;
    }
    host = text.substr(0, pos);
    port = text.substr(pos + 1);
    return true;
}

bool parse_dest_target(const std::string& input, std::string& host, std::string& port)
{
    if (input.empty())
    {
        return false;
    }
    host.clear();
    port.clear();
    const bool parsed = (input.front() == '[') ? parse_bracket_dest_target(input, host, port) : parse_plain_dest_target(input, host, port);
    return parsed && !host.empty() && !port.empty();
}

bool should_stop_accept_loop_on_error(const std::error_code& accept_ec,
                                      const std::atomic<bool>& stop_flag,
                                      const asio::ip::tcp::acceptor& acceptor)
{
    if (accept_ec == asio::error::operation_aborted || accept_ec == asio::error::bad_descriptor)
    {
        return true;
    }
    if (stop_flag.load(std::memory_order_acquire))
    {
        return true;
    }
    return !acceptor.is_open();
}

std::optional<std::pair<std::string, std::string>> find_exact_sni_fallback(const std::vector<config::fallback_entry>& fallbacks,
                                                                            const std::string& sni)
{
    if (sni.empty())
    {
        return std::nullopt;
    }
    for (const auto& fb : fallbacks)
    {
        if (fb.sni == sni)
        {
            return std::make_pair(fb.host, fb.port);
        }
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, std::string>> find_wildcard_fallback(const std::vector<config::fallback_entry>& fallbacks)
{
    for (const auto& fb : fallbacks)
    {
        if (fb.sni.empty() || fb.sni == "*")
        {
            return std::make_pair(fb.host, fb.port);
        }
    }
    return std::nullopt;
}

asio::ip::tcp::endpoint resolve_inbound_endpoint(const config::inbound_t& inbound)
{
    std::error_code ec;
    auto addr = asio::ip::make_address(inbound.host, ec);
    if (ec)
    {
        LOG_ERROR("parse inbound host {} failed {}", inbound.host, ec.message());
        addr = asio::ip::address_v6::any();
    }
    return asio::ip::tcp::endpoint(addr, inbound.port);
}

bool setup_server_acceptor(asio::ip::tcp::acceptor& acceptor, const asio::ip::tcp::endpoint& ep)
{
    std::error_code ec;
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("acceptor open failed {}", ec.message());
        return false;
    }
    ec = acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("acceptor set reuse address failed {}", ec.message());
        return false;
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("acceptor bind failed {}", ec.message());
        return false;
    }
    ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("acceptor listen failed {}", ec.message());
        return false;
    }
    return true;
}

void apply_reality_dest_config(const config::reality_t& reality_cfg,
                               std::string& fallback_dest_host,
                               std::string& fallback_dest_port,
                               bool& fallback_dest_valid,
                               bool& auth_config_valid)
{
    if (reality_cfg.dest.empty())
    {
        return;
    }
    if (!parse_dest_target(reality_cfg.dest, fallback_dest_host, fallback_dest_port))
    {
        LOG_ERROR("reality dest invalid {}", reality_cfg.dest);
        auth_config_valid = false;
        return;
    }
    fallback_dest_valid = true;
}

std::uint16_t parse_fallback_port(const std::string& port_text)
{
    std::uint16_t fetch_port = 443;
    auto [ptr, from_ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), fetch_port);
    if (from_ec != std::errc())
    {
        LOG_WARN("invalid fallback port {} defaulting to 443", port_text);
        return 443;
    }
    return fetch_port;
}

std::uint16_t normalize_cipher_suite(std::uint16_t cipher_suite)
{
    if (cipher_suite != 0x1301 && cipher_suite != 0x1302 && cipher_suite != 0x1303)
    {
        return 0x1301;
    }
    return cipher_suite;
}

const EVP_MD* digest_from_cipher_suite(const std::uint16_t cipher_suite)
{
    if (cipher_suite == 0x1302)
    {
        return EVP_sha384();
    }
    return EVP_sha256();
}

const EVP_CIPHER* cipher_from_cipher_suite(const std::uint16_t cipher_suite)
{
    if (cipher_suite == 0x1302)
    {
        return EVP_aes_256_gcm();
    }
    if (cipher_suite == 0x1303)
    {
        return EVP_chacha20_poly1305();
    }
    return EVP_aes_128_gcm();
}

std::size_t key_len_from_cipher_suite(const std::uint16_t cipher_suite)
{
    return (cipher_suite == 0x1302) ? 32 : 16;
}

bool build_auth_decrypt_inputs(const client_hello_info& info,
                               const std::vector<std::uint8_t>& buf,
                               const std::vector<std::uint8_t>& server_private_key,
                               const std::vector<std::uint8_t>& peer_pub_key,
                               std::vector<std::uint8_t>& auth_key,
                               std::vector<std::uint8_t>& nonce,
                               std::vector<std::uint8_t>& aad,
                               std::error_code& ec,
                               const connection_context& ctx)
{
    const auto shared = reality::crypto_util::x25519_derive(server_private_key, peer_pub_key, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail x25519 derive failed {}", log_event::kAuth, ec.message());
        return false;
    }

    const auto salt = std::vector<std::uint8_t>(info.random.begin(), info.random.begin() + 20);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    const auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 16, EVP_sha256(), ec);
    nonce.assign(info.random.begin() + 20, info.random.end());
    LOG_CTX_DEBUG(ctx, "auth key derived");

    if (info.sid_offset < 5)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail invalid sid offset {}", log_event::kAuth, info.sid_offset);
        return false;
    }

    aad.assign(buf.begin() + 5, buf.end());
    const std::uint32_t aad_sid_offset = info.sid_offset - 5;
    if (aad_sid_offset + constants::auth::kSessionIdLen > aad.size())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail aad size mismatch", log_event::kAuth);
        return false;
    }
    std::fill_n(aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);
    return true;
}

bool verify_auth_payload_fields(const std::optional<reality::auth_payload>& auth,
                                const std::vector<std::uint8_t>& short_id_bytes,
                                const std::string& sni,
                                const connection_context& ctx)
{
    if (!auth.has_value())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail invalid payload", log_event::kAuth);
        return false;
    }
    if (short_id_bytes.empty())
    {
        return true;
    }

    if (CRYPTO_memcmp(auth->short_id.data(), short_id_bytes.data(), short_id_bytes.size()) != 0)
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        stats.inc_auth_short_id_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, sni);
        LOG_CTX_WARN(ctx, "{} auth fail short id mismatch", log_event::kAuth);
        return false;
    }
    return true;
}

bool verify_auth_timestamp(const std::uint32_t timestamp, const std::string& sni, const connection_context& ctx)
{
    const auto now_tp = std::chrono::system_clock::now();
    const auto ts_tp = std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
    const auto diff = (now_tp > ts_tp) ? (now_tp - ts_tp) : (ts_tp - now_tp);
    const auto diff_sec = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
    const auto max_diff = std::chrono::seconds(constants::auth::kMaxClockSkewSec);
    if (diff > max_diff)
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        stats.inc_auth_clock_skew_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kClockSkew, sni);
        LOG_CTX_WARN(ctx, "{} clock skew too large diff {}s", log_event::kAuth, diff_sec);
        return false;
    }
    return true;
}

struct handshake_crypto_result
{
    bool ok = false;
    reality::handshake_keys hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
    const EVP_CIPHER* cipher = nullptr;
    const EVP_MD* md = nullptr;
    std::vector<std::uint8_t> sh_msg;
    std::vector<std::uint8_t> flight2_enc;
};

handshake_crypto_result build_handshake_crypto(const std::vector<std::uint8_t>& server_random,
                                               const std::vector<std::uint8_t>& session_id,
                                               const std::uint16_t cipher_suite,
                                               const std::uint16_t key_share_group,
                                               const std::vector<std::uint8_t>& key_share_data,
                                               const std::vector<std::uint8_t>& shared_secret,
                                               const std::vector<std::uint8_t>& cert_msg,
                                               const std::string& alpn,
                                               const std::vector<std::uint8_t>& sign_key_bytes,
                                               reality::transcript& trans,
                                               std::error_code& ec,
                                               const connection_context& ctx)
{
    handshake_crypto_result out;
    out.sh_msg = reality::construct_server_hello(server_random, session_id, cipher_suite, key_share_group, key_share_data);
    trans.update(out.sh_msg);

    out.md = digest_from_cipher_suite(cipher_suite);
    trans.set_protocol_hash(out.md);
    out.hs_keys = reality::tls_key_schedule::derive_handshake_keys(shared_secret, trans.finish(), out.md, ec);

    constexpr std::size_t iv_len = 12;
    const auto key_len = key_len_from_cipher_suite(cipher_suite);
    out.c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, out.md);
    out.s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, out.md);

    const auto enc_ext = reality::construct_encrypted_extensions(alpn);
    trans.update(enc_ext);
    trans.update(cert_msg);

    const reality::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), 32));
    if (sign_key == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to load private key", log_event::kHandshake);
        ec = asio::error::fault;
        return out;
    }

    const auto cv = reality::construct_certificate_verify(sign_key.get(), trans.finish());
    trans.update(cv);

    const auto s_fin_verify =
        reality::tls_key_schedule::compute_finished_verify_data(out.hs_keys.server_handshake_traffic_secret, trans.finish(), out.md, ec);
    const auto s_fin = reality::construct_finished(s_fin_verify);
    trans.update(s_fin);

    std::vector<std::uint8_t> flight2_plain;
    flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    flight2_plain.insert(flight2_plain.end(), cert_msg.begin(), cert_msg.end());
    flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
    flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

    out.cipher = cipher_from_cipher_suite(cipher_suite);
    out.flight2_enc =
        reality::tls_record_layer::encrypt_record(out.cipher, out.s_hs_keys.first, out.s_hs_keys.second, 0, flight2_plain, reality::kContentTypeHandshake, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail flight2 encrypt failed {}", log_event::kAuth, ec.message());
        return out;
    }

    out.ok = true;
    return out;
}

std::vector<std::uint8_t> compose_server_hello_flight(const std::vector<std::uint8_t>& sh_msg, const std::vector<std::uint8_t>& flight2_enc)
{
    std::vector<std::uint8_t> out_sh;
    const auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh_msg.size()));
    out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
    out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
    out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());
    return out_sh;
}

void close_fallback_socket(const std::shared_ptr<asio::ip::tcp::socket>& socket, const connection_context& ctx)
{
    std::error_code close_ec;
    close_ec = socket->shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
    if (close_ec && close_ec != asio::error::not_connected)
    {
        LOG_CTX_WARN(ctx, "{} shutdown failed {}", log_event::kFallback, close_ec.message());
    }
    close_ec = socket->close(close_ec);
    if (close_ec && close_ec != asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx, "{} close failed {}", log_event::kFallback, close_ec.message());
    }
}

asio::awaitable<void> proxy_half(const std::shared_ptr<asio::ip::tcp::socket>& from, const std::shared_ptr<asio::ip::tcp::socket>& to)
{
    std::vector<std::uint8_t> data(constants::net::kBufferSize);
    for (;;)
    {
        auto [read_ec, n] = co_await from->async_read_some(asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (read_ec)
        {
            break;
        }
        auto [write_ec, wn] = co_await asio::async_write(*to, asio::buffer(data, n), asio::as_tuple(asio::use_awaitable));
        if (write_ec)
        {
            break;
        }
    }
    std::error_code ec;
    ec = to->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
}

bool validate_auth_inputs(const client_hello_info& info, const bool auth_config_valid, const connection_context& ctx)
{
    if (!auth_config_valid)
    {
        LOG_CTX_ERROR(ctx, "{} invalid auth config", log_event::kAuth);
        return false;
    }
    if (!info.is_tls13 || info.session_id.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail is tls13 {} sid len {}", log_event::kAuth, info.is_tls13, info.session_id.size());
        return false;
    }
    return true;
}

std::optional<reality::auth_payload> decrypt_auth_payload(const client_hello_info& info,
                                                          const std::vector<std::uint8_t>& buf,
                                                          const std::vector<std::uint8_t>& private_key,
                                                          const std::vector<std::uint8_t>& peer_pub_key,
                                                          std::error_code& ec,
                                                          const connection_context& ctx)
{
    std::vector<std::uint8_t> auth_key;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> aad;
    if (!build_auth_decrypt_inputs(info, buf, private_key, peer_pub_key, auth_key, nonce, aad, ec, ctx))
    {
        return std::nullopt;
    }

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    const auto pt = reality::crypto_util::aead_decrypt(auth_cipher, auth_key, nonce, info.session_id, aad, ec);
    if (ec || pt.size() != 16)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail decrypt failed tag mismatch ec {} pt size {}", log_event::kAuth, ec.message(), pt.size());
        return std::nullopt;
    }

    return reality::parse_auth_payload(pt);
}

bool verify_replay_guard(replay_cache& replay_cache, const std::vector<std::uint8_t>& session_id, const std::string& sni, const connection_context& ctx)
{
    if (!replay_cache.check_and_insert(session_id))
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        stats.inc_auth_replay_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kReplay, sni);
        LOG_CTX_WARN(ctx, "{} replay attack detected", log_event::kAuth);
        return false;
    }
    return true;
}

bool generate_server_random(std::vector<std::uint8_t>& server_random, std::error_code& ec)
{
    server_random.assign(32, 0);
    if (RAND_bytes(server_random.data(), 32) != 1)
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        return false;
    }
    return true;
}

void log_ephemeral_public_key(const std::uint8_t* public_key, const connection_context& ctx)
{
    LOG_CTX_TRACE(ctx,
                  "{} generated ephemeral key {}",
                  log_event::kHandshake,
                  reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32)));
}

std::uint16_t select_cipher_suite_from_fingerprint(const reality::server_fingerprint& fingerprint)
{
    return normalize_cipher_suite(fingerprint.cipher_suite != 0 ? fingerprint.cipher_suite : 0x1301);
}

asio::awaitable<bool> read_tls_record_header_allow_ccs(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                                       std::array<std::uint8_t, 5>& header,
                                                       const connection_context& ctx)
{
    const auto [read_ec, read_n] = co_await asio::async_read(*socket, asio::buffer(header), asio::as_tuple(asio::use_awaitable));
    (void)read_n;
    if (read_ec)
    {
        LOG_CTX_ERROR(ctx, "{} read client finished header error {}", log_event::kHandshake, read_ec.message());
        co_return false;
    }

    if (header[0] != 0x14)
    {
        co_return true;
    }

    std::array<std::uint8_t, 1> dummy = {0};
    const auto [dummy_ec, dummy_n] = co_await asio::async_read(*socket, asio::buffer(dummy), asio::as_tuple(asio::use_awaitable));
    (void)dummy_n;
    if (dummy_ec)
    {
        LOG_CTX_ERROR(ctx, "{} read ccs error {}", log_event::kHandshake, dummy_ec.message());
        co_return false;
    }

    const auto [read_ec2, read_n2] = co_await asio::async_read(*socket, asio::buffer(header), asio::as_tuple(asio::use_awaitable));
    (void)read_n2;
    if (read_ec2)
    {
        LOG_CTX_ERROR(ctx, "{} read client finished header after ccs error {}", log_event::kHandshake, read_ec2.message());
        co_return false;
    }
    co_return true;
}

asio::awaitable<bool> read_tls_record_body(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                           const std::uint16_t body_len,
                                           std::vector<std::uint8_t>& body,
                                           const connection_context& ctx)
{
    body.assign(body_len, 0);
    const auto [read_ec, read_n] = co_await asio::async_read(*socket, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    (void)read_n;
    if (read_ec)
    {
        LOG_CTX_ERROR(ctx, "{} read client finished body error {}", log_event::kHandshake, read_ec.message());
        co_return false;
    }
    co_return true;
}

std::vector<std::uint8_t> compose_tls_record(const std::array<std::uint8_t, 5>& header, const std::vector<std::uint8_t>& body)
{
    std::vector<std::uint8_t> out(header.size() + body.size());
    std::memcpy(out.data(), header.data(), header.size());
    std::memcpy(out.data() + header.size(), body.data(), body.size());
    return out;
}

bool verify_client_finished_plaintext(const std::vector<std::uint8_t>& plaintext,
                                      const std::uint8_t content_type,
                                      const std::vector<std::uint8_t>& expected_verify,
                                      const connection_context& ctx)
{
    if (content_type != reality::kContentTypeHandshake || plaintext.size() < 4 || plaintext[0] != 0x14)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished verification failed type {}", log_event::kHandshake, static_cast<int>(content_type));
        return false;
    }

    const std::uint32_t msg_len = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
    if (msg_len != expected_verify.size() || plaintext.size() != 4 + msg_len)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished length invalid {}", log_event::kHandshake, plaintext.size());
        return false;
    }
    if (CRYPTO_memcmp(plaintext.data() + 4, expected_verify.data(), expected_verify.size()) != 0)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished hmac verification failed", log_event::kHandshake);
        return false;
    }
    return true;
}

asio::awaitable<void> fallback_failed_drain(const std::shared_ptr<asio::ip::tcp::socket>& socket)
{
    char data[constants::net::kBufferSize] = {0};
    for (;;)
    {
        const auto [read_ec, read_n] = co_await socket->async_read_some(asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (read_ec || read_n == 0)
        {
            break;
        }
    }
    std::error_code ignore;
    ignore = socket->shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
}

asio::awaitable<void> fallback_wait_random_timer(const std::uint32_t conn_id, asio::io_context& io_context)
{
    asio::steady_timer fallback_timer(io_context);
    constexpr std::uint32_t max_wait_ms = constants::fallback::kMaxWaitMs;
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> dist(0, max_wait_ms - 1);
    const std::uint32_t wait_ms = dist(gen);
    fallback_timer.expires_after(std::chrono::milliseconds(wait_ms));
    const auto [wait_ec] = co_await fallback_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (wait_ec)
    {
        LOG_ERROR("{} fallback failed timer {} ms error {}", conn_id, wait_ms, wait_ec.message());
    }
    LOG_DEBUG("{} fallback failed timer {} ms", conn_id, wait_ms);
}

asio::awaitable<void> handle_fallback_without_target(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                                     const connection_context& ctx,
                                                     const std::string& sni,
                                                     asio::io_context& io_context)
{
    LOG_CTX_INFO(ctx, "{} no target sni {}", log_event::kFallback, sni.empty() ? "empty" : sni);
    co_await fallback_wait_random_timer(ctx.conn_id(), io_context);
    close_fallback_socket(socket, ctx);
    LOG_CTX_INFO(ctx, "{} done", log_event::kFallback);
}

asio::awaitable<bool> resolve_and_connect_fallback_target(const std::shared_ptr<asio::ip::tcp::socket>& target_socket,
                                                          asio::io_context& io_context,
                                                          const std::string& target_host,
                                                          const std::string& target_port,
                                                          const connection_context& ctx)
{
    asio::ip::tcp::resolver resolver(io_context);
    const auto [resolve_ec, endpoints] = co_await resolver.async_resolve(target_host, target_port, asio::as_tuple(asio::use_awaitable));
    if (resolve_ec)
    {
        LOG_CTX_WARN(ctx, "{} resolve failed {}", log_event::kFallback, resolve_ec.message());
        co_return false;
    }

    const auto [connect_ec, endpoint] = co_await asio::async_connect(*target_socket, endpoints, asio::as_tuple(asio::use_awaitable));
    (void)endpoint;
    if (connect_ec)
    {
        LOG_CTX_WARN(ctx, "{} connect target failed {}", log_event::kFallback, connect_ec.message());
        co_return false;
    }
    co_return true;
}

asio::awaitable<bool> write_fallback_initial_buffer(const std::shared_ptr<asio::ip::tcp::socket>& target_socket,
                                                    const std::vector<std::uint8_t>& buf,
                                                    const connection_context& ctx)
{
    if (buf.empty())
    {
        co_return true;
    }

    const auto [write_ec, write_n] = co_await asio::async_write(*target_socket, asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
    (void)write_n;
    if (write_ec)
    {
        LOG_CTX_WARN(ctx, "{} write initial buf failed", log_event::kFallback);
        co_return false;
    }
    co_return true;
}

}    // namespace

remote_server::remote_server(io_context_pool& pool, const config& cfg)
    : io_context_(pool.get_io_context()),
      acceptor_(io_context_),
      replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries)),
      fallbacks_(cfg.fallbacks),
      fallback_guard_config_(cfg.reality.fallback_guard),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    const auto ep = resolve_inbound_endpoint(cfg.inbound);
    if (!setup_server_acceptor(acceptor_, ep))
    {
        return;
    }
    private_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.private_key);
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id");
    fallback_type_ = cfg.reality.type;
    if (!fallback_type_.empty() && fallback_type_ != "tcp")
    {
        LOG_WARN("reality fallback type not supported {}", fallback_type_);
    }
    apply_reality_dest_config(cfg.reality, fallback_dest_host_, fallback_dest_port_, fallback_dest_valid_, auth_config_valid_);
    std::error_code ignore;
    const auto pub = reality::crypto_util::extract_public_key(private_key_, ignore);
    LOG_INFO("server public key size {}", pub.size());
}

remote_server::~remote_server()
{
    if (!private_key_.empty())
    {
        OPENSSL_cleanse(private_key_.data(), private_key_.size());
    }
}

void remote_server::start()
{
    stop_.store(false, std::memory_order_release);
    started_.store(true, std::memory_order_release);
    asio::co_spawn(io_context_, [self = shared_from_this()] { return self->accept_loop(); }, asio::detached);
}

void remote_server::set_certificate(std::string sni,
                                    std::vector<std::uint8_t> cert_msg,
                                    reality::server_fingerprint fp,
                                    const std::string& trace_id)
{
    if (!started_.load(std::memory_order_acquire) || io_context_.get_executor().running_in_this_thread())
    {
        cert_manager_.set_certificate(sni, std::move(cert_msg), std::move(fp), trace_id);
        return;
    }

    auto done = std::make_shared<std::promise<void>>();
    auto done_future = done->get_future();
    asio::post(io_context_,
               [this, sni = std::move(sni), cert_msg = std::move(cert_msg), fp = std::move(fp), trace_id, done]() mutable
               {
                   cert_manager_.set_certificate(sni, std::move(cert_msg), std::move(fp), trace_id);
                   done->set_value();
               });
    done_future.wait();
}

void remote_server::stop()
{
    stop_.store(true, std::memory_order_release);
    LOG_INFO("remote server stopping");

    asio::dispatch(io_context_,
                   [self = shared_from_this()]()
                   {
                       std::error_code close_ec;
                       close_ec = self->acceptor_.close(close_ec);
                       if (close_ec && close_ec != asio::error::bad_descriptor)
                       {
                           LOG_WARN("acceptor close failed {}", close_ec.message());
                       }

                       LOG_INFO("closing {} active tunnels", self->active_tunnels_.size());
                       auto tunnels_to_close = std::move(self->active_tunnels_);
                       self->active_tunnels_.clear();

                       for (auto& weak_tunnel : tunnels_to_close)
                       {
                           const auto tunnel = weak_tunnel.lock();
                           if (tunnel != nullptr && tunnel->connection() != nullptr)
                           {
                               tunnel->connection()->stop();
                           }
                       }
                   });
}

asio::awaitable<void> remote_server::accept_loop()
{
    LOG_INFO("remote server listening for connections");
    while (!stop_.load(std::memory_order_acquire))
    {
        const auto s = std::make_shared<asio::ip::tcp::socket>(io_context_);
        const auto [accept_ec] = co_await acceptor_.async_accept(*s, asio::as_tuple(asio::use_awaitable));
        if (accept_ec)
        {
            if (should_stop_accept_loop_on_error(accept_ec, stop_, acceptor_))
            {
                LOG_INFO("acceptor closed stopping loop");
                break;
            }
            LOG_WARN("accept error {}", accept_ec.message());
            continue;
        }

        std::error_code ec;
        ec = s->set_option(asio::ip::tcp::no_delay(true), ec);
        (void)ec;
        const std::uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
        asio::co_spawn(io_context_, [self = shared_from_this(), s, conn_id]() { return self->handle(s, conn_id); }, asio::detached);
    }
}

connection_context remote_server::build_connection_context(const std::shared_ptr<asio::ip::tcp::socket>& s, const std::uint32_t conn_id)
{
    connection_context ctx;
    ctx.new_trace_id();
    ctx.conn_id(conn_id);

    const auto local_ep = s->local_endpoint();
    const auto remote_ep = s->remote_endpoint();
    const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
    const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
    ctx.local_addr(local_addr.to_string());
    ctx.local_port(local_ep.port());
    ctx.remote_addr(remote_addr.to_string());
    ctx.remote_port(remote_ep.port());
    return ctx;
}

client_hello_info remote_server::parse_client_hello(const std::vector<std::uint8_t>& initial_buf, std::string& client_sni)
{
    client_sni.clear();
    if (initial_buf.empty())
    {
        return {};
    }
    auto info = ch_parser::parse(initial_buf);
    client_sni = info.sni;
    return info;
}

bool remote_server::init_handshake_transcript(const std::vector<std::uint8_t>& initial_buf,
                                              reality::transcript& trans,
                                              const connection_context& ctx) const
{
    if (initial_buf.size() <= 5)
    {
        LOG_CTX_ERROR(ctx, "{} buffer too short", log_event::kHandshake);
        return false;
    }
    trans.update(std::vector<std::uint8_t>(initial_buf.begin() + 5, initial_buf.end()));
    return true;
}

asio::awaitable<remote_server::server_handshake_res> remote_server::delay_and_fallback(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                        const std::vector<std::uint8_t>& initial_buf,
                                                                                        const connection_context& ctx,
                                                                                        const std::string& client_sni)
{
    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
    asio::steady_timer delay_timer(io_context_);
    delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
    co_await delay_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    co_await handle_fallback(s, initial_buf, ctx, client_sni);
    co_return server_handshake_res{.ok = false};
}

asio::awaitable<remote_server::server_handshake_res> remote_server::negotiate_reality(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                      const connection_context& ctx,
                                                                                      std::vector<std::uint8_t>& initial_buf)
{
    const auto read_ok = co_await read_initial_and_validate(s, ctx, initial_buf);
    std::string client_sni;
    auto info = parse_client_hello(initial_buf, client_sni);

    if (!read_ok)
    {
        co_return co_await delay_and_fallback(s, initial_buf, ctx, client_sni);
    }

    if (!authenticate_client(info, initial_buf, ctx))
    {
        LOG_CTX_WARN(ctx, "{} auth failed sni {}", log_event::kAuth, client_sni);
        co_return co_await delay_and_fallback(s, initial_buf, ctx, client_sni);
    }

    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, info.sni);
    reality::transcript trans;
    if (!init_handshake_transcript(initial_buf, trans, ctx))
    {
        co_return server_handshake_res{.ok = false};
    }

    std::error_code ec;
    auto sh_res = co_await perform_handshake_response(s, info, trans, ctx, ec);
    if (!sh_res.ok)
    {
        LOG_CTX_ERROR(ctx, "{} response error {}", log_event::kHandshake, ec.message());
        co_return server_handshake_res{.ok = false};
    }

    if (!co_await verify_client_finished(s, sh_res.c_hs_keys, sh_res.hs_keys, trans, sh_res.cipher, sh_res.negotiated_md, ctx, ec))
    {
        co_return server_handshake_res{.ok = false};
    }

    sh_res.handshake_hash = trans.finish();
    co_return sh_res;
}

asio::awaitable<void> remote_server::handle(std::shared_ptr<asio::ip::tcp::socket> s, const std::uint32_t conn_id)
{
    auto ctx = build_connection_context(s, conn_id);
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());

    std::vector<std::uint8_t> initial_buf;
    auto sh_res = co_await negotiate_reality(s, ctx, initial_buf);
    if (!sh_res.ok)
    {
        co_return;
    }

    std::error_code ec;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_app_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_app_keys;
    if (!derive_application_traffic_keys(sh_res, c_app_keys, s_app_keys, ec))
    {
        LOG_CTX_ERROR(ctx, "{} derive app keys failed {}", log_event::kHandshake, ec.message());
        co_return;
    }

    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);

    if (co_await reject_connection_if_over_limit(s, initial_buf, ctx))
    {
        co_return;
    }

    auto tunnel = create_tunnel(s, sh_res, c_app_keys, s_app_keys, conn_id, ctx);
    install_syn_callback(tunnel, ctx);

    co_await tunnel->run();
}

bool remote_server::derive_application_traffic_keys(const server_handshake_res& sh_res,
                                                    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_app_keys,
                                                    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_app_keys,
                                                    std::error_code& ec) const
{
    const auto app_sec =
        reality::tls_key_schedule::derive_application_secrets(sh_res.hs_keys.master_secret, sh_res.handshake_hash, sh_res.negotiated_md, ec);
    if (ec)
    {
        return false;
    }

    const std::size_t key_len = EVP_CIPHER_key_length(sh_res.cipher);
    constexpr std::size_t iv_len = 12;
    c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec, key_len, iv_len, sh_res.negotiated_md);
    if (ec)
    {
        return false;
    }

    s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec, key_len, iv_len, sh_res.negotiated_md);
    if (ec)
    {
        return false;
    }

    return true;
}

asio::awaitable<bool> remote_server::reject_connection_if_over_limit(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                                     const std::vector<std::uint8_t>& initial_buf,
                                                                     const connection_context& ctx)
{
    std::erase_if(active_tunnels_, [](const auto& wp) { return wp.expired(); });
    const bool over_limit = active_tunnels_.size() >= limits_config_.max_connections;
    if (!over_limit)
    {
        co_return false;
    }

    LOG_CTX_WARN(ctx, "{} connection limit reached {} rejecting", log_event::kConnClose, limits_config_.max_connections);
    const auto info = ch_parser::parse(initial_buf);
    co_await handle_fallback(s, initial_buf, ctx, info.sni);
    co_return true;
}

std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> remote_server::create_tunnel(
    const std::shared_ptr<asio::ip::tcp::socket>& s,
    const server_handshake_res& sh_res,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_app_keys,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_app_keys,
    const std::uint32_t conn_id,
    const connection_context& ctx)
{
    reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second, sh_res.cipher);
    auto tunnel = std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(
        std::move(*s), io_context_, std::move(engine), false, conn_id, ctx.trace_id(), timeout_config_, limits_config_, heartbeat_config_);
    active_tunnels_.push_back(tunnel);
    return tunnel;
}

void remote_server::install_syn_callback(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel, const connection_context& ctx)
{
    std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> weak_tunnel = tunnel;
    tunnel->connection()->set_syn_callback(
        [weak_self = std::weak_ptr<remote_server>(shared_from_this()), weak_tunnel, ctx](const std::uint32_t id, std::vector<std::uint8_t> p)
        {
            if (auto self = weak_self.lock())
            {
                if (auto tunnel = weak_tunnel.lock())
                {
                    auto* stream_io_context = &tunnel->connection()->io_context();
                    asio::co_spawn(
                        *stream_io_context,
                        [self, tunnel, ctx, id, p = std::move(p), stream_io_context]() mutable
                        { return self->process_stream_request(tunnel, ctx, id, std::move(p), *stream_io_context); },
                        asio::detached);
                }
            }
        });
}

connection_context remote_server::build_stream_context(const connection_context& ctx, const syn_payload& syn)
{
    connection_context stream_ctx = ctx;
    if (!syn.trace_id.empty())
    {
        stream_ctx.trace_id(syn.trace_id);
    }
    return stream_ctx;
}

asio::awaitable<void> remote_server::send_stream_reset(const std::shared_ptr<mux_connection>& connection, const std::uint32_t stream_id) const
{
    (void)co_await connection->send_async(stream_id, kCmdRst, {});
}

asio::awaitable<void> remote_server::reject_stream_for_limit(const std::shared_ptr<mux_connection>& connection,
                                                             const connection_context& ctx,
                                                             const std::uint32_t stream_id) const
{
    LOG_CTX_WARN(ctx, "{} stream limit reached", log_event::kMux);
    const ack_payload ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
    std::vector<std::uint8_t> ack_data;
    mux_codec::encode_ack(ack, ack_data);
    (void)co_await connection->send_async(stream_id, kCmdAck, std::move(ack_data));
    co_await send_stream_reset(connection, stream_id);
}

asio::awaitable<void> remote_server::handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel,
                                                               const connection_context& stream_ctx,
                                                               const std::uint32_t stream_id,
                                                               const syn_payload& syn,
                                                               const std::size_t payload_size,
                                                               asio::io_context& io_context) const
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type tcp connect target {} {} payload size {}", log_event::kMux, stream_id, syn.addr, syn.port, payload_size);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_session>(connection, stream_id, io_context, stream_ctx);
    sess->set_manager(tunnel);
    if (!tunnel->try_register_stream(stream_id, sess))
    {
        LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }
    co_await sess->start(syn);
}

asio::awaitable<void> remote_server::handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& tunnel,
                                                                 const connection_context& stream_ctx,
                                                                 const std::uint32_t stream_id,
                                                                 asio::io_context& io_context) const
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, stream_id);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_udp_session>(connection, stream_id, io_context, stream_ctx);
    sess->set_manager(tunnel);
    if (!tunnel->try_register_stream(stream_id, sess))
    {
        LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }
    co_await sess->start();
}

asio::awaitable<void> remote_server::process_stream_request(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel,
                                                            const connection_context& ctx,
                                                            const std::uint32_t stream_id,
                                                            std::vector<std::uint8_t> payload,
                                                            asio::io_context& io_context) const
{
    const auto connection = tunnel->connection();
    if (!connection->can_accept_stream())
    {
        co_await reject_stream_for_limit(connection, ctx, stream_id);
        co_return;
    }

    syn_payload syn;
    if (!mux_codec::decode_syn(payload.data(), payload.size(), syn))
    {
        LOG_CTX_WARN(ctx, "{} stream {} invalid syn", log_event::kMux, stream_id);
        co_await send_stream_reset(connection, stream_id);
        co_return;
    }

    auto stream_ctx = build_stream_context(ctx, syn);
    if (!syn.trace_id.empty())
    {
        LOG_CTX_DEBUG(stream_ctx, "{} linked client trace id {}", log_event::kMux, syn.trace_id);
    }

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        co_await handle_tcp_connect_stream(tunnel, stream_ctx, stream_id, syn, payload.size(), io_context);
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        co_await handle_udp_associate_stream(tunnel, stream_ctx, stream_id, io_context);
        co_return;
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, stream_id);
}

asio::awaitable<bool> remote_server::read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                               const connection_context& ctx,
                                                               std::vector<std::uint8_t>& buf)
{
    buf.resize(constants::net::kBufferSize);
    const auto [read_ec, n] = co_await s->async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
    if (read_ec)
    {
        LOG_CTX_ERROR(ctx, "{} initial read error {}", log_event::kHandshake, read_ec.message());
        co_return false;
    }
    buf.resize(n);
    if (n < 5)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header short read {}", log_event::kHandshake, n);
        co_return false;
    }

    if (buf[0] != 0x16)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header 0x{:02x}", log_event::kHandshake, buf[0]);
        co_return false;
    }
    const std::size_t len = static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    while (buf.size() < 5 + len)
    {
        std::vector<std::uint8_t> tmp(5 + len - buf.size());
        const auto [read_ec2, n2] = co_await asio::async_read(*s, asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
        if (read_ec2)
        {
            co_return false;
        }
        buf.insert(buf.end(), tmp.begin(), tmp.end());
    }
    LOG_CTX_DEBUG(ctx, "{} received client hello record size {}", log_event::kHandshake, buf.size());
    co_return true;
}

std::optional<remote_server::selected_key_share> remote_server::select_key_share(const client_hello_info& info, const connection_context& ctx) const
{
    if (info.has_x25519_share && info.x25519_pub.size() == 32)
    {
        selected_key_share sel;
        sel.group = reality::tls_consts::group::kX25519;
        sel.x25519_pub = info.x25519_pub;
        return sel;
    }

    LOG_CTX_ERROR(ctx, "{} no supported key share", log_event::kHandshake);
    return std::nullopt;
}

bool remote_server::authenticate_client(const client_hello_info& info, const std::vector<std::uint8_t>& buf, const connection_context& ctx)
{
    if (!validate_auth_inputs(info, auth_config_valid_, ctx))
    {
        return false;
    }

    const auto selected = select_key_share(info, ctx);
    if (!selected.has_value())
    {
        return false;
    }

    std::error_code ec;
    const auto auth = decrypt_auth_payload(info, buf, private_key_, selected->x25519_pub, ec, ctx);
    if (!auth.has_value())
    {
        return false;
    }

    if (!verify_auth_payload_fields(auth, short_id_bytes_, info.sni, ctx))
    {
        return false;
    }
    if (!verify_auth_timestamp(auth->timestamp, info.sni, ctx))
    {
        return false;
    }

    return verify_replay_guard(replay_cache_, info.session_id, info.sni, ctx);
}

asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                               const client_hello_info& info,
                                                                                               reality::transcript& trans,
                                                                                               const connection_context& ctx,
                                                                                               std::error_code& ec)
{
    const auto key_pair = key_rotator_.get_current_key();
    const std::uint8_t* public_key = key_pair->public_key;
    const std::uint8_t* private_key = key_pair->private_key;
    std::vector<std::uint8_t> server_random;
    if (!generate_server_random(server_random, ec))
    {
        co_return server_handshake_res{.ok = false};
    }

    log_ephemeral_public_key(public_key, ctx);

    std::vector<std::uint8_t> sh_shared;
    std::vector<std::uint8_t> key_share_data;
    std::uint16_t key_share_group = 0;
    if (!derive_server_key_share(info, public_key, private_key, ctx, sh_shared, key_share_data, key_share_group, ec))
    {
        co_return server_handshake_res{.ok = false};
    }

    const auto target = resolve_certificate_target(info);
    const auto cert = co_await load_certificate_material(target, ctx);
    if (!cert.has_value())
    {
        ec = asio::error::connection_refused;
        co_return server_handshake_res{.ok = false};
    }

    const std::uint16_t cipher_suite = select_cipher_suite_from_fingerprint(cert->fingerprint);
    const auto crypto = build_handshake_crypto(server_random,
                                               info.session_id,
                                               cipher_suite,
                                               key_share_group,
                                               key_share_data,
                                               sh_shared,
                                               cert->cert_msg,
                                               cert->fingerprint.alpn,
                                               private_key_,
                                               trans,
                                               ec,
                                               ctx);
    if (!crypto.ok)
    {
        co_return server_handshake_res{.ok = false};
    }

    if (!co_await send_server_hello_flight(s, crypto.sh_msg, crypto.flight2_enc, ctx, ec))
    {
        co_return server_handshake_res{.ok = false};
    }

    co_return server_handshake_res{
        .ok = true,
        .hs_keys = crypto.hs_keys,
        .s_hs_keys = crypto.s_hs_keys,
        .c_hs_keys = crypto.c_hs_keys,
        .cipher = crypto.cipher,
        .negotiated_md = crypto.md};
}

bool remote_server::derive_server_key_share(const client_hello_info& info,
                                            const std::uint8_t* public_key,
                                            const std::uint8_t* private_key,
                                            const connection_context& ctx,
                                            std::vector<std::uint8_t>& sh_shared,
                                            std::vector<std::uint8_t>& key_share_data,
                                            std::uint16_t& key_share_group,
                                            std::error_code& ec) const
{
    const auto selected = select_key_share(info, ctx);
    if (!selected.has_value())
    {
        ec = asio::error::invalid_argument;
        return false;
    }

    sh_shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), selected->x25519_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        return false;
    }

    key_share_data.assign(public_key, public_key + 32);
    key_share_group = selected->group;
    return true;
}

remote_server::certificate_target remote_server::resolve_certificate_target(const client_hello_info& info) const
{
    certificate_target target;
    target.cert_sni = info.sni;
    target.fetch_host = "www.apple.com";
    target.fetch_port = 443;

    const auto fb = find_fallback_target_by_sni(info.sni);
    if (!fb.first.empty())
    {
        target.fetch_host = fb.first;
        target.fetch_port = parse_fallback_port(fb.second);
        if (target.cert_sni.empty())
        {
            target.cert_sni = fb.first;
        }
    }
    return target;
}

asio::awaitable<std::optional<remote_server::certificate_material>> remote_server::load_certificate_material(const certificate_target& target,
                                                                                                              const connection_context& ctx)
{
    const auto cached_entry = cert_manager_.get_certificate(target.cert_sni);
    if (cached_entry.has_value())
    {
        co_return certificate_material{
            .cert_msg = cached_entry->cert_msg,
            .fingerprint = cached_entry->fingerprint};
    }

    LOG_CTX_INFO(ctx, "{} certificate miss fetching {} {}", log_event::kCert, target.fetch_host, target.fetch_port);
    const auto res = co_await reality::cert_fetcher::fetch(io_context_, target.fetch_host, target.fetch_port, target.cert_sni, ctx.trace_id());
    if (!res.has_value())
    {
        LOG_CTX_ERROR(ctx, "{} fetch certificate failed", log_event::kCert);
        co_return std::nullopt;
    }

    certificate_material material{
        .cert_msg = res->cert_msg,
        .fingerprint = res->fingerprint};
    set_certificate(target.cert_sni, material.cert_msg, material.fingerprint, ctx.trace_id());
    co_return material;
}

asio::awaitable<bool> remote_server::send_server_hello_flight(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                              const std::vector<std::uint8_t>& sh_msg,
                                                              const std::vector<std::uint8_t>& flight2_enc,
                                                              const connection_context& ctx,
                                                              std::error_code& ec) const
{
    LOG_CTX_INFO(ctx, "generated sh msg size {}", sh_msg.size());
    const auto out_sh = compose_server_hello_flight(sh_msg, flight2_enc);
    LOG_CTX_INFO(ctx, "total out sh size {}", out_sh.size());
    LOG_CTX_DEBUG(ctx, "{} sending server hello flight size {}", log_event::kHandshake, out_sh.size());
    const auto [we, wn] = co_await asio::async_write(*s, asio::buffer(out_sh), asio::as_tuple(asio::use_awaitable));
    (void)wn;
    if (we)
    {
        ec = we;
        co_return false;
    }
    co_return true;
}

asio::awaitable<bool> remote_server::verify_client_finished(std::shared_ptr<asio::ip::tcp::socket> s,
                                                            const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                            const reality::handshake_keys& hs_keys,
                                                            const reality::transcript& trans,
                                                            const EVP_CIPHER* cipher,
                                                            const EVP_MD* md,
                                                            const connection_context& ctx,
                                                            std::error_code& ec)
{
    std::array<std::uint8_t, 5> header = {0};
    if (!co_await read_tls_record_header_allow_ccs(s, header, ctx))
    {
        co_return false;
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    std::vector<std::uint8_t> body;
    if (!co_await read_tls_record_body(s, body_len, body, ctx))
    {
        co_return false;
    }

    const auto record = compose_tls_record(header, body);
    std::uint8_t ctype = 0;
    const auto plaintext = reality::tls_record_layer::decrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, record, ctype, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished decrypt failed {}", log_event::kHandshake, ec.message());
        co_return false;
    }

    const auto expected_fin_verify =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), md, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished verify data failed {}", log_event::kHandshake, ec.message());
        co_return false;
    }
    co_return verify_client_finished_plaintext(plaintext, ctype, expected_fin_verify, ctx);
}

std::pair<std::string, std::string> remote_server::find_fallback_target_by_sni(const std::string& sni) const
{
    if (const auto exact = find_exact_sni_fallback(fallbacks_, sni); exact.has_value())
    {
        return *exact;
    }
    if (const auto wildcard = find_wildcard_fallback(fallbacks_); wildcard.has_value())
    {
        return *wildcard;
    }
    if (fallback_dest_valid_)
    {
        return std::make_pair(fallback_dest_host_, fallback_dest_port_);
    }
    return {};
}

asio::awaitable<void> remote_server::fallback_failed_timer(const std::uint32_t conn_id, asio::io_context& io_context)
{
    asio::steady_timer fallback_timer(io_context);
    constexpr std::uint32_t max_wait_ms = constants::fallback::kMaxWaitMs;
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> dist(0, max_wait_ms - 1);
    const std::uint32_t wait_ms = dist(gen);
    fallback_timer.expires_after(std::chrono::milliseconds(wait_ms));
    const auto [wait_ec] = co_await fallback_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (wait_ec)
    {
        LOG_ERROR("{} fallback failed timer {} ms error {}", conn_id, wait_ms, wait_ec.message());
    }
    LOG_DEBUG("{} fallback failed timer {} ms", conn_id, wait_ms);
}

asio::awaitable<void> remote_server::fallback_failed(const std::shared_ptr<asio::ip::tcp::socket>& s)
{
    char d[constants::net::kBufferSize] = {0};
    for (;;)
    {
        const auto [read_ec, n] = co_await s->async_read_some(asio::buffer(d), asio::as_tuple(asio::use_awaitable));
        if (read_ec || n == 0)
        {
            break;
        }
    }

    std::error_code ignore;
    ignore = s->shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
}

std::string remote_server::fallback_guard_key(const connection_context& ctx) const
{
    if (!ctx.remote_addr().empty())
    {
        return ctx.remote_addr();
    }
    return "unknown";
}

void remote_server::cleanup_fallback_guard_state_locked(const std::chrono::steady_clock::time_point& now)
{
    const auto ttl_seconds = std::max<std::uint32_t>(1, fallback_guard_config_.state_ttl_sec);
    const auto ttl = std::chrono::seconds(ttl_seconds);
    std::erase_if(fallback_guard_states_,
                  [&](const auto& kv)
                  { return now - kv.second.last_seen > ttl; });
}

bool remote_server::consume_fallback_token(const connection_context& ctx)
{
    if (!fallback_guard_config_.enabled)
    {
        return true;
    }

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(fallback_guard_mu_);
    cleanup_fallback_guard_state_locked(now);

    auto& state = fallback_guard_states_[fallback_guard_key(ctx)];
    if (state.tokens == 0 && state.last_seen.time_since_epoch().count() == 0)
    {
        state.tokens = static_cast<double>(fallback_guard_config_.burst);
        state.last_refill = now;
    }

    const auto rate_per_sec = static_cast<double>(fallback_guard_config_.rate_per_sec);
    if (rate_per_sec > 0)
    {
        const auto elapsed = std::chrono::duration<double>(now - state.last_refill).count();
        if (elapsed > 0)
        {
            const auto burst = static_cast<double>(fallback_guard_config_.burst);
            state.tokens = std::min(burst, state.tokens + elapsed * rate_per_sec);
            state.last_refill = now;
        }
    }
    state.last_seen = now;

    if (state.circuit_open_until > now)
    {
        statistics::instance().inc_fallback_rate_limited();
        return false;
    }

    if (state.tokens < 1.0)
    {
        statistics::instance().inc_fallback_rate_limited();
        return false;
    }

    state.tokens -= 1.0;
    return true;
}

void remote_server::record_fallback_result(const connection_context& ctx, const bool success)
{
    if (!fallback_guard_config_.enabled)
    {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(fallback_guard_mu_);
    auto it = fallback_guard_states_.find(fallback_guard_key(ctx));
    if (it == fallback_guard_states_.end())
    {
        return;
    }

    auto& state = it->second;
    state.last_seen = now;
    if (success)
    {
        state.consecutive_failures = 0;
        return;
    }

    state.consecutive_failures++;
    if (fallback_guard_config_.circuit_fail_threshold > 0 && state.consecutive_failures >= fallback_guard_config_.circuit_fail_threshold)
    {
        const auto open_sec = std::max<std::uint32_t>(1, fallback_guard_config_.circuit_open_sec);
        state.circuit_open_until = now + std::chrono::seconds(open_sec);
        state.consecutive_failures = 0;
    }
}

asio::awaitable<void> remote_server::handle_fallback(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                     const std::vector<std::uint8_t>& buf,
                                                     const connection_context& ctx,
                                                     const std::string& sni)
{
    if (!consume_fallback_token(ctx))
    {
        LOG_CTX_WARN(ctx, "{} blocked by fallback guard", log_event::kFallback);
        co_await fallback_wait_random_timer(ctx.conn_id(), io_context_);
        close_fallback_socket(s, ctx);
        co_return;
    }

    const auto fallback_target = find_fallback_target_by_sni(sni);
    if (fallback_target.first.empty())
    {
        co_await handle_fallback_without_target(s, ctx, sni, io_context_);
        record_fallback_result(ctx, false);
        co_return;
    }

    const auto target_host = fallback_target.first;
    const auto target_port = fallback_target.second;
    auto t = std::make_shared<asio::ip::tcp::socket>(io_context_);
    LOG_CTX_INFO(ctx, "{} proxying sni {} to {} {}", log_event::kFallback, sni, target_host, target_port);
    if (!co_await resolve_and_connect_fallback_target(t, io_context_, target_host, target_port, ctx))
    {
        record_fallback_result(ctx, false);
        co_return;
    }
    if (!co_await write_fallback_initial_buffer(t, buf, ctx))
    {
        record_fallback_result(ctx, false);
        co_return;
    }

    using asio::experimental::awaitable_operators::operator&&;
    co_await (proxy_half(s, t) && proxy_half(t, s));
    record_fallback_result(ctx, true);
    LOG_CTX_INFO(ctx, "{} session finished", log_event::kFallback);
}

}    // namespace mux
