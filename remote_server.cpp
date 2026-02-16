#include <ctime>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <thread>
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
#include "stop_dispatch.h"
#include "tls_record_validation.h"
#include "remote_server.h"
#include "reality_engine.h"
#include "remote_session.h"
#include "remote_udp_session.h"

namespace mux
{

namespace
{

constexpr std::uint32_t kEphemeralServerBindRetryAttempts = 120;
const auto kEphemeralServerBindRetryDelay = std::chrono::milliseconds(25);

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

struct timed_socket_read_res
{
    bool ok = false;
    bool timed_out = false;
    std::size_t read_size = 0;
    std::error_code ec;
};

[[nodiscard]] bool should_skip_fallback_after_read_failure(const std::error_code& read_ec, const std::atomic<bool>& stop_flag)
{
    if (stop_flag.load(std::memory_order_acquire))
    {
        return true;
    }
    return read_ec == asio::error::operation_aborted || read_ec == asio::error::bad_descriptor || read_ec == asio::error::timed_out;
}

asio::awaitable<timed_socket_read_res> read_socket_with_timeout(const std::shared_ptr<asio::ip::tcp::socket>& socket,
                                                                const asio::mutable_buffer buffer,
                                                                asio::io_context& io_context,
                                                                const std::uint32_t timeout_sec,
                                                                const bool require_full_buffer)
{
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
                LOG_WARN("cancel timeout socket failed {}", cancel_ec.message());
            }

            std::error_code close_ec;
            close_ec = socket->close(close_ec);
            if (close_ec && close_ec != asio::error::bad_descriptor)
            {
                LOG_WARN("close timeout socket failed {}", close_ec.message());
            }
        });

    std::error_code read_ec;
    std::size_t read_size = 0;
    if (require_full_buffer)
    {
        const auto [exact_read_ec, exact_read_size] = co_await asio::async_read(*socket, buffer, asio::as_tuple(asio::use_awaitable));
        read_ec = exact_read_ec;
        read_size = exact_read_size;
    }
    else
    {
        const auto [read_some_ec, read_some_size] = co_await socket->async_read_some(buffer, asio::as_tuple(asio::use_awaitable));
        read_ec = read_some_ec;
        read_size = read_some_size;
    }

    const auto cancelled = timer->cancel();
    (void)cancelled;
    if (timeout_triggered->load(std::memory_order_acquire))
    {
        co_return timed_socket_read_res{
            .ok = false,
            .timed_out = true,
            .ec = asio::error::timed_out};
    }
    if (read_ec)
    {
        co_return timed_socket_read_res{
            .ok = false,
            .ec = read_ec};
    }
    co_return timed_socket_read_res{
        .ok = true,
        .read_size = read_size};
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
    const bool retry_ephemeral_bind = (ep.port() == 0);
    const std::uint32_t max_attempts = retry_ephemeral_bind ? kEphemeralServerBindRetryAttempts : 1;

    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        auto close_on_failure = [&acceptor]()
        {
            std::error_code close_ec;
            acceptor.close(close_ec);
        };

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
            close_on_failure();
            return false;
        }
        ec = acceptor.bind(ep, ec);
        if (ec)
        {
            close_on_failure();
            const bool can_retry = retry_ephemeral_bind && ec == asio::error::address_in_use && (attempt + 1) < max_attempts;
            if (can_retry)
            {
                std::this_thread::sleep_for(kEphemeralServerBindRetryDelay);
                continue;
            }
            LOG_ERROR("acceptor bind failed {}", ec.message());
            return false;
        }
        ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            LOG_ERROR("acceptor listen failed {}", ec.message());
            close_on_failure();
            return false;
        }
        return true;
    }
    return false;
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
    const auto begin = port_text.data();
    const auto end = begin + port_text.size();
    auto [ptr, from_ec] = std::from_chars(begin, end, fetch_port);
    if (from_ec != std::errc() || ptr != end)
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

std::uint8_t clamp_prefix(const std::uint8_t prefix, const std::uint8_t max_prefix)
{
    if (prefix > max_prefix)
    {
        return max_prefix;
    }
    return prefix;
}

std::uint32_t mask_from_v4_prefix(const std::uint8_t prefix)
{
    if (prefix == 0)
    {
        return 0;
    }
    if (prefix >= 32)
    {
        return 0xFFFFFFFFU;
    }
    return 0xFFFFFFFFU << (32 - prefix);
}

std::string format_v4_subnet_key(const asio::ip::address_v4& address, const std::uint8_t prefix)
{
    const auto mask = mask_from_v4_prefix(prefix);
    const auto network = address.to_uint() & mask;
    return asio::ip::address_v4(network).to_string() + "/" + std::to_string(prefix);
}

std::string format_v6_subnet_key(const asio::ip::address_v6& address, const std::uint8_t prefix)
{
    auto bytes = address.to_bytes();
    if (prefix == 0)
    {
        bytes.fill(0);
    }
    else if (prefix < 128)
    {
        const std::size_t full_bytes = prefix / 8;
        const std::uint8_t rem_bits = prefix % 8;
        if (rem_bits == 0)
        {
            for (std::size_t i = full_bytes; i < bytes.size(); ++i)
            {
                bytes[i] = 0;
            }
        }
        else
        {
            const auto mask = static_cast<std::uint8_t>(0xFFU << (8 - rem_bits));
            bytes[full_bytes] &= mask;
            for (std::size_t i = full_bytes + 1; i < bytes.size(); ++i)
            {
                bytes[i] = 0;
            }
        }
    }
    return asio::ip::address_v6(bytes).to_string() + "/" + std::to_string(prefix);
}

std::string build_source_limit_key(const asio::ip::address& address, const config::limits_t& limits)
{
    const auto normalized = socks_codec::normalize_ip_address(address);
    if (normalized.is_v4())
    {
        const auto prefix_v4 = clamp_prefix(limits.source_prefix_v4, 32);
        return format_v4_subnet_key(normalized.to_v4(), prefix_v4);
    }
    if (normalized.is_v6())
    {
        const auto prefix_v6 = clamp_prefix(limits.source_prefix_v6, 128);
        return format_v6_subnet_key(normalized.to_v6(), prefix_v6);
    }
    return "unknown";
}

struct auth_inputs
{
    std::vector<std::uint8_t> auth_key;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> aad;
};

std::expected<auth_inputs, std::error_code> build_auth_decrypt_inputs(const client_hello_info& info,
                                                                      const std::vector<std::uint8_t>& buf,
                                                                      const std::vector<std::uint8_t>& server_private_key,
                                                                      const std::vector<std::uint8_t>& peer_pub_key,
                                                                      const connection_context& ctx)
{
    auto shared_result = reality::crypto_util::x25519_derive(server_private_key, peer_pub_key);
    if (!shared_result)
    {
        const auto ec = shared_result.error();
        LOG_CTX_ERROR(ctx, "{} auth fail x25519 derive failed {}", log_event::kAuth, ec.message());
        return std::unexpected(ec);
    }
    const auto& shared = *shared_result;

    const auto salt = std::vector<std::uint8_t>(info.random.begin(), info.random.begin() + 20);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    auto prk_result = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256());
    if (!prk_result)
    {
        return std::unexpected(prk_result.error());
    }
    auto auth_key_result = reality::crypto_util::hkdf_expand(*prk_result, r_info, 16, EVP_sha256());
    if (!auth_key_result)
    {
        return std::unexpected(auth_key_result.error());
    }
    
    auth_inputs out;
    out.auth_key = std::move(*auth_key_result);
    out.nonce.assign(info.random.begin() + 20, info.random.end());
    LOG_CTX_DEBUG(ctx, "auth key derived");

    if (info.sid_offset < 5)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail invalid sid offset {}", log_event::kAuth, info.sid_offset);
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    out.aad.assign(buf.begin() + 5, buf.end());
    const std::uint32_t aad_sid_offset = info.sid_offset - 5;
    if (aad_sid_offset + constants::auth::kSessionIdLen > out.aad.size())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail aad size mismatch", log_event::kAuth);
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    std::fill_n(out.aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);
    return out;
}

bool verify_auth_payload_fields(const reality::auth_payload& auth,
                                const std::vector<std::uint8_t>& short_id_bytes,
                                const std::string& sni,
                                const connection_context& ctx)
{
    if (short_id_bytes.empty())
    {
        return true;
    }

    if (short_id_bytes.size() > reality::kShortIdMaxLen)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail short id length invalid {}", log_event::kAuth, short_id_bytes.size());
        return false;
    }

    std::array<std::uint8_t, reality::kShortIdMaxLen> expected_short_id = {};
    std::copy(short_id_bytes.begin(), short_id_bytes.end(), expected_short_id.begin());
    if (CRYPTO_memcmp(auth.short_id.data(), expected_short_id.data(), expected_short_id.size()) != 0)
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
    reality::handshake_keys hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_hs_keys;
    std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_hs_keys;
    const EVP_CIPHER* cipher = nullptr;
    const EVP_MD* md = nullptr;
    std::vector<std::uint8_t> sh_msg;
    std::vector<std::uint8_t> flight2_enc;
};

std::expected<handshake_crypto_result, std::error_code> build_handshake_crypto(const std::vector<std::uint8_t>& server_random,
                                                                               const std::vector<std::uint8_t>& session_id,
                                                                               const std::uint16_t cipher_suite,
                                                                               const std::uint16_t key_share_group,
                                                                               const std::vector<std::uint8_t>& key_share_data,
                                                                               const std::vector<std::uint8_t>& shared_secret,
                                                                               const std::vector<std::uint8_t>& cert_msg,
                                                                               const std::string& alpn,
                                                                               const std::vector<std::uint8_t>& sign_key_bytes,
                                                                               reality::transcript& trans,
                                                                               const connection_context& ctx)
{
    handshake_crypto_result out;
    out.sh_msg = reality::construct_server_hello(server_random, session_id, cipher_suite, key_share_group, key_share_data);
    trans.update(out.sh_msg);

    out.md = digest_from_cipher_suite(cipher_suite);
    trans.set_protocol_hash(out.md);
    auto hs_keys_result = reality::tls_key_schedule::derive_handshake_keys(shared_secret, trans.finish(), out.md);
    if (!hs_keys_result)
    {
        return std::unexpected(hs_keys_result.error());
    }
    out.hs_keys = std::move(*hs_keys_result);

    constexpr std::size_t iv_len = 12;
    const auto key_len = key_len_from_cipher_suite(cipher_suite);
    auto c_hs = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.client_handshake_traffic_secret, key_len, iv_len, out.md);
    auto s_hs = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.server_handshake_traffic_secret, key_len, iv_len, out.md);
    if (!c_hs || !s_hs)
    {
        return std::unexpected(c_hs ? s_hs.error() : c_hs.error());
    }
    out.c_hs_keys = std::move(*c_hs);
    out.s_hs_keys = std::move(*s_hs);

    const auto enc_ext = reality::construct_encrypted_extensions(alpn);
    trans.update(enc_ext);
    trans.update(cert_msg);

    const reality::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), 32));
    if (sign_key == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to load private key", log_event::kHandshake);
        return std::unexpected(asio::error::fault);
    }

    const auto cv = reality::construct_certificate_verify(sign_key.get(), trans.finish());
    if (cv.empty())
    {
        LOG_CTX_ERROR(ctx, "{} certificate verify construct failed", log_event::kHandshake);
        return std::unexpected(asio::error::fault);
    }
    trans.update(cv);

    const auto s_fin_result =
        reality::tls_key_schedule::compute_finished_verify_data(out.hs_keys.server_handshake_traffic_secret, trans.finish(), out.md);
    if (!s_fin_result)
    {
        const auto ec = s_fin_result.error();
        LOG_CTX_ERROR(ctx, "{} compute server finished failed {}", log_event::kHandshake, ec.message());
        return std::unexpected(ec);
    }
    const auto s_fin = reality::construct_finished(*s_fin_result);
    trans.update(s_fin);

    std::vector<std::uint8_t> flight2_plain;
    flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    flight2_plain.insert(flight2_plain.end(), cert_msg.begin(), cert_msg.end());
    flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
    flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

    out.cipher = cipher_from_cipher_suite(cipher_suite);
    auto flight2_result =
        reality::tls_record_layer::encrypt_record(out.cipher, out.s_hs_keys.first, out.s_hs_keys.second, 0, flight2_plain, reality::kContentTypeHandshake);
    if (!flight2_result)
    {
        const auto ec = flight2_result.error();
        LOG_CTX_ERROR(ctx, "{} auth fail flight2 encrypt failed {}", log_event::kAuth, ec.message());
        return std::unexpected(ec);
    }
    out.flight2_enc = std::move(*flight2_result);

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

void close_socket_quietly(const std::shared_ptr<asio::ip::tcp::socket>& socket)
{
    std::error_code ec;
    ec = socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != asio::error::not_connected)
    {
        LOG_WARN("{} reject socket shutdown failed {}", log_event::kConnClose, ec.message());
    }
    ec = socket->close(ec);
    if (ec && ec != asio::error::bad_descriptor)
    {
        LOG_WARN("{} reject socket close failed {}", log_event::kConnClose, ec.message());
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

std::expected<reality::auth_payload, std::error_code> decrypt_auth_payload(const client_hello_info& info,
                                                                           const std::vector<std::uint8_t>& buf,
                                                                           const std::vector<std::uint8_t>& private_key,
                                                                           const std::vector<std::uint8_t>& peer_pub_key,
                                                                           const connection_context& ctx)
{
    const auto inputs_result = build_auth_decrypt_inputs(info, buf, private_key, peer_pub_key, ctx);
    if (!inputs_result)
    {
        return std::unexpected(inputs_result.error());
    }
    const auto& inputs = *inputs_result;

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    auto pt = reality::crypto_util::aead_decrypt(auth_cipher, inputs.auth_key, inputs.nonce, info.session_id, inputs.aad);
    if (!pt || pt->size() != 16)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail decrypt failed tag mismatch pt size {}", log_event::kAuth, pt ? pt->size() : 0);
        return std::unexpected(std::make_error_code(std::errc::bad_message));
    }

    auto payload = reality::parse_auth_payload(*pt);
    if (!payload)
    {
        return std::unexpected(std::make_error_code(std::errc::bad_message));
    }
    return *payload;
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

std::expected<std::vector<std::uint8_t>, std::error_code> generate_server_random()
{
    std::vector<std::uint8_t> server_random(32, 0);
    if (RAND_bytes(server_random.data(), 32) != 1)
    {
        return std::unexpected(std::make_error_code(std::errc::operation_canceled));
    }
    return server_random;
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

    const auto ccs_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    if (ccs_len != 1)
    {
        LOG_CTX_ERROR(ctx, "{} invalid ccs length {}", log_event::kHandshake, ccs_len);
        co_return false;
    }

    std::array<std::uint8_t, 1> ccs_body = {0};
    const auto [read_ccs_ec, read_ccs_n] = co_await asio::async_read(*socket, asio::buffer(ccs_body), asio::as_tuple(asio::use_awaitable));
    (void)read_ccs_n;
    if (read_ccs_ec)
    {
        LOG_CTX_ERROR(ctx, "{} read ccs error {}", log_event::kHandshake, read_ccs_ec.message());
        co_return false;
    }
    if (!reality::is_valid_tls13_compat_ccs(header, ccs_body[0]))
    {
        LOG_CTX_ERROR(ctx, "{} invalid ccs body {}", log_event::kHandshake, ccs_body[0]);
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
      inbound_endpoint_(resolve_inbound_endpoint(cfg.inbound)),
      replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries)),
      fallbacks_(cfg.fallbacks),
      fallback_guard_config_(cfg.reality.fallback_guard),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    const auto normalized_max_connections = normalize_max_connections(limits_config_.max_connections);
    if (normalized_max_connections != limits_config_.max_connections)
    {
        LOG_WARN("max connections is 0 using 1");
    }
    limits_config_.max_connections = normalized_max_connections;
    const auto normalized_prefix_v4 = clamp_prefix(limits_config_.source_prefix_v4, 32);
    if (normalized_prefix_v4 != limits_config_.source_prefix_v4)
    {
        LOG_WARN("source prefix v4 {} out of range using {}", limits_config_.source_prefix_v4, normalized_prefix_v4);
    }
    limits_config_.source_prefix_v4 = normalized_prefix_v4;
    const auto normalized_prefix_v6 = clamp_prefix(limits_config_.source_prefix_v6, 128);
    if (normalized_prefix_v6 != limits_config_.source_prefix_v6)
    {
        LOG_WARN("source prefix v6 {} out of range using {}", limits_config_.source_prefix_v6, normalized_prefix_v6);
    }
    limits_config_.source_prefix_v6 = normalized_prefix_v6;

    if (!setup_server_acceptor(acceptor_, inbound_endpoint_))
    {
        return;
    }
    private_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.private_key);
    if (private_key_.size() != 32)
    {
        LOG_ERROR("private key length invalid {}", private_key_.size());
        auth_config_valid_ = false;
    }
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id") && auth_config_valid_;
    fallback_type_ = cfg.reality.type;
    if (!fallback_type_.empty() && fallback_type_ != "tcp")
    {
        LOG_WARN("reality fallback type not supported {}", fallback_type_);
    }
    apply_reality_dest_config(cfg.reality, fallback_dest_host_, fallback_dest_port_, fallback_dest_valid_, auth_config_valid_);
    auto pub = reality::crypto_util::extract_public_key(private_key_);
    LOG_INFO("server public key size {}", pub ? pub->size() : 0);
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
    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        LOG_WARN("remote server already started");
        return;
    }

    if (!auth_config_valid_)
    {
        LOG_ERROR("remote server start failed invalid auth config");
        std::error_code close_ec;
        acceptor_.close(close_ec);
        if (close_ec)
        {
            LOG_ERROR("remote server close acceptor failed {}", close_ec.message());
        }
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }

    if (!ensure_acceptor_open())
    {
        LOG_ERROR("remote server start failed acceptor unavailable");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }

    stop_.store(false, std::memory_order_release);
    asio::co_spawn(io_context_, [self = shared_from_this()] { return self->accept_loop(); }, asio::detached);
}

void remote_server::drain()
{
    stop_.store(true, std::memory_order_release);
    LOG_INFO("remote server draining");

    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                self->stop_local(false);
            }
        },
        detail::dispatch_timeout_policy::kRunInline);
}

void remote_server::set_certificate(std::string sni,
                                    std::vector<std::uint8_t> cert_msg,
                                    reality::server_fingerprint fp,
                                    const std::string& trace_id)
{
    cert_manager_.set_certificate(sni, std::move(cert_msg), std::move(fp), trace_id);
}

void remote_server::stop()
{
    stop_.store(true, std::memory_order_release);
    LOG_INFO("remote server stopping");

    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                self->stop_local(true);
            }
        },
        detail::dispatch_timeout_policy::kRunInline);
}

bool remote_server::ensure_acceptor_open()
{
    if (acceptor_.is_open())
    {
        return true;
    }
    return setup_server_acceptor(acceptor_, inbound_endpoint_);
}

std::shared_ptr<remote_server::tunnel_list_t> remote_server::snapshot_active_tunnels() const
{
    auto snapshot = std::atomic_load_explicit(&active_tunnels_, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<tunnel_list_t>();
}

std::size_t remote_server::prune_expired_tunnels()
{
    for (;;)
    {
        auto current = snapshot_active_tunnels();
        auto pruned = std::make_shared<tunnel_list_t>();
        pruned->reserve(current->size());
        bool changed = false;
        for (const auto& weak_tunnel : *current)
        {
            if (weak_tunnel.expired())
            {
                changed = true;
                continue;
            }
            pruned->push_back(weak_tunnel);
        }

        if (!changed)
        {
            return current->size();
        }

        if (std::atomic_compare_exchange_weak_explicit(
                &active_tunnels_, &current, pruned, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return pruned->size();
        }
    }
}

std::size_t remote_server::active_tunnel_count() const
{
    return snapshot_active_tunnels()->size();
}

std::shared_ptr<remote_server::tunnel_list_t> remote_server::detach_active_tunnels()
{
    auto empty = std::make_shared<tunnel_list_t>();
    for (;;)
    {
        auto current = snapshot_active_tunnels();
        if (std::atomic_compare_exchange_weak_explicit(
                &active_tunnels_, &current, empty, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return current;
        }
    }
}

void remote_server::append_active_tunnel(const tunnel_ptr_t& tunnel)
{
    for (;;)
    {
        auto current = snapshot_active_tunnels();
        auto updated = std::make_shared<tunnel_list_t>();
        updated->reserve(current->size() + 1);
        for (const auto& weak_tunnel : *current)
        {
            if (!weak_tunnel.expired())
            {
                updated->push_back(weak_tunnel);
            }
        }
        updated->push_back(tunnel);
        if (std::atomic_compare_exchange_weak_explicit(
                &active_tunnels_, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

void remote_server::track_connection_socket(const std::shared_ptr<asio::ip::tcp::socket>& socket)
{
    if (socket == nullptr)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(tracked_connection_socket_mu_);
    tracked_connection_sockets_[socket.get()] = socket;
}

void remote_server::untrack_connection_socket(const std::shared_ptr<asio::ip::tcp::socket>& socket)
{
    if (socket == nullptr)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(tracked_connection_socket_mu_);
    tracked_connection_sockets_.erase(socket.get());
}

std::vector<std::shared_ptr<asio::ip::tcp::socket>> remote_server::snapshot_tracked_connection_sockets()
{
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> sockets;
    std::lock_guard<std::mutex> lock(tracked_connection_socket_mu_);
    for (auto it = tracked_connection_sockets_.begin(); it != tracked_connection_sockets_.end();)
    {
        const auto socket = it->second.lock();
        if (socket == nullptr)
        {
            it = tracked_connection_sockets_.erase(it);
            continue;
        }
        sockets.push_back(socket);
        ++it;
    }
    return sockets;
}

std::size_t remote_server::close_tracked_connection_sockets()
{
    auto sockets = snapshot_tracked_connection_sockets();
    for (const auto& socket : sockets)
    {
        close_socket_quietly(socket);
    }
    return sockets.size();
}

void remote_server::stop_local(const bool close_tunnels)
{
    started_.store(false, std::memory_order_release);

    std::error_code close_ec;
    close_ec = acceptor_.close(close_ec);
    if (close_ec && close_ec != asio::error::bad_descriptor)
    {
        LOG_WARN("acceptor close failed {}", close_ec.message());
    }

    const auto closed_connection_sockets = close_tracked_connection_sockets();
    if (closed_connection_sockets > 0)
    {
        LOG_INFO("closed {} in-flight sockets", closed_connection_sockets);
    }

    if (!close_tunnels)
    {
        LOG_INFO("drain mode active keeping {} active tunnels", prune_expired_tunnels());
        return;
    }

    LOG_INFO("closing {} active tunnels", prune_expired_tunnels());
    auto tunnels_to_close = detach_active_tunnels();

    for (auto& weak_tunnel : *tunnels_to_close)
    {
        const auto tunnel = weak_tunnel.lock();
        if (tunnel != nullptr && tunnel->connection() != nullptr)
        {
            tunnel->connection()->stop();
        }
    }
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
        const auto source_key = connection_limit_source_key(s);
        if (!try_reserve_connection_slot(source_key))
        {
            statistics::instance().inc_connection_limit_rejected();
            LOG_WARN("{} connection limit reached rejecting before handshake conn {} source {}", log_event::kConnClose, conn_id, source_key);
            close_socket_quietly(s);
            continue;
        }
        track_connection_socket(s);
        asio::co_spawn(
            io_context_,
            [self = shared_from_this(), s, conn_id, source_key]() { return self->handle(s, conn_id, source_key); },
            asio::detached);
    }
}

bool remote_server::try_reserve_connection_slot(const std::string& source_key)
{
    std::lock_guard<std::mutex> lock(connection_slot_mu_);
    const auto current = active_connection_slots_.load(std::memory_order_acquire);
    if (current >= limits_config_.max_connections)
    {
        return false;
    }

    if (limits_config_.max_connections_per_source > 0)
    {
        auto& source_slots = active_source_connection_slots_[source_key];
        if (source_slots >= limits_config_.max_connections_per_source)
        {
            return false;
        }
        source_slots++;
    }

    active_connection_slots_.store(current + 1, std::memory_order_release);
    return true;
}

void remote_server::release_connection_slot(const std::string& source_key)
{
    std::lock_guard<std::mutex> lock(connection_slot_mu_);
    const auto current = active_connection_slots_.load(std::memory_order_acquire);
    if (current > 0)
    {
        active_connection_slots_.store(current - 1, std::memory_order_release);
    }

    if (limits_config_.max_connections_per_source == 0)
    {
        return;
    }

    const auto it = active_source_connection_slots_.find(source_key);
    if (it == active_source_connection_slots_.end())
    {
        return;
    }

    if (it->second <= 1)
    {
        active_source_connection_slots_.erase(it);
    }
    else
    {
        it->second--;
    }
}

std::string remote_server::connection_limit_source_key(const std::shared_ptr<asio::ip::tcp::socket>& s) const
{
    std::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (remote_ep_ec)
    {
        return "unknown";
    }
    return build_source_limit_key(remote_ep.address(), limits_config_);
}

asio::awaitable<void> remote_server::handle(std::shared_ptr<asio::ip::tcp::socket> s,
                                            const std::uint32_t conn_id,
                                            std::string source_key)
{
    [[maybe_unused]] const std::shared_ptr<void> slot_guard(
        nullptr,
        [self = shared_from_this(), source_key = std::move(source_key)](void*) mutable
        {
            self->release_connection_slot(source_key);
        });
    [[maybe_unused]] const std::shared_ptr<void> tracked_socket_guard(
        nullptr,
        [self = shared_from_this(), s](void*) mutable
        {
            self->untrack_connection_socket(s);
        });

    auto ctx = build_connection_context(s, conn_id);
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());

    std::vector<std::uint8_t> initial_buf;
    auto sh_res = co_await negotiate_reality(s, ctx, initial_buf);
    if (!sh_res.ok)
    {
        co_return;
    }

    auto app_keys_result = derive_application_traffic_keys(sh_res);
    if (!app_keys_result)
    {
        LOG_CTX_ERROR(ctx, "{} derive app keys failed {}", log_event::kHandshake, app_keys_result.error().message());
        co_return;
    }
    const auto& app_keys = *app_keys_result;

    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);

    if (co_await reject_connection_if_over_limit(s, initial_buf, ctx))
    {
        co_return;
    }

    auto tunnel = create_tunnel(s, sh_res, app_keys.c_app_keys, app_keys.s_app_keys, conn_id, ctx);
    untrack_connection_socket(s);
    install_syn_callback(tunnel, ctx);

    co_await tunnel->run();
}

connection_context remote_server::build_connection_context(const std::shared_ptr<asio::ip::tcp::socket>& s, const std::uint32_t conn_id)
{
    connection_context ctx;
    ctx.new_trace_id();
    ctx.conn_id(conn_id);

    std::error_code local_ep_ec;
    const auto local_ep = s->local_endpoint(local_ep_ec);
    if (!local_ep_ec)
    {
        const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
        ctx.local_addr(local_addr.to_string());
        ctx.local_port(local_ep.port());
    }
    else
    {
        LOG_CTX_WARN(ctx, "{} query local endpoint failed {}", log_event::kConnInit, local_ep_ec.message());
        ctx.local_addr("unknown");
        ctx.local_port(0);
    }

    std::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (!remote_ep_ec)
    {
        const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
        ctx.remote_addr(remote_addr.to_string());
        ctx.remote_port(remote_ep.port());
    }
    else
    {
        LOG_CTX_WARN(ctx, "{} query remote endpoint failed {}", log_event::kConnInit, remote_ep_ec.message());
        ctx.remote_addr("unknown");
        ctx.remote_port(0);
    }
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
    if (stop_.load(std::memory_order_acquire))
    {
        close_socket_quietly(s);
        co_return server_handshake_res{.ok = false, .ec = asio::error::operation_aborted};
    }

    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
    asio::steady_timer delay_timer(io_context_);
    delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
    const auto [delay_ec] = co_await delay_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (delay_ec && delay_ec != asio::error::operation_aborted)
    {
        LOG_CTX_WARN(ctx, "{} fallback delay timer failed {}", log_event::kFallback, delay_ec.message());
    }
    if (stop_.load(std::memory_order_acquire))
    {
        close_socket_quietly(s);
        co_return server_handshake_res{.ok = false, .ec = asio::error::operation_aborted};
    }
    co_await handle_fallback(s, initial_buf, ctx, client_sni);
    co_return server_handshake_res{.ok = false};
}

asio::awaitable<remote_server::server_handshake_res> remote_server::negotiate_reality(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                      const connection_context& ctx,
                                                                                      std::vector<std::uint8_t>& initial_buf)
{
    const auto read_res = co_await read_initial_and_validate(s, ctx, initial_buf);
    if (!read_res.ok)
    {
        if (!read_res.allow_fallback || stop_.load(std::memory_order_acquire))
        {
            co_return server_handshake_res{.ok = false, .ec = read_res.ec};
        }
        std::string client_sni;
        (void)parse_client_hello(initial_buf, client_sni);
        co_return co_await delay_and_fallback(s, initial_buf, ctx, client_sni);
    }

    std::string client_sni;
    auto info = parse_client_hello(initial_buf, client_sni);

    if (!authenticate_client(info, initial_buf, ctx))
    {
        if (stop_.load(std::memory_order_acquire))
        {
            co_return server_handshake_res{.ok = false, .ec = asio::error::operation_aborted};
        }
        LOG_CTX_WARN(ctx, "{} auth failed sni {}", log_event::kAuth, client_sni);
        co_return co_await delay_and_fallback(s, initial_buf, ctx, client_sni);
    }

    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, info.sni);
    reality::transcript trans;
    if (!init_handshake_transcript(initial_buf, trans, ctx))
    {
        co_return server_handshake_res{.ok = false};
    }

    auto sh_res = co_await perform_handshake_response(s, info, trans, ctx);
    if (!sh_res.ok)
    {
        LOG_CTX_ERROR(ctx, "{} response error {}", log_event::kHandshake, sh_res.ec.message());
        co_return server_handshake_res{.ok = false};
    }

    if (const auto ec = co_await verify_client_finished(s, sh_res.c_hs_keys, sh_res.hs_keys, trans, sh_res.cipher, sh_res.negotiated_md, ctx); ec)
    {
        co_return server_handshake_res{.ok = false};
    }

    sh_res.handshake_hash = trans.finish();
    co_return sh_res;
}

std::expected<remote_server::app_keys, std::error_code> remote_server::derive_application_traffic_keys(
    const server_handshake_res& sh_res) const
{
    auto app_sec =
        reality::tls_key_schedule::derive_application_secrets(sh_res.hs_keys.master_secret, sh_res.handshake_hash, sh_res.negotiated_md);
    if (!app_sec)
    {
        return std::unexpected(app_sec.error());
    }

    const std::size_t key_len = EVP_CIPHER_key_length(sh_res.cipher);
    constexpr std::size_t iv_len = 12;
    auto c_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec->first, key_len, iv_len, sh_res.negotiated_md);
    if (!c_keys)
    {
        return std::unexpected(c_keys.error());
    }

    auto s_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec->second, key_len, iv_len, sh_res.negotiated_md);
    if (!s_keys)
    {
        return std::unexpected(s_keys.error());
    }

    app_keys keys;
    keys.c_app_keys = std::move(*c_keys);
    keys.s_app_keys = std::move(*s_keys);
    return keys;
}

asio::awaitable<bool> remote_server::reject_connection_if_over_limit(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                                     const std::vector<std::uint8_t>& initial_buf,
                                                                     const connection_context& ctx)
{
    const bool over_limit = prune_expired_tunnels() >= limits_config_.max_connections;
    if (!over_limit)
    {
        co_return false;
    }

    statistics::instance().inc_connection_limit_rejected();
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
    append_active_tunnel(tunnel);
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
    statistics::instance().inc_stream_limit_rejected();
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
    const auto sess = std::make_shared<remote_udp_session>(connection, stream_id, io_context, stream_ctx, timeout_config_);
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

asio::awaitable<remote_server::initial_read_res> remote_server::read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                           const connection_context& ctx,
                                                                                           std::vector<std::uint8_t>& buf)
{
    const auto timeout_sec = std::max<std::uint32_t>(1, timeout_config_.read);
    if (stop_.load(std::memory_order_acquire))
    {
        co_return initial_read_res{.ok = false, .allow_fallback = false, .ec = asio::error::operation_aborted};
    }

    buf.resize(constants::net::kBufferSize);
    const auto first_read = co_await read_socket_with_timeout(s, asio::buffer(buf), io_context_, timeout_sec, false);
    if (!first_read.ok)
    {
        if (first_read.timed_out)
        {
            LOG_CTX_WARN(ctx, "{} initial read timed out {}s", log_event::kHandshake, timeout_sec);
        }
        else if (!should_skip_fallback_after_read_failure(first_read.ec, stop_))
        {
            LOG_CTX_ERROR(ctx, "{} initial read error {}", log_event::kHandshake, first_read.ec.message());
        }
        co_return initial_read_res{.ok = false, .allow_fallback = false, .ec = first_read.ec};
    }
    const auto n = first_read.read_size;
    buf.resize(n);
    if (n < 5)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header short read {}", log_event::kHandshake, n);
        co_return initial_read_res{.ok = false, .allow_fallback = true};
    }

    if (buf[0] != 0x16)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header 0x{:02x}", log_event::kHandshake, buf[0]);
        co_return initial_read_res{.ok = false, .allow_fallback = true};
    }
    const std::size_t len = static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    while (buf.size() < 5 + len)
    {
        if (stop_.load(std::memory_order_acquire))
        {
            co_return initial_read_res{.ok = false, .allow_fallback = false, .ec = asio::error::operation_aborted};
        }
        std::vector<std::uint8_t> tmp(5 + len - buf.size());
        const auto extra_read = co_await read_socket_with_timeout(s, asio::buffer(tmp), io_context_, timeout_sec, true);
        if (!extra_read.ok)
        {
            if (extra_read.timed_out)
            {
                LOG_CTX_WARN(ctx, "{} handshake body read timed out {}s", log_event::kHandshake, timeout_sec);
            }
            else if (!should_skip_fallback_after_read_failure(extra_read.ec, stop_))
            {
                LOG_CTX_ERROR(ctx, "{} handshake body read error {}", log_event::kHandshake, extra_read.ec.message());
            }
            co_return initial_read_res{.ok = false, .allow_fallback = false, .ec = extra_read.ec};
        }
        const auto n2 = extra_read.read_size;
        tmp.resize(n2);
        buf.insert(buf.end(), tmp.begin(), tmp.end());
    }
    LOG_CTX_DEBUG(ctx, "{} received client hello record size {}", log_event::kHandshake, buf.size());
    co_return initial_read_res{.ok = true};
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

    const auto auth = decrypt_auth_payload(info, buf, private_key_, selected->x25519_pub, ctx);
    if (!auth.has_value())
    {
        return false;
    }

    if (!verify_auth_payload_fields(*auth, short_id_bytes_, info.sni, ctx))
    {
        return false;
    }
    if (!verify_auth_timestamp(auth->timestamp, info.sni, ctx))
    {
        return false;
    }

    return verify_replay_guard(replay_cache_, info.session_id, info.sni, ctx);
}

asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(
    std::shared_ptr<asio::ip::tcp::socket> s,
    const client_hello_info& info,
    reality::transcript& trans,
    const connection_context& ctx)
{
    const auto key_pair = key_rotator_.get_current_key();
    if (key_pair == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} key rotation unavailable", log_event::kHandshake);
        co_return server_handshake_res{.ok = false, .ec = asio::error::fault};
    }
    const std::uint8_t* public_key = key_pair->public_key;
    const std::uint8_t* private_key = key_pair->private_key;
    
    auto server_random_result = generate_server_random();
    if (!server_random_result)
    {
        co_return server_handshake_res{.ok = false, .ec = server_random_result.error()};
    }
    const auto& server_random = *server_random_result;

    log_ephemeral_public_key(public_key, ctx);

    auto key_share_res = derive_server_key_share(info, public_key, private_key, ctx);
    if (!key_share_res)
    {
        co_return server_handshake_res{.ok = false, .ec = key_share_res.error()};
    }
    const auto& ks = *key_share_res;

    const auto target = resolve_certificate_target(info);
    const auto cert = co_await load_certificate_material(target, ctx);
    if (!cert.has_value())
    {
        co_return server_handshake_res{.ok = false, .ec = asio::error::connection_refused};
    }

    const std::uint16_t cipher_suite = select_cipher_suite_from_fingerprint(cert->fingerprint);
    auto crypto_result = build_handshake_crypto(server_random,
                                                info.session_id,
                                                cipher_suite,
                                                ks.key_share_group,
                                                ks.key_share_data,
                                                ks.sh_shared,
                                                cert->cert_msg,
                                                cert->fingerprint.alpn,
                                                private_key_,
                                                trans,
                                                ctx);
    if (!crypto_result)
    {
        co_return server_handshake_res{.ok = false, .ec = crypto_result.error()};
    }
    const auto& crypto = *crypto_result;

    if (const auto ec = co_await send_server_hello_flight(s, crypto.sh_msg, crypto.flight2_enc, ctx); ec)
    {
        co_return server_handshake_res{.ok = false, .ec = ec};
    }

    co_return server_handshake_res{
        .ok = true,
        .hs_keys = crypto.hs_keys,
        .s_hs_keys = crypto.s_hs_keys,
        .c_hs_keys = crypto.c_hs_keys,
        .cipher = crypto.cipher,
        .negotiated_md = crypto.md};
}

std::expected<remote_server::key_share_result, std::error_code> remote_server::derive_server_key_share(
    const client_hello_info& info,
    const std::uint8_t* public_key,
    const std::uint8_t* private_key,
    const connection_context& ctx) const
{
    const auto selected = select_key_share(info, ctx);
    if (!selected.has_value())
    {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    auto sh_shared_result = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), selected->x25519_pub);
    if (!sh_shared_result)
    {
        const auto ec = sh_shared_result.error();
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        return std::unexpected(ec);
    }
    
    key_share_result res;
    res.sh_shared = std::move(*sh_shared_result);
    res.key_share_data.assign(public_key, public_key + 32);
    res.key_share_group = selected->group;
    return res;
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

asio::awaitable<std::error_code> remote_server::send_server_hello_flight(
    const std::shared_ptr<asio::ip::tcp::socket>& s,
    const std::vector<std::uint8_t>& sh_msg,
    const std::vector<std::uint8_t>& flight2_enc,
    const connection_context& ctx) const
{
    LOG_CTX_INFO(ctx, "generated sh msg size {}", sh_msg.size());
    const auto out_sh = compose_server_hello_flight(sh_msg, flight2_enc);
    LOG_CTX_INFO(ctx, "total out sh size {}", out_sh.size());
    LOG_CTX_DEBUG(ctx, "{} sending server hello flight size {}", log_event::kHandshake, out_sh.size());
    const auto [we, wn] = co_await asio::async_write(*s, asio::buffer(out_sh), asio::as_tuple(asio::use_awaitable));
    (void)wn;
    if (we)
    {
        co_return we;
    }
    co_return std::error_code{};
}

asio::awaitable<std::error_code> remote_server::verify_client_finished(
    std::shared_ptr<asio::ip::tcp::socket> s,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
    const reality::handshake_keys& hs_keys,
    const reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md,
    const connection_context& ctx)
{
    std::array<std::uint8_t, 5> header = {0};
    if (!co_await read_tls_record_header_allow_ccs(s, header, ctx))
    {
        co_return asio::error::fault;
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    std::vector<std::uint8_t> body;
    if (!co_await read_tls_record_body(s, body_len, body, ctx))
    {
        co_return asio::error::fault;
    }

    const auto record = compose_tls_record(header, body);
    std::uint8_t ctype = 0;
    auto plaintext_result = reality::tls_record_layer::decrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, record, ctype);
    if (!plaintext_result)
    {
        const auto ec = plaintext_result.error();
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished decrypt failed {}", log_event::kHandshake, ec.message());
        co_return ec;
    }

    auto expected_fin_verify =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), md);
    if (!expected_fin_verify)
    {
        const auto ec = expected_fin_verify.error();
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished verify data failed {}", log_event::kHandshake, ec.message());
        co_return ec;
    }
    
    if (!verify_client_finished_plaintext(*plaintext_result, ctype, *expected_fin_verify, ctx))
    {
        co_return std::make_error_code(std::errc::bad_message);
    }
    co_return std::error_code{};
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
    if (stop_.load(std::memory_order_acquire))
    {
        close_fallback_socket(s, ctx);
        co_return;
    }

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
