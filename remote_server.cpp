#include <array>
#include <ctime>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <cctype>
#include <expected>
#include <optional>
#include <algorithm>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "ch_parser.h"
#include "constants.h"
#include "timeout_io.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "transcript.h"
#include "crypto_util.h"
#include "scoped_exit.h"
#include "log_context.h"
#include "cert_fetcher.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "reality_core.h"
#include "replay_cache.h"
#include "remote_server.h"
#include "remote_session.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "remote_udp_session.h"
#include "tls_record_validation.h"

namespace mux
{

struct reality_context
{
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    connection_context ctx;
    std::vector<std::uint8_t> client_hello_record;
    std::vector<std::uint8_t> client_hello_handshake;
    client_hello_info client_hello;
    std::uint16_t key_share_group = 0;
    std::vector<std::uint8_t> mlkem768_peer_pub;
    std::vector<std::uint8_t> x25519_peer_pub;
    reality::transcript transcript;
    std::vector<std::uint8_t> server_random;
    std::vector<std::uint8_t> server_key_share_data;
    std::vector<std::uint8_t> server_shared_secret;
    std::vector<std::uint8_t> auth_key;
    std::vector<std::uint8_t> cert_msg;
};

namespace
{

constexpr std::size_t kTlsRecordHeaderSize = 5;
constexpr std::uint16_t kMaxTlsPlaintextRecordLen = static_cast<std::uint16_t>(reality::kMaxTlsPlaintextLen);
constexpr std::uint16_t kMaxTlsCiphertextRecordLen = static_cast<std::uint16_t>(reality::kMaxTlsPlaintextLen + 256);
constexpr std::uint32_t kMaxTlsCompatCcsRecords = 8;
constexpr std::uint16_t kFallbackTlsPort = 443;
constexpr std::size_t kFallbackRelayBufferSize = 16 * 1024;
constexpr std::uint32_t kFallbackMaxConcurrent = 32;
constexpr std::uint32_t kFallbackRateLimitWindowSec = 10;
constexpr std::size_t kFallbackMaxAttemptsPerWindowPerSource = 8;
constexpr std::size_t kFallbackAttemptTrackerMaxEntries = 4096;
constexpr std::uint32_t kSiteMaterialFetchSuccessTtlSec = 6 * 60 * 60;
constexpr std::uint32_t kSiteMaterialFetchFailureRetrySec = 5 * 60;
constexpr std::size_t kSiteMaterialCacheCapacity = 4;

std::shared_ptr<void> make_active_connection_guard()
{
    return {new int(0),
            [](void* ptr)
            {
                delete static_cast<int*>(ptr);
                statistics::instance().dec_active_connections();
            }};
}

bool equal_server_name_ascii(const std::string& lhs, const std::string& rhs)
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < lhs.size(); ++i)
    {
        const auto lhs_ch = static_cast<unsigned char>(lhs[i]);
        const auto rhs_ch = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(lhs_ch) != std::tolower(rhs_ch))
        {
            return false;
        }
    }

    return true;
}

bool verify_client_hello_sni(const client_hello_info& client_hello, const config& cfg)
{
    if (cfg.reality.sni.empty())
    {
        return true;
    }
    if (client_hello.sni.empty())
    {
        return false;
    }

    return equal_server_name_ascii(client_hello.sni, cfg.reality.sni);
}

[[nodiscard]] bool is_invalid_sni(const std::string& sni)
{
    return !reality::valid_sni_hostname(sni);
}

std::string format_fetch_error(const reality::fetch_error& error)
{
    if (error.stage.empty())
    {
        return error.reason;
    }
    if (error.reason.empty())
    {
        return error.stage;
    }
    return error.stage + ": " + error.reason;
}

boost::asio::awaitable<void> read_tls_record_header(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                    std::vector<std::uint8_t>& buf,
                                                    std::uint64_t start_ms,
                                                    std::uint32_t timeout,
                                                    boost::system::error_code& ec)
{
    while (buf.size() < kTlsRecordHeaderSize)
    {
        std::vector<std::uint8_t> header_remaining(kTlsRecordHeaderSize - buf.size());
        const auto read_timeout = timeout_io::remaining_timeout_seconds(start_ms, timeout, ec);
        if (ec)
        {
            co_return;
        }
        auto read_size = co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(header_remaining), read_timeout, ec);
        if (ec)
        {
            co_return;
        }
        header_remaining.resize(read_size);
        buf.insert(buf.end(), header_remaining.begin(), header_remaining.end());
    }
    co_return;
}

boost::asio::awaitable<void> read_tls_record_body(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                  std::vector<std::uint8_t>& buf,
                                                  std::uint32_t payload_len,
                                                  std::uint64_t start_ms,
                                                  std::uint32_t timeout,
                                                  boost::system::error_code& ec)
{
    while (buf.size() < kTlsRecordHeaderSize + payload_len)
    {
        std::vector<std::uint8_t> extra(kTlsRecordHeaderSize + payload_len - buf.size());
        const auto read_timeout = timeout_io::remaining_timeout_seconds(start_ms, timeout, ec);
        if (ec)
        {
            co_return;
        }
        const auto read_size = co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(extra), read_timeout, ec);
        if (ec)
        {
            co_return;
        }
        extra.resize(read_size);
        buf.insert(buf.end(), extra.begin(), extra.end());
    }
    co_return;
}

boost::asio::awaitable<const char*> read_client_hello_handshake(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                std::vector<std::uint8_t>& wire_buf,
                                                                std::vector<std::uint8_t>& handshake_buf,
                                                                const connection_context& ctx,
                                                                const std::uint32_t timeout,
                                                                const std::size_t max_handshake_len,
                                                                boost::system::error_code& ec)
{
    ec.clear();
    wire_buf.clear();
    handshake_buf.clear();
    const auto handshake_start_ms = timeout_io::now_ms();
    std::size_t record_count = 0;
    const auto max_records =
        std::max<std::size_t>(1, (max_handshake_len + kMaxTlsPlaintextRecordLen - 1) / kMaxTlsPlaintextRecordLen);
    const auto max_wire_len = max_handshake_len + max_records * kTlsRecordHeaderSize;
    std::uint32_t ccs_count = 0;
    while (true)
    {
        std::vector<std::uint8_t> record_buf;
        co_await read_tls_record_header(socket, record_buf, handshake_start_ms, timeout, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx, "{} read tls record header failed {}", log_event::kHandshake, ec.message());
            co_return "read_tls_record_header_failed";
        }
        if (record_buf[1] != 0x03 || record_buf[2] != 0x03)
        {
            LOG_CTX_ERROR(ctx, "{} invalid tls record version {} {}", log_event::kHandshake, record_buf[1], record_buf[2]);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return "invalid_tls_record_version";
        }
        const auto record_len = static_cast<std::uint16_t>((record_buf[3] << 8) | record_buf[4]);
        if (record_buf[0] == 0x14)
        {
            if (ccs_count >= kMaxTlsCompatCcsRecords)
            {
                statistics::instance().inc_client_finished_failures();
                LOG_CTX_ERROR(ctx, "{} too many ccs records {}", log_event::kHandshake, ccs_count);
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return "tls13_ccs_too_many";
            }
            ccs_count++;
            if (record_len != 1)
            {
                statistics::instance().inc_client_finished_failures();
                LOG_CTX_ERROR(ctx, "{} invalid ccs length {}", log_event::kHandshake, record_len);
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return "tls13_ccs_len_invalid";
            }
            co_await read_tls_record_body(socket, record_buf, record_len, handshake_start_ms, timeout, ec);
            if (ec)
            {
                statistics::instance().inc_client_finished_failures();
                LOG_CTX_ERROR(ctx, "{} read tls record body failed {}", log_event::kHandshake, ec.message());
                co_return "read_tls_record_body_failed";
            }
            const std::array<std::uint8_t, 5> header = {record_buf[0], record_buf[1], record_buf[2], record_buf[3], record_buf[4]};
            const auto ccs_body = record_buf[kTlsRecordHeaderSize];
            if (!reality::is_valid_tls13_compat_ccs(header, ccs_body))
            {
                statistics::instance().inc_client_finished_failures();
                LOG_CTX_ERROR(ctx, "{} invalid ccs body {}", log_event::kHandshake, ccs_body);
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return "tls13_ccs_body_invalid";
            }
            continue;
        }
        if (record_buf[0] != 0x16)
        {
            LOG_CTX_ERROR(ctx, "{} unexpected tls record type {}", log_event::kHandshake, record_buf[0]);
            ec = boost::asio::error::invalid_argument;
            co_return "unexpected_tls_record_type";
        }
        if (record_len > kMaxTlsPlaintextRecordLen)
        {
            LOG_CTX_ERROR(ctx, "{} client hello record too large {}", log_event::kHandshake, record_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return "client_hello_record_too_large";
        }
        if (record_len == 0)
        {
            LOG_CTX_ERROR(ctx, "{} client hello record empty", log_event::kHandshake);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return "client_hello_record_empty";
        }
        if (record_count >= max_records)
        {
            LOG_CTX_ERROR(ctx, "{} client hello record too many {}", log_event::kHandshake, record_count);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return "client_hello_record_too_many";
        }
        record_count++;

        co_await read_tls_record_body(socket, record_buf, record_len, handshake_start_ms, timeout, ec);
        if (ec)
        {
            statistics::instance().inc_client_finished_failures();
            LOG_CTX_ERROR(ctx, "{} read tls record body failed {}", log_event::kHandshake, ec.message());
            co_return "read_tls_record_body_failed";
        }

        if (record_buf.size() > max_wire_len - wire_buf.size())
        {
            LOG_CTX_ERROR(ctx, "{} client hello wire too large {}", log_event::kHandshake, wire_buf.size() + record_buf.size());
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return "client_hello_wire_too_large";
        }
        wire_buf.insert(wire_buf.end(), record_buf.begin(), record_buf.end());
        handshake_buf.insert(handshake_buf.end(), record_buf.begin() + static_cast<std::ptrdiff_t>(kTlsRecordHeaderSize), record_buf.end());
        if (handshake_buf.size() < 4)
        {
            continue;
        }
        if (handshake_buf[0] != 0x01)
        {
            LOG_CTX_ERROR(ctx, "{} unexpected client hello type {}", log_event::kHandshake, handshake_buf[0]);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return "unexpected_client_hello_type";
        }

        const auto hello_msg_len = (static_cast<std::uint32_t>(handshake_buf[1]) << 16) | (static_cast<std::uint32_t>(handshake_buf[2]) << 8) |
                                   static_cast<std::uint32_t>(handshake_buf[3]);
        const auto total_len = static_cast<std::size_t>(hello_msg_len) + 4;
        if (total_len > max_handshake_len)
        {
            LOG_CTX_ERROR(ctx, "{} client hello message too large {}", log_event::kHandshake, total_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return "client_hello_message_too_large";
        }
        if (handshake_buf.size() < total_len)
        {
            continue;
        }
        if (handshake_buf.size() != total_len)
        {
            LOG_CTX_ERROR(ctx, "{} client hello message has trailing data {}", log_event::kHandshake, handshake_buf.size() - total_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return "client_hello_message_has_trailing_data";
        }
        co_return nullptr;
    }
}

struct auth_inputs
{
    std::vector<std::uint8_t> auth_key;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> aad;
};

auth_inputs build_auth_decrypt_inputs(const reality_context& reality_ctx,
                                      const std::vector<std::uint8_t>& server_private_key,
                                      boost::system::error_code& ec)
{
    ec.clear();
    auto shared = reality::crypto_util::x25519_derive(server_private_key, reality_ctx.x25519_peer_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail x25519 derive failed {}", log_event::kAuth, ec.message());
        return {};
    }

    if (reality_ctx.client_hello.random.size() != 32 || reality_ctx.client_hello.session_id.size() != constants::auth::kSessionIdLen ||
        reality_ctx.client_hello.sid_offset == 0 ||
        reality_ctx.client_hello.sid_offset + constants::auth::kSessionIdLen > reality_ctx.client_hello_handshake.size())
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail invalid client hello fields", log_event::kAuth);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const auto salt = std::vector<std::uint8_t>(reality_ctx.client_hello.random.begin(), reality_ctx.client_hello.random.begin() + 20);
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

    auth_inputs out;
    out.auth_key = std::move(auth_key);
    out.nonce.assign(reality_ctx.client_hello.random.begin() + 20, reality_ctx.client_hello.random.end());
    LOG_CTX_DEBUG(reality_ctx.ctx, "auth key derived");

    if (reality_ctx.client_hello.sid_offset == 0)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail invalid sid offset {}", log_event::kAuth, reality_ctx.client_hello.sid_offset);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    out.aad = reality_ctx.client_hello_handshake;
    const std::uint32_t aad_sid_offset = reality_ctx.client_hello.sid_offset;
    if (aad_sid_offset + constants::auth::kSessionIdLen > out.aad.size())
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail aad size mismatch", log_event::kAuth);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::fill_n(out.aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);
    return out;
}

bool verify_auth_payload_fields(const reality::auth_payload& auth,
                                const std::vector<std::uint8_t>& short_id_bytes,
                                const reality_context& reality_ctx)
{
    if (auth.version_x != 1 || auth.version_y != 0 || auth.version_z != 0)
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        LOG_CTX_WARN(reality_ctx.ctx, "{} auth fail version mismatch {}.{}.{}", log_event::kAuth, auth.version_x, auth.version_y, auth.version_z);
        return false;
    }

    if (short_id_bytes.empty())
    {
        return true;
    }

    if (short_id_bytes.size() > reality::kShortIdMaxLen)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail short id length invalid {}", log_event::kAuth, short_id_bytes.size());
        return false;
    }

    std::array<std::uint8_t, reality::kShortIdMaxLen> expected_short_id = {};
    std::ranges::copy(short_id_bytes, expected_short_id.begin());
    if (CRYPTO_memcmp(auth.short_id.data(), expected_short_id.data(), expected_short_id.size()) != 0)
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        stats.inc_auth_short_id_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, reality_ctx.client_hello.sni);
        LOG_CTX_WARN(reality_ctx.ctx, "{} auth fail short id mismatch", log_event::kAuth);
        return false;
    }
    return true;
}

bool verify_auth_timestamp(const std::uint32_t timestamp, const reality_context& reality_ctx)
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
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kClockSkew, reality_ctx.client_hello.sni);
        LOG_CTX_WARN(reality_ctx.ctx, "{} clock skew too large diff {}s", log_event::kAuth, diff_sec);
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
    std::vector<std::uint8_t> flight2_plain;
};

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
std::size_t key_len_from_cipher_suite(const std::uint16_t cipher_suite) { return (cipher_suite == 0x1302) ? 32 : 16; }

handshake_crypto_result build_handshake_crypto(reality_context& reality_ctx,
                                               const std::uint16_t cipher_suite,
                                               const std::string& alpn,
                                               std::span<const std::uint16_t> server_hello_extension_order,
                                               std::span<const std::uint16_t> encrypted_extension_order,
                                               const bool include_encrypted_extensions_padding,
                                               const std::optional<std::uint16_t> encrypted_extensions_padding_len,
                                               const std::vector<std::uint8_t>& sign_key_bytes,
                                               boost::system::error_code& ec)
{
    ec.clear();
    handshake_crypto_result out;
    out.sh_msg = reality::construct_server_hello(reality_ctx.server_random,
                                                 reality_ctx.client_hello.session_id,
                                                 cipher_suite,
                                                 reality_ctx.key_share_group,
                                                 reality_ctx.server_key_share_data,
                                                 server_hello_extension_order);
    reality_ctx.transcript.update(out.sh_msg);

    out.md = digest_from_cipher_suite(cipher_suite);
    reality_ctx.transcript.set_protocol_hash(out.md);
    out.hs_keys = reality::tls_key_schedule::derive_handshake_keys(reality_ctx.server_shared_secret, reality_ctx.transcript.finish(), out.md, ec);
    if (ec)
    {
        return {};
    }

    constexpr std::size_t iv_len = 12;
    const auto key_len = key_len_from_cipher_suite(cipher_suite);
    out.c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, out.md);
    if (ec)
    {
        return {};
    }
    out.s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(out.hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, out.md);
    if (ec)
    {
        return {};
    }

    const auto enc_ext = reality::construct_encrypted_extensions(
        alpn, encrypted_extension_order, include_encrypted_extensions_padding, encrypted_extensions_padding_len);
    reality_ctx.transcript.update(enc_ext);
    reality_ctx.transcript.update(reality_ctx.cert_msg);

    const reality::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), 32));
    if (sign_key == nullptr)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} failed to load private key", log_event::kHandshake);
        ec = boost::asio::error::fault;
        return {};
    }

    const auto cv = reality::construct_certificate_verify(sign_key.get(), reality_ctx.transcript.finish());
    if (cv.empty())
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} certificate verify construct failed", log_event::kHandshake);
        ec = boost::asio::error::fault;
        return {};
    }
    reality_ctx.transcript.update(cv);

    const auto s_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(
        out.hs_keys.server_handshake_traffic_secret, reality_ctx.transcript.finish(), out.md, ec);
    if (ec)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} compute server finished failed {}", log_event::kHandshake, ec.message());
        return {};
    }
    const auto s_fin = reality::construct_finished(s_fin_verify);
    if (s_fin.empty())
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} server finished construct failed", log_event::kHandshake);
        ec = boost::asio::error::fault;
        return {};
    }
    reality_ctx.transcript.update(s_fin);

    out.cipher = cipher_from_cipher_suite(cipher_suite);
    out.flight2_plain.insert(out.flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    out.flight2_plain.insert(out.flight2_plain.end(), reality_ctx.cert_msg.begin(), reality_ctx.cert_msg.end());
    out.flight2_plain.insert(out.flight2_plain.end(), cv.begin(), cv.end());
    out.flight2_plain.insert(out.flight2_plain.end(), s_fin.begin(), s_fin.end());

    return out;
}

reality::auth_payload decrypt_auth_payload(reality_context& reality_ctx, const std::vector<std::uint8_t>& private_key, boost::system::error_code& ec)
{
    ec.clear();
    const auto inputs = build_auth_decrypt_inputs(reality_ctx, private_key, ec);
    if (ec)
    {
        return {};
    }
    reality_ctx.auth_key = inputs.auth_key;

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    auto pt = reality::crypto_util::aead_decrypt(auth_cipher, inputs.auth_key, inputs.nonce, reality_ctx.client_hello.session_id, inputs.aad, ec);
    if (ec || pt.size() != 16)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail decrypt failed tag mismatch pt size {}", log_event::kAuth, pt.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }

    auto payload = reality::parse_auth_payload(pt);
    if (!payload)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    return *payload;
}

bool verify_replay_guard(replay_cache& replay_cache, const reality_context& reality_ctx)
{
    if (!replay_cache.check_and_insert(reality_ctx.client_hello.session_id))
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        stats.inc_auth_replay_failures();
        stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kReplay, reality_ctx.client_hello.sni);
        LOG_CTX_WARN(reality_ctx.ctx, "{} replay attack detected sni {}", log_event::kAuth, reality_ctx.client_hello.sni);
        return false;
    }
    return true;
}

std::vector<std::uint8_t> generate_server_random(boost::system::error_code& ec)
{
    ec.clear();
    std::vector<std::uint8_t> server_random(32, 0);
    if (RAND_bytes(server_random.data(), 32) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }
    return server_random;
}

std::vector<std::uint8_t> build_reality_bound_certificate(const std::vector<std::uint8_t>& cert_template,
                                                          const std::vector<std::uint8_t>& auth_key,
                                                          const std::vector<std::uint8_t>& cert_public_key,
                                                          boost::system::error_code& ec)
{
    ec.clear();
    auto template_signature = reality::crypto_util::extract_certificate_signature(cert_template, ec);
    if (ec)
    {
        return {};
    }
    if (template_signature.size() != 64 || cert_template.size() < template_signature.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    const auto signature_offset = cert_template.size() - template_signature.size();
    if (!std::equal(template_signature.begin(), template_signature.end(), cert_template.begin() + static_cast<std::ptrdiff_t>(signature_offset)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    auto reality_signature = reality::crypto_util::hmac_sha512(auth_key, cert_public_key, ec);
    if (ec)
    {
        return {};
    }
    if (reality_signature.size() != template_signature.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<std::uint8_t> cert_der = cert_template;
    std::copy(reality_signature.begin(), reality_signature.end(), cert_der.begin() + static_cast<std::ptrdiff_t>(signature_offset));
    return cert_der;
}

bool client_offers_cipher_suite(const client_hello_info& hello, const std::uint16_t cipher_suite)
{
    return std::find(hello.cipher_suites.begin(), hello.cipher_suites.end(), cipher_suite) != hello.cipher_suites.end();
}

bool client_offers_alpn(const client_hello_info& hello, const std::string& alpn)
{
    return std::find(hello.alpn_protocols.begin(), hello.alpn_protocols.end(), alpn) != hello.alpn_protocols.end();
}

bool client_offers_signature_scheme(const client_hello_info& hello, const std::uint16_t scheme)
{
    return std::find(hello.signature_algorithms.begin(), hello.signature_algorithms.end(), scheme) != hello.signature_algorithms.end();
}

std::optional<reality::site_material_snapshot> get_cached_site_material_snapshot(reality::site_material_manager& manager, const config& cfg)
{
    if (cfg.reality.sni.empty())
    {
        return std::nullopt;
    }
    const auto snapshot = manager.get_material_snapshot(cfg.reality.sni);
    if (!snapshot.has_value() || !snapshot->material.has_value())
    {
        return std::nullopt;
    }
    return snapshot;
}

std::vector<std::vector<std::uint8_t>> build_reality_certificate_chain(const std::vector<std::uint8_t>& leaf_cert_der,
                                                                       const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    std::vector<std::vector<std::uint8_t>> cert_chain;
    cert_chain.push_back(leaf_cert_der);
    if (!site_material_snapshot.has_value())
    {
        return cert_chain;
    }

    const auto& cached_chain = site_material_snapshot->material->certificate_chain;
    cert_chain.insert(cert_chain.end(), cached_chain.begin(), cached_chain.end());
    return cert_chain;
}

std::optional<std::uint16_t> select_reality_cipher_suite(const client_hello_info& hello,
                                                         const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (site_material_snapshot.has_value())
    {
        const auto cached_cipher = normalize_cipher_suite(site_material_snapshot->material->fingerprint.cipher_suite);
        if (client_offers_cipher_suite(hello, cached_cipher))
        {
            return cached_cipher;
        }
    }

    constexpr std::array<std::uint16_t, 3> kFallbackCipherSuites = {reality::tls_consts::cipher::kTlsAes128GcmSha256,
                                                                    reality::tls_consts::cipher::kTlsAes256GcmSha384,
                                                                    reality::tls_consts::cipher::kTlsChacha20Poly1305Sha256};
    for (const auto cipher_suite : kFallbackCipherSuites)
    {
        if (client_offers_cipher_suite(hello, cipher_suite))
        {
            return cipher_suite;
        }
    }
    return std::nullopt;
}

std::string select_reality_alpn(const client_hello_info& hello, const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return {};
    }
    const auto& cached_alpn = site_material_snapshot->material->fingerprint.alpn;
    if (cached_alpn.empty())
    {
        return {};
    }
    if (!client_offers_alpn(hello, cached_alpn))
    {
        return {};
    }
    return cached_alpn;
}

std::vector<std::uint16_t> select_server_hello_extension_order(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return {};
    }
    std::vector<std::uint16_t> out;
    for (const auto ext_type : site_material_snapshot->material->server_hello_extension_types)
    {
        if (ext_type == reality::tls_consts::ext::kSupportedVersions || ext_type == reality::tls_consts::ext::kKeyShare)
        {
            out.push_back(ext_type);
        }
    }
    return out;
}

std::vector<std::uint16_t> select_encrypted_extensions_order(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return {};
    }
    std::vector<std::uint16_t> out;
    for (const auto ext_type : site_material_snapshot->material->encrypted_extension_types)
    {
        if (ext_type == reality::tls_consts::ext::kAlpn || ext_type == reality::tls_consts::ext::kPadding)
        {
            out.push_back(ext_type);
        }
    }
    return out;
}

bool should_include_encrypted_extensions_padding(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return true;
    }
    return std::find(site_material_snapshot->material->encrypted_extension_types.begin(),
                     site_material_snapshot->material->encrypted_extension_types.end(),
                     reality::tls_consts::ext::kPadding) != site_material_snapshot->material->encrypted_extension_types.end();
}

std::optional<std::uint16_t> select_encrypted_extensions_padding_len(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return std::nullopt;
    }
    return site_material_snapshot->material->encrypted_extensions_padding_len;
}

bool should_send_change_cipher_spec(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return true;
    }
    return site_material_snapshot->material->sends_change_cipher_spec;
}

std::vector<std::uint16_t> select_encrypted_handshake_record_sizes(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return {};
    }
    return site_material_snapshot->material->encrypted_handshake_record_sizes;
}

std::size_t select_reality_certificate_chain_size(const std::optional<reality::site_material_snapshot>& site_material_snapshot)
{
    if (!site_material_snapshot.has_value())
    {
        return 1;
    }
    return 1 + site_material_snapshot->material->certificate_chain.size();
}

void close_tcp_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket.close(ec);
}

void record_fallback_resolve_failure(const boost::system::error_code& ec)
{
    auto& stats = statistics::instance();
    stats.inc_fallback_resolve_failures();
    if (ec == boost::asio::error::timed_out)
    {
        stats.inc_fallback_resolve_timeouts();
    }
    else
    {
        stats.inc_fallback_resolve_errors();
    }
}

void record_fallback_connect_failure(const boost::system::error_code& ec)
{
    auto& stats = statistics::instance();
    stats.inc_fallback_connect_failures();
    if (ec == boost::asio::error::timed_out)
    {
        stats.inc_fallback_connect_timeouts();
    }
    else
    {
        stats.inc_fallback_connect_errors();
    }
}

void record_fallback_write_failure(const boost::system::error_code& ec)
{
    auto& stats = statistics::instance();
    stats.inc_fallback_write_failures();
    if (ec == boost::asio::error::timed_out)
    {
        stats.inc_fallback_write_timeouts();
    }
    else
    {
        stats.inc_fallback_write_errors();
    }
}

std::string select_fallback_target_host(const reality_context& reality_ctx, const config& cfg)
{
    if (!cfg.reality.sni.empty())
    {
        return cfg.reality.sni;
    }
    (void)reality_ctx;
    return {};
}

boost::asio::awaitable<void> connect_fallback_target(boost::asio::io_context& io_context,
                                                     boost::asio::ip::tcp::socket& upstream_socket,
                                                     const connection_context& ctx,
                                                     const config& cfg,
                                                     const std::string& host,
                                                     const std::uint16_t port,
                                                     boost::system::error_code& ec)
{
    boost::asio::ip::tcp::resolver resolver(io_context);
    const auto endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg.timeout.connect, ec);
    if (ec)
    {
        record_fallback_resolve_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage=resolve target={}:{} error={}", log_event::kFallback, host, port, ec.message());
        co_return;
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        record_fallback_resolve_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage=resolve target={}:{} error={}", log_event::kFallback, host, port, ec.message());
        co_return;
    }

    boost::system::error_code last_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : endpoints)
    {
        if (upstream_socket.is_open())
        {
            close_tcp_socket(upstream_socket);
        }

        boost::system::error_code op_ec;
        op_ec = upstream_socket.open(entry.endpoint().protocol(), op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }

        op_ec = upstream_socket.set_option(boost::asio::ip::tcp::no_delay(true), op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }

        co_await timeout_io::wait_connect_with_timeout(upstream_socket, entry.endpoint(), cfg.timeout.connect, op_ec);
        if (!op_ec)
        {
            ec.clear();
            LOG_CTX_INFO(ctx, "{} stage=connect target={}:{} connected", log_event::kFallback, host, port);
            co_return;
        }

        last_ec = op_ec;
    }

    ec = last_ec;
    record_fallback_connect_failure(ec);
    LOG_CTX_WARN(ctx, "{} stage=connect target={}:{} error={}", log_event::kFallback, host, port, ec.message());
    co_return;
}

boost::asio::awaitable<void> relay_fallback_data(
    boost::asio::ip::tcp::socket& src,
    boost::asio::ip::tcp::socket& dst,
    const connection_context& ctx,
    const config& cfg,
    const char* direction,
    const std::uint64_t fallback_start_ms)
{
    const auto fallback_timeout = cfg.timeout.idle;
    boost::system::error_code ec;
    std::vector<std::uint8_t> buf(kFallbackRelayBufferSize);
    for (;;)
    {
        const auto read_timeout = timeout_io::remaining_timeout_seconds(fallback_start_ms, fallback_timeout, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx, "{} stage={} overall timeout {}", log_event::kFallback, direction, ec.message());
            close_tcp_socket(dst);
            co_return;
        }
        const auto n = co_await timeout_io::wait_read_some_with_timeout(src, boost::asio::buffer(buf), read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = dst.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec && shutdown_ec != boost::asio::error::not_connected)
                {
                    LOG_CTX_WARN(ctx, "{} stage={} shutdown send error {}", log_event::kFallback, direction, shutdown_ec.message());
                }
                co_return;
            }
            if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted && ec != boost::asio::error::connection_reset)
            {
                LOG_CTX_WARN(ctx, "{} stage={} read error {}", log_event::kFallback, direction, ec.message());
            }
            close_tcp_socket(dst);
            co_return;
        }
        if (n == 0)
        {
            co_return;
        }

        const auto write_timeout = timeout_io::remaining_timeout_seconds(fallback_start_ms, fallback_timeout, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx, "{} stage={} overall timeout {}", log_event::kFallback, direction, ec.message());
            close_tcp_socket(dst);
            co_return;
        }
        const auto written = co_await timeout_io::wait_write_with_timeout(dst, boost::asio::buffer(buf.data(), n), write_timeout, ec);
        if (ec)
        {
            record_fallback_write_failure(ec);
            LOG_CTX_WARN(ctx, "{} stage={} write error {}", log_event::kFallback, direction, ec.message());
            co_return;
        }
        if (written != n)
        {
            ec = boost::asio::error::fault;
            record_fallback_write_failure(ec);
            LOG_CTX_WARN(ctx, "{} stage={} short write {} of {}", log_event::kFallback, direction, written, n);
            co_return;
        }
    }
}

boost::asio::awaitable<void> consume_tls13_compat_ccs(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                      const std::array<std::uint8_t, 5>& header,
                                                      const connection_context& ctx,
                                                      const std::uint32_t timeout_sec,
                                                      boost::system::error_code& ec)
{
    std::array<std::uint8_t, 1> ccs_body = {0};
    co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(ccs_body), timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (!reality::is_valid_tls13_compat_ccs(header, ccs_body[0]))
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} invalid ccs body {}", log_event::kHandshake, ccs_body[0]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> read_tls_record_header_allow_ccs(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                              std::array<std::uint8_t, 5>& header,
                                                              const connection_context& ctx,
                                                              const std::uint32_t timeout_sec,
                                                              boost::system::error_code& ec)
{
    co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(header), timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (header[1] != 0x03 || header[2] != 0x03)
    {
        LOG_CTX_ERROR(ctx, "{} invalid tls record version {} {}", log_event::kHandshake, header[1], header[2]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }

    std::uint32_t ccs_count = 0;
    while (header[0] == 0x14)
    {
        if (ccs_count >= kMaxTlsCompatCcsRecords)
        {
            statistics::instance().inc_client_finished_failures();
            LOG_CTX_ERROR(ctx, "{} too many ccs records {}", log_event::kHandshake, ccs_count);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        ccs_count++;

        const auto ccs_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
        if (ccs_len != 1)
        {
            statistics::instance().inc_client_finished_failures();
            LOG_CTX_ERROR(ctx, "{} invalid ccs length {}", log_event::kHandshake, ccs_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        co_await consume_tls13_compat_ccs(socket, header, ctx, timeout_sec, ec);
        if (ec)
        {
            co_return;
        }

        co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(header), timeout_sec, ec);
        if (ec)
        {
            co_return;
        }
        if (header[1] != 0x03 || header[2] != 0x03)
        {
            LOG_CTX_ERROR(ctx, "{} invalid tls record version {} {}", log_event::kHandshake, header[1], header[2]);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
    }

    co_return;
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

    const std::uint32_t msg_len =
        (static_cast<std::uint32_t>(plaintext[1]) << 16) | (static_cast<std::uint32_t>(plaintext[2]) << 8) | static_cast<std::uint32_t>(plaintext[3]);
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

connection_context build_connection_context(const std::shared_ptr<boost::asio::ip::tcp::socket>& s, std::uint32_t conn_id)
{
    connection_context ctx;
    ctx.new_trace_id();
    ctx.conn_id(conn_id);

    boost::system::error_code local_ep_ec;
    const auto local_ep = s->local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_CTX_WARN(ctx, "{} query local endpoint failed {}", log_event::kConnInit, local_ep_ec.message());
        ctx.local_addr("unknown");
        ctx.local_port(0);
    }
    else
    {
        const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
        ctx.local_addr(local_addr.to_string());
        ctx.local_port(local_ep.port());
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (remote_ep_ec)
    {
        LOG_CTX_WARN(ctx, "{} query remote endpoint failed {}", log_event::kConnInit, remote_ep_ec.message());
        ctx.remote_addr("unknown");
        ctx.remote_port(0);
    }
    else
    {
        const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
        ctx.remote_addr(remote_addr.to_string());
        ctx.remote_port(remote_ep.port());
    }
    return ctx;
}

}    // namespace

boost::asio::awaitable<void> remote_server::fallback_to_target_site(reality_context& reality_ctx, const char* reason)
{
    auto& ctx = reality_ctx.ctx;
    const auto host = select_fallback_target_host(reality_ctx, cfg_);
    if (host.empty())
    {
        statistics::instance().inc_fallback_no_target();
        LOG_CTX_WARN(ctx, "{} reason={} no fallback target", log_event::kFallback, reason);
        co_return;
    }

    if (!try_acquire_fallback_budget(ctx, reason))
    {
        co_return;
    }

    ctx.set_target(host, kFallbackTlsPort);
    LOG_CTX_INFO(ctx,
                 "{} reason={} target={}:{} client_hello_size={}",
                 log_event::kFallback,
                 reason,
                 host,
                 kFallbackTlsPort,
                 reality_ctx.client_hello_record.size());

    boost::asio::ip::tcp::socket upstream_socket(io_context_);
    DEFER(release_fallback_budget();
          if (reality_ctx.socket != nullptr) { close_tcp_socket(*reality_ctx.socket); } close_tcp_socket(upstream_socket););

    boost::system::error_code ec;
    co_await connect_fallback_target(io_context_, upstream_socket, ctx, cfg_, host, kFallbackTlsPort, ec);
    if (ec)
    {
        co_return;
    }

    const auto initial_write =
        co_await timeout_io::wait_write_with_timeout(upstream_socket, boost::asio::buffer(reality_ctx.client_hello_record), cfg_.timeout.write, ec);
    if (ec || initial_write != reality_ctx.client_hello_record.size())
    {
        if (!ec)
        {
            ec = boost::asio::error::fault;
        }
        record_fallback_write_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage=initial_write target={}:{} error={}", log_event::kFallback, host, kFallbackTlsPort, ec.message());
        co_return;
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    using boost::asio::experimental::awaitable_operators::operator&&;
    const auto fallback_start_ms = timeout_io::now_ms();
    co_await (relay_fallback_data(*reality_ctx.socket, upstream_socket, ctx, cfg_, "client_to_target", fallback_start_ms) &&
              relay_fallback_data(upstream_socket, *reality_ctx.socket, ctx, cfg_, "target_to_client", fallback_start_ms));

    LOG_CTX_INFO(ctx, "{} finished target={}:{}", log_event::kFallback, host, kFallbackTlsPort);
}

remote_server::remote_server(io_context_pool& pool, const config& cfg)
    : cfg_(cfg),
      pool_(pool),
      io_context_(pool.get_io_context()),
      replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries)),
      site_material_manager_(kSiteMaterialCacheCapacity)
{
    private_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.private_key);
    if (private_key_.size() != 32)
    {
        LOG_ERROR("private key length invalid {}", private_key_.size());
        return;
    }
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(short_id_bytes_));
    boost::system::error_code ec;
    auto pub = reality::crypto_util::extract_public_key(private_key_, ec);
    LOG_INFO("server public key size {}", ec ? 0 : pub.size());

    std::uint8_t cert_public_key[32] = {};
    if (!reality::crypto_util::generate_ed25519_keypair(cert_public_key, reality_cert_private_key_.data()))
    {
        LOG_ERROR("failed to generate REALITY certificate identity");
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_public_key_.assign(cert_public_key, cert_public_key + 32);
    auto cert_template = reality::crypto_util::create_self_signed_ed25519_certificate(
        std::vector<std::uint8_t>(reality_cert_private_key_.begin(), reality_cert_private_key_.end()), ec);
    if (ec)
    {
        LOG_ERROR("failed to build REALITY certificate template {}", ec.message());
        reality_cert_public_key_.clear();
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_template_ = std::move(cert_template);
}

remote_server::~remote_server()
{
    if (!private_key_.empty())
    {
        OPENSSL_cleanse(private_key_.data(), private_key_.size());
    }
    OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
}

void remote_server::start()
{
    if (!cfg_.reality.sni.empty())
    {
        boost::asio::co_spawn(
            io_context_, [self = shared_from_this()] { return self->refresh_site_material_loop(); }, group_.adapt(boost::asio::detached));
    }
    boost::asio::co_spawn(io_context_, [self = shared_from_this()] { return self->accept_loop(); }, group_.adapt(boost::asio::detached));
}

void remote_server::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(io_context_,
                      [self = shared_from_this()]()
                      {
                          boost::system::error_code ec;
                          self->acceptor_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("remote acceptor close error {}", ec.message());
                          }
                          self->group_.emit(boost::asio::cancellation_type::all);
                      });
}

boost::asio::awaitable<void> remote_server::wait_stopped()
{
    const auto [ec] = co_await group_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("remote server wait stopped failed {}", ec.message());
    }
}

bool remote_server::try_acquire_fallback_budget(const connection_context& ctx, const char* reason)
{
    const auto now_sec = timeout_io::now_second();
    const auto remote_addr = ctx.remote_addr().empty() ? std::string("unknown") : ctx.remote_addr();
    std::lock_guard<std::mutex> lock(fallback_budget_mu_);

    const auto current_active = active_fallbacks_.load(std::memory_order_relaxed);
    if (current_active >= kFallbackMaxConcurrent)
    {
        statistics::instance().inc_fallback_rate_limited();
        LOG_CTX_WARN(ctx,
                     "{} reason={} stage=rate_limit mode=concurrency active={} limit={}",
                     log_event::kFallback,
                     reason,
                     current_active,
                     kFallbackMaxConcurrent);
        return false;
    }

    auto it = fallback_attempts_by_remote_.find(remote_addr);
    if (it == fallback_attempts_by_remote_.end() && fallback_attempts_by_remote_.size() >= kFallbackAttemptTrackerMaxEntries)
    {
        for (auto cleanup_it = fallback_attempts_by_remote_.begin(); cleanup_it != fallback_attempts_by_remote_.end();)
        {
            auto& entry_attempts = cleanup_it->second;
            while (!entry_attempts.empty() && entry_attempts.front() + kFallbackRateLimitWindowSec <= now_sec)
            {
                entry_attempts.pop_front();
            }
            if (entry_attempts.empty())
            {
                cleanup_it = fallback_attempts_by_remote_.erase(cleanup_it);
                continue;
            }
            ++cleanup_it;
        }
        if (fallback_attempts_by_remote_.size() >= kFallbackAttemptTrackerMaxEntries)
        {
            statistics::instance().inc_fallback_rate_limited();
            LOG_CTX_WARN(ctx,
                         "{} reason={} stage=rate_limit mode=tracker_capacity entries={} limit={}",
                         log_event::kFallback,
                         reason,
                         fallback_attempts_by_remote_.size(),
                         kFallbackAttemptTrackerMaxEntries);
            return false;
        }
    }

    if (it == fallback_attempts_by_remote_.end())
    {
        it = fallback_attempts_by_remote_.emplace(remote_addr, std::deque<std::uint64_t>{}).first;
    }
    auto& attempts = it->second;
    while (!attempts.empty() && attempts.front() + kFallbackRateLimitWindowSec <= now_sec)
    {
        attempts.pop_front();
    }

    if (attempts.size() >= kFallbackMaxAttemptsPerWindowPerSource)
    {
        statistics::instance().inc_fallback_rate_limited();
        LOG_CTX_WARN(ctx,
                     "{} reason={} stage=rate_limit mode=per_source remote={} attempts={} window_sec={} limit={}",
                     log_event::kFallback,
                     reason,
                     remote_addr,
                     attempts.size(),
                     kFallbackRateLimitWindowSec,
                     kFallbackMaxAttemptsPerWindowPerSource);
        return false;
    }

    attempts.push_back(now_sec);
    active_fallbacks_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void remote_server::release_fallback_budget() { active_fallbacks_.fetch_sub(1, std::memory_order_relaxed); }

boost::asio::awaitable<void> remote_server::refresh_site_material_loop()
{
    const auto target_host = cfg_.reality.sni;
    if (target_host.empty())
    {
        LOG_INFO("REALITY site material refresh disabled because reality.sni is empty");
        co_return;
    }

    const std::string trace_id = "site-material:" + target_host;
    boost::asio::steady_timer refresh_timer(io_context_);

    for (;;)
    {
        const auto attempt_at = timeout_io::now_second();
        site_material_manager_.mark_fetch_started(target_host, target_host, target_host, kFallbackTlsPort, attempt_at, trace_id);
        statistics::instance().inc_site_material_fetch_attempts();

        auto fetch_result = co_await reality::cert_fetcher::fetch(
            io_context_, target_host, kFallbackTlsPort, target_host, trace_id, cfg_.timeout.connect, cfg_.timeout.connect, cfg_.timeout.connect);

        std::uint32_t sleep_seconds = kSiteMaterialFetchFailureRetrySec;
        if (fetch_result)
        {
            statistics::instance().inc_site_material_fetch_successes();
            const auto next_refresh_at = timeout_io::now_second() + kSiteMaterialFetchSuccessTtlSec;
            site_material_manager_.set_material(
                target_host, target_host, target_host, kFallbackTlsPort, std::move(fetch_result->material), next_refresh_at, trace_id);
            sleep_seconds = kSiteMaterialFetchSuccessTtlSec;
        }
        else
        {
            statistics::instance().inc_site_material_fetch_failures();
            const auto next_refresh_at = timeout_io::now_second() + kSiteMaterialFetchFailureRetrySec;
            site_material_manager_.set_fetch_failure(target_host,
                                                     target_host,
                                                     target_host,
                                                     kFallbackTlsPort,
                                                     format_fetch_error(fetch_result.error()),
                                                     attempt_at,
                                                     next_refresh_at,
                                                     trace_id);
        }

        boost::system::error_code timer_ec;
        refresh_timer.expires_after(std::chrono::seconds(sleep_seconds));
        co_await refresh_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec));
        if (timer_ec == boost::asio::error::operation_aborted)
        {
            co_return;
        }
        if (timer_ec)
        {
            LOG_WARN("REALITY site material refresh timer error {}", timer_ec.message());
        }
    }
}

boost::asio::awaitable<void> remote_server::accept_loop()
{
    LOG_INFO("remote server listening for connections");
    auto self = shared_from_this();
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(cfg_.inbound.host, ec);
    if (ec)
    {
        co_return;
    }
    auto ep = boost::asio::ip::tcp::endpoint(addr, cfg_.inbound.port);
    const bool enable_dual_stack = addr.is_v6() && addr.to_v6().is_unspecified();
    ec = acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        co_return;
    }
    ec = acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        co_return;
    }
    if (enable_dual_stack)
    {
        ec = acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            co_return;
        }
    }
    ec = acceptor_.bind(ep, ec);
    if (ec)
    {
        co_return;
    }
    ec = acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        co_return;
    }
    boost::asio::steady_timer retry_timer(io_context_);
    while (true)
    {
        auto& io = pool_.get_io_context();
        const auto s = std::make_shared<boost::asio::ip::tcp::socket>(io);
        const auto [accept_ec] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (accept_ec)
        {
            if (accept_ec == boost::asio::error::operation_aborted || accept_ec == boost::asio::error::bad_descriptor)
            {
                LOG_INFO("accept loop stopped {}", accept_ec.message());
                break;
            }
            LOG_WARN("accept error {} retrying", accept_ec.message());
            retry_timer.expires_after(std::chrono::milliseconds(200));
            const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (wait_ec && wait_ec != boost::asio::error::operation_aborted)
            {
                LOG_WARN("accept retry wait error {}", wait_ec.message());
            }
            continue;
        }

        auto& stats = statistics::instance();
        if (stats.active_connections() >= cfg_.limits.max_connections)
        {
            stats.inc_connection_limit_rejected();
            close_tcp_socket(*s);
            LOG_WARN("remote server connection limit reached drop");
            continue;
        }

        boost::system::error_code ec;
        ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
        (void)ec;
        const std::uint32_t conn_id = next_conn_id_++;
        stats.inc_active_connections();
        auto active_guard = make_active_connection_guard();
        boost::asio::co_spawn(
            io,
            [this, self, io = &io, s, conn_id, active_guard]() { return handle(*io, s, conn_id); },
            group_.adapt(boost::asio::detached));
    }
    LOG_INFO("accept loop exited");
}

boost::asio::awaitable<void> remote_server::handle(boost::asio::io_context& io,
                                                   std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                   std::uint32_t conn_id)
{
    reality_context reality_ctx;
    reality_ctx.socket = std::move(s);
    reality_ctx.ctx = build_connection_context(reality_ctx.socket, conn_id);
    auto& ctx = reality_ctx.ctx;
    auto& client_hello_wire = reality_ctx.client_hello_record;
    auto& client_hello_handshake = reality_ctx.client_hello_handshake;
    auto fallback = [&](const char* reason) -> boost::asio::awaitable<void> { co_await fallback_to_target_site(reality_ctx, reason); };
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());
    boost::system::error_code ec;
    // tls handshake
    const auto max_client_hello_len =
        static_cast<std::size_t>(std::max(cfg_.limits.max_handshake_records, 1U)) * static_cast<std::size_t>(kMaxTlsPlaintextRecordLen);
    const auto read_failure_reason = co_await read_client_hello_handshake(
        reality_ctx.socket, client_hello_wire, client_hello_handshake, ctx, cfg_.timeout.read, max_client_hello_len, ec);
    if (read_failure_reason != nullptr)
    {
        co_await fallback(read_failure_reason);
        co_return;
    }
    LOG_CTX_DEBUG(ctx,
                  "{} received client hello wire size {} handshake size {}",
                  log_event::kHandshake,
                  client_hello_wire.size(),
                  client_hello_handshake.size());

    reality_ctx.client_hello = ch_parser::parse(client_hello_handshake);
    if (reality_ctx.client_hello.malformed_sni)
    {
        LOG_CTX_WARN(ctx, "{} auth fail malformed sni extension drop", log_event::kAuth);
        if (reality_ctx.socket != nullptr)
        {
            close_tcp_socket(*reality_ctx.socket);
        }
        co_return;
    }
    if (is_invalid_sni(reality_ctx.client_hello.sni))
    {
        LOG_CTX_WARN(ctx, "{} auth fail invalid sni drop", log_event::kAuth);
        if (reality_ctx.socket != nullptr)
        {
            close_tcp_socket(*reality_ctx.socket);
        }
        co_return;
    }
    ctx.sni(reality_ctx.client_hello.sni);
    if (!verify_client_hello_sni(reality_ctx.client_hello, cfg_))
    {
        const auto client_sni = reality_ctx.client_hello.sni.empty() ? std::string("empty") : reality_ctx.client_hello.sni;
        LOG_CTX_WARN(ctx, "{} auth fail server name mismatch client={} expected={}", log_event::kAuth, client_sni, cfg_.reality.sni);
        co_await fallback("server_name_mismatch");
        co_return;
    }
    if (reality_ctx.client_hello.malformed_key_share)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed key share extension", log_event::kAuth);
        co_await fallback("malformed_key_share");
        co_return;
    }
    if (reality_ctx.client_hello.malformed_supported_groups || reality_ctx.client_hello.malformed_supported_versions ||
        reality_ctx.client_hello.malformed_renegotiation_info)
    {
        LOG_CTX_ERROR(ctx,
                      "{} auth fail malformed tls13 extensions supported_groups={} supported_versions={} renegotiation_info={}",
                      log_event::kAuth,
                      reality_ctx.client_hello.malformed_supported_groups,
                      reality_ctx.client_hello.malformed_supported_versions,
                      reality_ctx.client_hello.malformed_renegotiation_info);
        co_await fallback("malformed_tls13_extensions");
        co_return;
    }
    if (reality_ctx.client_hello.malformed_signature_algorithms)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed signature algorithms extension", log_event::kAuth);
        co_await fallback("malformed_signature_algorithms");
        co_return;
    }
    if (reality_ctx.client_hello.signature_algorithms.empty())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail missing signature algorithms extension", log_event::kAuth);
        co_await fallback("missing_signature_algorithms");
        co_return;
    }
    if (!client_offers_signature_scheme(reality_ctx.client_hello, reality::tls_consts::sig_alg::kEd25519))
    {
        LOG_CTX_WARN(ctx, "{} auth fail missing ed25519 signature algorithm", log_event::kAuth);
        co_await fallback("missing_ed25519_signature_algorithm");
        co_return;
    }
    if (!reality_ctx.client_hello.is_tls13 || reality_ctx.client_hello.session_id.size() != 32)
    {
        LOG_CTX_ERROR(ctx,
                      "{} auth fail is tls13 {} sid len {}",
                      log_event::kAuth,
                      reality_ctx.client_hello.is_tls13,
                      reality_ctx.client_hello.session_id.size());
        co_await fallback("invalid_tls13_client_hello");
        co_return;
    }
    if (reality_ctx.client_hello.random.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail random len {}", log_event::kAuth, reality_ctx.client_hello.random.size());
        co_await fallback("invalid_client_random");
        co_return;
    }
    if (client_offers_cipher_suite(reality_ctx.client_hello, reality::tls_consts::cipher::kTlsFallbackScsv))
    {
        LOG_CTX_WARN(ctx, "{} auth fail unexpected tls fallback scsv", log_event::kAuth);
        co_await fallback("unexpected_tls_fallback_scsv");
        co_return;
    }
    if (reality_ctx.client_hello.compression_methods.size() != 1)
    {
        LOG_CTX_ERROR(
            ctx, "{} auth fail illegal tls13 compression method count {}", log_event::kAuth, reality_ctx.client_hello.compression_methods.size());
        co_await fallback("illegal_tls13_compression_methods");
        co_return;
    }
    if (reality_ctx.client_hello.compression_methods[0] != 0x00)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail illegal tls13 compression method {:02x}", log_event::kAuth, reality_ctx.client_hello.compression_methods[0]);
        co_await fallback("illegal_tls13_compression_methods");
        co_return;
    }
    if (!reality_ctx.client_hello.secure_renegotiation.empty())
    {
        LOG_CTX_WARN(ctx, "{} auth fail non-empty renegotiation info len {}", log_event::kAuth, reality_ctx.client_hello.secure_renegotiation.size());
        co_await fallback("non_empty_renegotiation_info");
        co_return;
    }
    if (reality_ctx.client_hello.key_share_group == reality::tls_consts::group::kX25519MLKEM768 &&
        reality_ctx.client_hello.x25519_mlkem768_share.size() == reality::kMlkem768PublicKeySize + 32)
    {
        reality_ctx.key_share_group = reality::tls_consts::group::kX25519MLKEM768;
        reality_ctx.mlkem768_peer_pub.assign(
            reality_ctx.client_hello.x25519_mlkem768_share.begin(),
            reality_ctx.client_hello.x25519_mlkem768_share.begin() + static_cast<std::ptrdiff_t>(reality::kMlkem768PublicKeySize));
        reality_ctx.x25519_peer_pub.assign(reality_ctx.client_hello.x25519_mlkem768_share.end() - 32,
                                           reality_ctx.client_hello.x25519_mlkem768_share.end());
    }
    else if (reality_ctx.client_hello.key_share_group == reality::tls_consts::group::kX25519 && reality_ctx.client_hello.x25519_pub.size() == 32)
    {
        reality_ctx.key_share_group = reality::tls_consts::group::kX25519;
        reality_ctx.x25519_peer_pub = reality_ctx.client_hello.x25519_pub;
    }
    if (reality_ctx.x25519_peer_pub.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail missing valid x25519 key share", log_event::kAuth);
        co_await fallback("missing_x25519_share");
        co_return;
    }
    auto auth = decrypt_auth_payload(reality_ctx, private_key_, ec);
    if (ec)
    {
        co_await fallback("decrypt_auth_payload_failed");
        co_return;
    }
    if (!verify_auth_payload_fields(auth, short_id_bytes_, reality_ctx))
    {
        co_await fallback("verify_auth_payload_failed");
        co_return;
    }
    if (!verify_auth_timestamp(auth.timestamp, reality_ctx))
    {
        co_await fallback("verify_auth_timestamp_failed");
        co_return;
    }
    LOG_CTX_INFO(ctx,
                 "{} client_hello selected_key_share_group=0x{:04x} {} client_hybrid={} client_x25519={}",
                 log_event::kHandshake,
                 reality_ctx.key_share_group,
                 reality::named_group_name(reality_ctx.key_share_group),
                 reality_ctx.client_hello.has_x25519_mlkem768_share,
                 reality_ctx.client_hello.has_x25519_share);
    if (client_hello_handshake.size() < 4)
    {
        LOG_CTX_ERROR(ctx, "{} buffer too short", log_event::kHandshake);
        co_await fallback("client_hello_message_too_short");
        co_return;
    }
    reality_ctx.transcript.update(client_hello_handshake);
    auto response = co_await perform_handshake_response(reality_ctx, ec);
    if (ec)
    {
        co_return;
    }
    co_await verify_client_finished(reality_ctx, response, ec);
    if (ec)
    {
        co_return;
    }
    if (!verify_replay_guard(replay_cache_, reality_ctx))
    {
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, reality_ctx.client_hello.sni);
    response.handshake_hash = reality_ctx.transcript.finish();

    auto app_sec =
        reality::tls_key_schedule::derive_application_secrets(response.hs_keys.master_secret, response.handshake_hash, response.negotiated_md, ec);
    if (ec)
    {
        co_return;
    }

    const int key_len_raw = EVP_CIPHER_key_length(response.cipher);
    if (key_len_raw <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        co_return;
    }
    const auto key_len = static_cast<std::size_t>(key_len_raw);
    constexpr std::size_t iv_len = 12;
    auto c_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec, key_len, iv_len, response.negotiated_md);
    if (ec)
    {
        co_return;
    }

    auto s_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec, key_len, iv_len, response.negotiated_md);
    if (ec)
    {
        co_return;
    }
    struct app_keys
    {
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_app_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_app_keys;
    } keys;
    keys.c_app_keys = std::move(c_keys);
    keys.s_app_keys = std::move(s_keys);
    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);
    //
    reality_engine engine(keys.c_app_keys.first, keys.c_app_keys.second, keys.s_app_keys.first, keys.s_app_keys.second, response.cipher);
    auto tunnel = std::make_shared<mux_tunnel_impl>(std::move(*reality_ctx.socket), io, std::move(engine), cfg_, group_, conn_id, ctx.trace_id());

    std::weak_ptr<remote_server> weak_self = weak_from_this();
    std::weak_ptr<mux_tunnel_impl> weak_tunnel = tunnel;
    tunnel->set_new_stream_cb(
        [weak_self, weak_tunnel, ctx, io = &io](mux_frame frame) -> boost::asio::awaitable<void>
        {
            const auto self = weak_self.lock();
            const auto tunnel_ref = weak_tunnel.lock();
            if (self == nullptr || tunnel_ref == nullptr)
            {
                co_return;
            }
            co_await self->process_stream_request(*io, tunnel_ref, ctx, std::move(frame));
        });
    tunnel->run();

    boost::asio::steady_timer hold_timer(io);
    while (true)
    {
        const auto tunnel_ref = weak_tunnel.lock();
        if (tunnel_ref == nullptr)
        {
            break;
        }
        const auto connection = tunnel_ref->connection();
        if (connection == nullptr || !connection->is_active())
        {
            break;
        }

        hold_timer.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await hold_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
    }
    co_return;
}

static boost::asio::awaitable<void> send_stream_reset(const std::shared_ptr<mux_connection>& connection, mux_frame frame)
{
    frame.h.command = mux::kCmdRst;
    if (!frame.payload.empty())
    {
        std::vector<std::uint8_t>().swap(frame.payload);
    }
    boost::system::error_code ec;
    constexpr std::uint32_t kRstSendTimeoutSec = 1;
    co_await connection->send_async_with_timeout(std::move(frame), kRstSendTimeoutSec, ec);
}

static boost::asio::awaitable<void> handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl>& tunnel,
                                                              const connection_context& stream_ctx,
                                                              mux_frame frame,
                                                              const syn_payload& syn,
                                                              const config& cfg,
                                                              boost::asio::io_context& io_context,
                                                              task_group& group)
{
    LOG_CTX_INFO(stream_ctx,
                 "{} stream {} type tcp connect target {} {} payload size {}",
                 log_event::kMux,
                 frame.h.stream_id,
                 syn.addr,
                 syn.port,
                 frame.payload.size());

    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_tcp_session>(connection, frame.h.stream_id, io_context, stream_ctx, cfg);
    sess->set_manager(tunnel);
    boost::asio::co_spawn(
        io_context, [sess, syn]() mutable -> boost::asio::awaitable<void> { co_await sess->start(syn); }, group.adapt(boost::asio::detached));
    co_return;
}

static boost::asio::awaitable<void> handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl>& tunnel,
                                                                const connection_context& stream_ctx,
                                                                mux_frame frame,
                                                                const config& cfg,
                                                                boost::asio::io_context& io_context,
                                                                task_group& group)
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, frame.h.stream_id);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_udp_session>(connection, frame.h.stream_id, io_context, stream_ctx, cfg);
    sess->set_manager(tunnel);
    boost::asio::co_spawn(
        io_context, [sess]() mutable -> boost::asio::awaitable<void> { co_await sess->start(); }, group.adapt(boost::asio::detached));
    co_return;
}

boost::asio::awaitable<void> remote_server::process_stream_request(boost::asio::io_context& io,
                                                                   std::shared_ptr<mux_tunnel_impl> tunnel,
                                                                   const connection_context& ctx,
                                                                   mux_frame frame)
{
    const auto connection = tunnel->connection();
    syn_payload syn;
    if (!mux_codec::decode_syn(frame.payload.data(), frame.payload.size(), syn))
    {
        LOG_CTX_WARN(ctx, "{} stream {} invalid syn", log_event::kMux, frame.h.stream_id);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }

    connection_context stream_ctx = ctx;
    if (!syn.trace_id.empty())
    {
        stream_ctx.trace_id(syn.trace_id);
    }
    if (!syn.trace_id.empty())
    {
        LOG_CTX_DEBUG(stream_ctx, "{} linked client trace id {}", log_event::kMux, syn.trace_id);
    }
    if (syn.addr.empty())
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} invalid target empty", log_event::kMux, frame.h.stream_id);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdConnect && syn.port == 0)
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} invalid target {} {}", log_event::kMux, frame.h.stream_id, syn.addr, syn.port);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        co_return co_await handle_tcp_connect_stream(tunnel, stream_ctx, std::move(frame), syn, cfg_, io, group_);
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        co_return co_await handle_udp_associate_stream(tunnel, stream_ctx, std::move(frame), cfg_, io, group_);
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, frame.h.stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, std::move(frame));
}

static std::vector<std::uint8_t> compose_server_hello_flight(const std::vector<std::uint8_t>& sh_msg,
                                                             const std::vector<std::uint8_t>& flight2_plain,
                                                             const bool send_change_cipher_spec,
                                                             std::span<const std::uint16_t> encrypted_handshake_record_sizes,
                                                             const EVP_CIPHER* cipher,
                                                             const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
                                                             boost::system::error_code& ec)
{
    ec.clear();
    std::vector<std::uint8_t> out_sh;
    const auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh_msg.size()));
    out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
    out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
    if (send_change_cipher_spec)
    {
        out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    }

    std::size_t offset = 0;
    std::uint64_t seq = 0;
    const auto append_encrypted_chunk = [&](const std::size_t len) -> bool
    {
        if (len == 0 || offset >= flight2_plain.size())
        {
            return true;
        }

        std::vector<std::uint8_t> chunk(flight2_plain.begin() + static_cast<std::ptrdiff_t>(offset),
                                        flight2_plain.begin() + static_cast<std::ptrdiff_t>(offset + len));
        auto record =
            reality::tls_record_layer::encrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, chunk, reality::kContentTypeHandshake, ec);
        if (ec)
        {
            return false;
        }
        out_sh.insert(out_sh.end(), record.begin(), record.end());
        offset += len;
        return true;
    };

    if (!encrypted_handshake_record_sizes.empty())
    {
        for (std::size_t i = 0; i + 1 < encrypted_handshake_record_sizes.size() && offset < flight2_plain.size(); ++i)
        {
            const auto next_len = std::min<std::size_t>(encrypted_handshake_record_sizes[i], flight2_plain.size() - offset);
            if (!append_encrypted_chunk(next_len))
            {
                return {};
            }
        }
    }
    if (offset < flight2_plain.size() && !append_encrypted_chunk(flight2_plain.size() - offset))
    {
        return {};
    }
    return out_sh;
}

boost::asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(reality_context& reality_ctx,
                                                                                                      boost::system::error_code& ec)
{
    server_handshake_res res;
    auto& ctx = reality_ctx.ctx;
    std::array<std::uint8_t, 32> ephemeral_public_key{};
    std::array<std::uint8_t, 32> ephemeral_private_key{};
    DEFER(OPENSSL_cleanse(ephemeral_private_key.data(), ephemeral_private_key.size()));
    if (!reality::crypto_util::generate_x25519_keypair(ephemeral_public_key.data(), ephemeral_private_key.data()))
    {
        LOG_CTX_ERROR(ctx, "{} generate ephemeral x25519 key failed", log_event::kHandshake);
        ec = boost::asio::error::fault;
        co_return res;
    }
    const std::uint8_t* public_key = ephemeral_public_key.data();
    const std::uint8_t* private_key = ephemeral_private_key.data();

    reality_ctx.server_random = generate_server_random(ec);
    if (ec)
    {
        co_return res;
    }

    LOG_CTX_TRACE(ctx,
                  "{} generated ephemeral key {}",
                  log_event::kHandshake,
                  reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32)));

    auto x25519_shared =
        reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), reality_ctx.x25519_peer_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        co_return res;
    }
    if (reality_ctx.key_share_group == reality::tls_consts::group::kX25519MLKEM768)
    {
        std::vector<std::uint8_t> mlkem768_shared;
        auto ciphertext = reality::crypto_util::mlkem768_encapsulate(reality_ctx.mlkem768_peer_pub, mlkem768_shared, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx, "{} mlkem768 encapsulate failed {}", log_event::kHandshake, ec.message());
            co_return res;
        }
        reality_ctx.server_shared_secret = std::move(mlkem768_shared);
        reality_ctx.server_shared_secret.insert(reality_ctx.server_shared_secret.end(), x25519_shared.begin(), x25519_shared.end());
        reality_ctx.server_key_share_data = std::move(ciphertext);
        reality_ctx.server_key_share_data.insert(reality_ctx.server_key_share_data.end(), public_key, public_key + 32);
    }
    else
    {
        reality_ctx.server_shared_secret = std::move(x25519_shared);
        reality_ctx.server_key_share_data.assign(public_key, public_key + 32);
    }

    if (reality_ctx.auth_key.empty() || reality_cert_public_key_.size() != 32 || reality_cert_template_.empty())
    {
        LOG_CTX_ERROR(ctx, "{} REALITY certificate identity unavailable", log_event::kHandshake);
        ec = boost::asio::error::fault;
        co_return res;
    }

    auto cert_der = build_reality_bound_certificate(reality_cert_template_, reality_ctx.auth_key, reality_cert_public_key_, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} build REALITY certificate failed {}", log_event::kHandshake, ec.message());
        co_return res;
    }
    const auto site_material_snapshot = get_cached_site_material_snapshot(site_material_manager_, cfg_);
    const auto cert_chain = build_reality_certificate_chain(cert_der, site_material_snapshot);
    reality_ctx.cert_msg = reality::construct_certificate(cert_chain);
    const auto cipher_suite = select_reality_cipher_suite(reality_ctx.client_hello, site_material_snapshot);
    if (!cipher_suite.has_value())
    {
        LOG_CTX_ERROR(ctx, "{} no mutual tls13 cipher suite", log_event::kHandshake);
        ec = boost::asio::error::no_protocol_option;
        co_return res;
    }
    const std::string selected_alpn = select_reality_alpn(reality_ctx.client_hello, site_material_snapshot);
    const auto server_hello_extension_order = select_server_hello_extension_order(site_material_snapshot);
    const auto encrypted_extension_order = select_encrypted_extensions_order(site_material_snapshot);
    const bool include_ee_padding = should_include_encrypted_extensions_padding(site_material_snapshot);
    const auto encrypted_extensions_padding_len = select_encrypted_extensions_padding_len(site_material_snapshot);
    const bool send_change_cipher_spec = should_send_change_cipher_spec(site_material_snapshot);
    const auto encrypted_handshake_record_sizes = select_encrypted_handshake_record_sizes(site_material_snapshot);
    const auto cert_chain_size = select_reality_certificate_chain_size(site_material_snapshot);
    LOG_CTX_INFO(ctx,
                 "{} success_path_material cache={} certs={} group=0x{:04x} {} key_share_len={} cipher=0x{:04x} alpn='{}' sh_exts={} ee_exts={} "
                 "ee_padding={} ee_padding_len={} ccs={} hs_records={}",
                 log_event::kHandshake,
                 site_material_snapshot.has_value(),
                 cert_chain_size,
                 reality_ctx.key_share_group,
                 reality::named_group_name(reality_ctx.key_share_group),
                 reality_ctx.server_key_share_data.size(),
                 *cipher_suite,
                 selected_alpn,
                 server_hello_extension_order.size(),
                 encrypted_extension_order.size(),
                 include_ee_padding,
                 encrypted_extensions_padding_len.value_or(0),
                 send_change_cipher_spec,
                 encrypted_handshake_record_sizes.size());

    auto crypto = build_handshake_crypto(reality_ctx,
                                         *cipher_suite,
                                         selected_alpn,
                                         server_hello_extension_order,
                                         encrypted_extension_order,
                                         include_ee_padding,
                                         encrypted_extensions_padding_len,
                                         std::vector<std::uint8_t>(reality_cert_private_key_.begin(), reality_cert_private_key_.end()),
                                         ec);
    if (ec)
    {
        co_return res;
    }
    const auto out_sh = compose_server_hello_flight(
        crypto.sh_msg, crypto.flight2_plain, send_change_cipher_spec, encrypted_handshake_record_sizes, crypto.cipher, crypto.s_hs_keys, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} compose server hello flight failed {}", log_event::kHandshake, ec.message());
        co_return res;
    }
    LOG_CTX_DEBUG(ctx, "{} sending server hello flight size {}", log_event::kHandshake, out_sh.size());
    co_await timeout_io::wait_write_with_timeout(*reality_ctx.socket, boost::asio::buffer(out_sh), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} write server hello failed {}", log_event::kHandshake, ec.message());
        co_return res;
    }

    co_return server_handshake_res{.hs_keys = crypto.hs_keys,
                                   .s_hs_keys = crypto.s_hs_keys,
                                   .c_hs_keys = crypto.c_hs_keys,
                                   .cipher = crypto.cipher,
                                   .negotiated_md = crypto.md,
                                   .handshake_hash = {}};
}

boost::asio::awaitable<void> remote_server::verify_client_finished(reality_context& reality_ctx,
                                                                   const server_handshake_res& response,
                                                                   boost::system::error_code& ec) const
{
    const auto& ctx = reality_ctx.ctx;
    std::array<std::uint8_t, 5> header = {0};
    co_await read_tls_record_header_allow_ccs(reality_ctx.socket, header, ctx, cfg_.timeout.read, ec);
    if (ec)
    {
        co_return;
    }

    const auto body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    if (body_len > kMaxTlsCiphertextRecordLen)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished record too large {}", log_event::kHandshake, body_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return;
    }
    std::vector<std::uint8_t> body(body_len);
    co_await timeout_io::wait_read_with_timeout(*reality_ctx.socket, boost::asio::buffer(body), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return;
    }

    const auto record = compose_tls_record(header, body);
    std::uint8_t ctype = 0;
    auto plaintext =
        reality::tls_record_layer::decrypt_record(response.cipher, response.c_hs_keys.first, response.c_hs_keys.second, 0, record, ctype, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished decrypt failed {}", log_event::kHandshake, ec.message());
        co_return;
    }

    auto expected_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(
        response.hs_keys.client_handshake_traffic_secret, reality_ctx.transcript.finish(), response.negotiated_md, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished verify data failed {}", log_event::kHandshake, ec.message());
        co_return;
    }

    if (!verify_client_finished_plaintext(plaintext, ctype, expected_fin_verify, ctx))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    co_return;
}

}    // namespace mux
