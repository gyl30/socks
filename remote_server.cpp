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

namespace
{

constexpr std::size_t kTlsRecordHeaderSize = 5;
constexpr std::uint16_t kMaxTlsPlaintextRecordLen = static_cast<std::uint16_t>(reality::kMaxTlsPlaintextLen);
constexpr std::uint16_t kMaxTlsCiphertextRecordLen = static_cast<std::uint16_t>(reality::kMaxTlsPlaintextLen + 256);
constexpr std::uint32_t kMaxTlsCompatCcsRecords = 8;

boost::asio::awaitable<void> read_tls_record_header(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                    std::vector<std::uint8_t>& buf,
                                                    std::uint32_t timeout,
                                                    boost::system::error_code& ec)
{
    while (buf.size() < kTlsRecordHeaderSize)
    {
        std::vector<std::uint8_t> header_remaining(kTlsRecordHeaderSize - buf.size());
        auto read_size = co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(header_remaining), timeout, ec);
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
                                                  std::uint32_t timeout,
                                                  boost::system::error_code& ec)
{
    while (buf.size() < kTlsRecordHeaderSize + payload_len)
    {
        std::vector<std::uint8_t> extra(kTlsRecordHeaderSize + payload_len - buf.size());
        const auto read_size = co_await timeout_io::wait_read_with_timeout(*socket, boost::asio::buffer(extra), timeout, ec);
        if (ec)
        {
            co_return;
        }
        extra.resize(read_size);
        buf.insert(buf.end(), extra.begin(), extra.end());
    }
    co_return;
}

struct auth_inputs
{
    std::vector<std::uint8_t> auth_key;
    std::vector<std::uint8_t> nonce;
    std::vector<std::uint8_t> aad;
};

std::expected<auth_inputs, boost::system::error_code> build_auth_decrypt_inputs(const client_hello_info& info,
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
    const auto reality_label_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    auto pseudo_random_key_result = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256());
    if (!pseudo_random_key_result)
    {
        return std::unexpected(pseudo_random_key_result.error());
    }
    auto auth_key_result = reality::crypto_util::hkdf_expand(*pseudo_random_key_result, reality_label_info, 16, EVP_sha256());
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
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
    }

    out.aad.assign(buf.begin() + 5, buf.end());
    const std::uint32_t aad_sid_offset = info.sid_offset - 5;
    if (aad_sid_offset + constants::auth::kSessionIdLen > out.aad.size())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail aad size mismatch", log_event::kAuth);
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
    }
    std::fill_n(out.aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);
    return out;
}

bool verify_auth_payload_fields(const reality::auth_payload& auth,
                                const std::vector<std::uint8_t>& short_id_bytes,
                                const std::string& sni,
                                const connection_context& ctx)
{
    if (auth.version_x != 1 || auth.version_y != 0 || auth.version_z != 0)
    {
        auto& stats = statistics::instance();
        stats.inc_auth_failures();
        LOG_CTX_WARN(ctx, "{} auth fail version mismatch {}.{}.{}", log_event::kAuth, auth.version_x, auth.version_y, auth.version_z);
        return false;
    }

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
    std::ranges::copy(short_id_bytes, expected_short_id.begin());
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

std::expected<handshake_crypto_result, boost::system::error_code> build_handshake_crypto(const std::vector<std::uint8_t>& server_random,
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
        return std::unexpected(boost::asio::error::fault);
    }

    const auto cv = reality::construct_certificate_verify(sign_key.get(), trans.finish());
    if (cv.empty())
    {
        LOG_CTX_ERROR(ctx, "{} certificate verify construct failed", log_event::kHandshake);
        return std::unexpected(boost::asio::error::fault);
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
    auto flight2_result = reality::tls_record_layer::encrypt_record(
        out.cipher, out.s_hs_keys.first, out.s_hs_keys.second, 0, flight2_plain, reality::kContentTypeHandshake);
    if (!flight2_result)
    {
        const auto ec = flight2_result.error();
        LOG_CTX_ERROR(ctx, "{} auth fail flight2 encrypt failed {}", log_event::kAuth, ec.message());
        return std::unexpected(ec);
    }
    out.flight2_enc = std::move(*flight2_result);

    return out;
}

std::expected<reality::auth_payload, boost::system::error_code> decrypt_auth_payload(const client_hello_info& info,
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
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::bad_message));
    }

    auto payload = reality::parse_auth_payload(*pt);
    if (!payload)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::bad_message));
    }
    return *payload;
}

bool verify_replay_guard(replay_cache& replay_cache,
                         const std::vector<std::uint8_t>& session_id,
                         const std::string& sni,
                         const connection_context& ctx)
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

std::expected<std::vector<std::uint8_t>, boost::system::error_code> generate_server_random()
{
    std::vector<std::uint8_t> server_random(32, 0);
    if (RAND_bytes(server_random.data(), 32) != 1)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
    }
    return server_random;
}

std::uint16_t select_cipher_suite_from_fingerprint(const reality::server_fingerprint& fingerprint)
{
    return normalize_cipher_suite(fingerprint.cipher_suite != 0 ? fingerprint.cipher_suite : 0x1301);
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

remote_server::remote_server(io_context_pool& pool, const config& cfg)
    : cfg_(cfg), pool_(pool), io_context_(pool.get_io_context()), replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries))
{
    private_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.private_key);
    if (private_key_.size() != 32)
    {
        LOG_ERROR("private key length invalid {}", private_key_.size());
        return;
    }
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(short_id_bytes_));
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
    boost::asio::co_spawn(io_context_, [self = shared_from_this()] { return self->accept_loop(); }, group_.adapt(boost::asio::detached));
}

void remote_server::stop()
{
    boost::asio::co_spawn(
        io_context_,
        [this, self = shared_from_this()]() -> boost::asio::awaitable<void>
        {
            group_.emit(boost::asio::cancellation_type::all);
            boost::system::error_code ec;
            co_await group_.async_wait(::boost::asio::redirect_error(::boost::asio::use_awaitable, ec));
        },
        boost::asio::detached);
}

boost::asio::awaitable<void> remote_server::accept_loop()
{
    LOG_INFO("remote server listening for connections");
    auto self = shared_from_this();
    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor{io_context_};
    auto addr = boost::asio::ip::make_address(cfg_.inbound.host, ec);
    if (ec)
    {
        co_return;
    }
    auto ep = boost::asio::ip::tcp::endpoint(addr, cfg_.inbound.port);
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        co_return;
    }
    ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        co_return;
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        co_return;
    }
    ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        co_return;
    }
    boost::asio::steady_timer retry_timer(io_context_);
    while (true)
    {
        const auto s = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
        const auto [accept_ec] = co_await acceptor.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
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

        boost::system::error_code ec;
        ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
        (void)ec;
        const std::uint32_t conn_id = next_conn_id_++;
        boost::asio::co_spawn(io_context_, [this, self, s, conn_id]() { return handle(s, conn_id); }, group_.adapt(boost::asio::detached));
    }
    LOG_INFO("accept loop exited");
}

boost::asio::awaitable<void> remote_server::handle(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::uint32_t conn_id)
{
    auto ctx = build_connection_context(s, conn_id);
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());
    boost::system::error_code ec;
    std::vector<std::uint8_t> buf;
    // tls handshake
    // step 1 tls header
    co_await read_tls_record_header(s, buf, cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} read tls record header failed {}", log_event::kHandshake, ec.message());
        co_return;
    }
    if (buf[0] != 0x16)
    {
        LOG_CTX_ERROR(ctx, "{} unexpected tls record type {}", log_event::kHandshake, buf[0]);
        co_return;
    }
    const uint32_t len = static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    if (len > kMaxTlsPlaintextRecordLen)
    {
        LOG_CTX_ERROR(ctx, "{} client hello record too large {}", log_event::kHandshake, len);
        co_return;
    }
    // step 2 tls body
    co_await read_tls_record_body(s, buf, len, cfg_.timeout.read, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        co_return;
    }
    LOG_CTX_DEBUG(ctx, "{} received client hello record size {}", log_event::kHandshake, buf.size());

    auto client_info = ch_parser::parse(buf);
    if (client_info.malformed_sni)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed sni extension", log_event::kAuth);
        co_return;
    }
    if (client_info.malformed_key_share)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed key share extension", log_event::kAuth);
        co_return;
    }
    if (!client_info.is_tls13 || client_info.session_id.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail is tls13 {} sid len {}", log_event::kAuth, client_info.is_tls13, client_info.session_id.size());
        co_return;
    }
    if (client_info.random.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail random len {}", log_event::kAuth, client_info.random.size());
        co_return;
    }
    struct selected_key_share
    {
        std::uint16_t group = 0;
        std::vector<std::uint8_t> x25519_pub;
    } sel;
    if (client_info.has_x25519_share && client_info.x25519_pub.size() == 32)
    {
        sel.group = reality::tls_consts::group::kX25519;
        sel.x25519_pub = client_info.x25519_pub;
    }
    if (sel.x25519_pub.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail missing valid x25519 key share", log_event::kAuth);
        co_return;
    }
    auto auth = decrypt_auth_payload(client_info, buf, private_key_, sel.x25519_pub, ctx);
    if (!auth.has_value())
    {
        co_return;
    }
    if (!verify_auth_payload_fields(*auth, short_id_bytes_, client_info.sni, ctx))
    {
        co_return;
    }
    if (!verify_auth_timestamp(auth->timestamp, client_info.sni, ctx))
    {
        co_return;
    }

    if (!verify_replay_guard(replay_cache_, client_info.session_id, client_info.sni, ctx))
    {
        LOG_CTX_WARN(ctx, "{} auth failed sni {}", log_event::kAuth, client_info.sni);
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, client_info.sni);
    reality::transcript trans;
    if (buf.size() <= 5)
    {
        LOG_CTX_ERROR(ctx, "{} buffer too short", log_event::kHandshake);
        co_return;
    }
    trans.update(std::vector<std::uint8_t>(buf.begin() + 5, buf.end()));
    auto response = co_await perform_handshake_response(s, client_info, trans, ctx, ec);
    if (ec)
    {
        co_return;
    }
    co_await verify_client_finished(s, response, trans, ctx, ec);
    if (ec)
    {
        co_return;
    }
    response.handshake_hash = trans.finish();

    auto app_sec =
        reality::tls_key_schedule::derive_application_secrets(response.hs_keys.master_secret, response.handshake_hash, response.negotiated_md);
    if (!app_sec)
    {
        ec = app_sec.error();
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
    auto c_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec->first, key_len, iv_len, response.negotiated_md);
    if (!c_keys)
    {
        ec = c_keys.error();
        co_return;
    }

    auto s_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec->second, key_len, iv_len, response.negotiated_md);
    if (!s_keys)
    {
        ec = s_keys.error();
        co_return;
    }
    struct app_keys
    {
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> c_app_keys;
        std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> s_app_keys;
    } keys;
    keys.c_app_keys = std::move(*c_keys);
    keys.s_app_keys = std::move(*s_keys);
    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);
    //
    reality_engine engine(keys.c_app_keys.first, keys.c_app_keys.second, keys.s_app_keys.first, keys.s_app_keys.second, response.cipher);
    auto tunnel = std::make_shared<mux_tunnel_impl>(std::move(*s), io_context_, std::move(engine), cfg_, group_, conn_id, ctx.trace_id());

    std::weak_ptr<remote_server> weak_self = weak_from_this();
    std::weak_ptr<mux_tunnel_impl> weak_tunnel = tunnel;
    tunnel->set_new_stream_cb([weak_self, weak_tunnel, ctx](mux_frame frame) -> boost::asio::awaitable<void>
                              {
                                  const auto self = weak_self.lock();
                                  const auto tunnel_ref = weak_tunnel.lock();
                                  if (self == nullptr || tunnel_ref == nullptr)
                                  {
                                      co_return;
                                  }
                                  co_await self->process_stream_request(tunnel_ref, ctx, std::move(frame));
                              });
    tunnel->run();

    boost::asio::steady_timer hold_timer(io_context_);
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
    boost::system::error_code ec;
    co_await connection->send_async(std::move(frame), ec);
    if (ec)
    {
    }
}

static boost::asio::awaitable<void> handle_tcp_connect_stream(const std::shared_ptr<mux_tunnel_impl>& tunnel,
                                                              const connection_context& stream_ctx,
                                                              mux_frame frame,
                                                              const syn_payload& syn,
                                                              const config& cfg,
                                                              boost::asio::io_context& io_context)
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
    boost::asio::co_spawn(io_context, [sess, syn]() mutable -> boost::asio::awaitable<void> { co_await sess->start(syn); }, boost::asio::detached);
    co_return;
}

static boost::asio::awaitable<void> handle_udp_associate_stream(const std::shared_ptr<mux_tunnel_impl>& tunnel,
                                                                const connection_context& stream_ctx,
                                                                mux_frame frame,
                                                                const config& cfg,
                                                                boost::asio::io_context& io_context)
{
    LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, frame.h.stream_id);
    const auto connection = tunnel->connection();
    const auto sess = std::make_shared<remote_udp_session>(connection, frame.h.stream_id, io_context, stream_ctx, cfg);
    sess->set_manager(tunnel);
    boost::asio::co_spawn(io_context, [sess]() mutable -> boost::asio::awaitable<void> { co_await sess->start(); }, boost::asio::detached);
    co_return;
}

boost::asio::awaitable<void> remote_server::process_stream_request(std::shared_ptr<mux_tunnel_impl> tunnel,
                                                                   const connection_context& ctx,
                                                                   mux_frame frame) const
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
    if (syn.socks_cmd == socks::kCmdConnect && syn.port == 0)
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} invalid target {} {}", log_event::kMux, frame.h.stream_id, syn.addr, syn.port);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        co_return co_await handle_tcp_connect_stream(tunnel, stream_ctx, std::move(frame), syn, cfg_, pool_.get_io_context());
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        co_return co_await handle_udp_associate_stream(tunnel, stream_ctx, std::move(frame), cfg_, pool_.get_io_context());
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, frame.h.stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, std::move(frame));
}

static std::vector<std::uint8_t> compose_server_hello_flight(const std::vector<std::uint8_t>& sh_msg, const std::vector<std::uint8_t>& flight2_enc)
{
    std::vector<std::uint8_t> out_sh;
    const auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh_msg.size()));
    out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
    out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
    out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());
    return out_sh;
}

boost::asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                                                      const client_hello_info& info,
                                                                                                      reality::transcript& trans,
                                                                                                      const connection_context& ctx,
                                                                                                      boost::system::error_code& ec)
{
    server_handshake_res res;
    const auto key_pair = key_rotator_.get_current_key();
    if (key_pair == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} key rotation unavailable", log_event::kHandshake);
        ec = boost::asio::error::fault;
        co_return res;
    }
    const std::uint8_t* public_key = key_pair->public_key;
    const std::uint8_t* private_key = key_pair->private_key;

    auto server_random_result = generate_server_random();
    if (!server_random_result)
    {
        ec = server_random_result.error();
        co_return res;
    }
    const auto& server_random = *server_random_result;

    LOG_CTX_TRACE(ctx,
                  "{} generated ephemeral key {}",
                  log_event::kHandshake,
                  reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32)));

    //

    auto sh_shared_result = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), info.x25519_pub);
    if (!sh_shared_result)
    {
        ec = sh_shared_result.error();
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        co_return res;
    }
    struct key_share_result
    {
        std::vector<std::uint8_t> sh_shared;
        std::vector<std::uint8_t> key_share_data;
        std::uint16_t key_share_group;
    } ks;
    ks.sh_shared = std::move(*sh_shared_result);
    ks.key_share_data.assign(public_key, public_key + 32);
    ks.key_share_group = reality::tls_consts::group::kX25519;
    struct certificate_target
    {
        std::string cert_sni;
        std::string fetch_host;
        std::uint16_t fetch_port = 443;
    } target;
    target.cert_sni = info.sni;
    target.fetch_host = "www.apple.com";
    target.fetch_port = 443;

    const auto fb = find_fallback_target_by_sni(info.sni);
    if (!fb.first.empty())
    {
        target.fetch_host = fb.first;
        target.fetch_port = static_cast<uint16_t>(atoi(fb.second.c_str()));
    }
    struct certificate_material
    {
        std::vector<std::uint8_t> cert_msg;
        reality::server_fingerprint fingerprint;
    } cert;
    const auto cached_entry = cert_manager_.get_certificate(target.cert_sni);
    if (cached_entry.has_value())
    {
        cert.cert_msg = cached_entry->cert_msg;
        cert.fingerprint = cached_entry->fingerprint;
    }
    else
    {
        LOG_CTX_INFO(ctx, "{} certificate miss fetching {} {}", log_event::kCert, target.fetch_host, target.fetch_port);
        const auto fetch_res =
            co_await reality::cert_fetcher::fetch(io_context_, target.fetch_host, target.fetch_port, target.cert_sni, ctx.trace_id());
        if (!fetch_res.has_value())
        {
            LOG_CTX_ERROR(ctx, "{} fetch certificate failed", log_event::kCert);
            ec = boost::asio::error::connection_refused;
            co_return res;
        }
        cert.cert_msg = fetch_res->cert_msg;
        cert.fingerprint = fetch_res->fingerprint;
        cert_manager_.set_certificate(target.cert_sni, cert.cert_msg, cert.fingerprint, ctx.trace_id());
    }

    const std::uint16_t cipher_suite = select_cipher_suite_from_fingerprint(cert.fingerprint);
    auto crypto_result = build_handshake_crypto(server_random,
                                                info.session_id,
                                                cipher_suite,
                                                ks.key_share_group,
                                                ks.key_share_data,
                                                ks.sh_shared,
                                                cert.cert_msg,
                                                cert.fingerprint.alpn,
                                                private_key_,
                                                trans,
                                                ctx);
    if (!crypto_result)
    {
        ec = crypto_result.error();
        co_return res;
    }
    const auto& crypto = *crypto_result;
    auto sh_msg = crypto.sh_msg;
    auto flight2_enc = crypto.flight2_enc;
    LOG_CTX_INFO(ctx, "generated sh msg size {}", sh_msg.size());
    const auto out_sh = compose_server_hello_flight(sh_msg, flight2_enc);
    LOG_CTX_INFO(ctx, "total out sh size {}", out_sh.size());
    LOG_CTX_DEBUG(ctx, "{} sending server hello flight size {}", log_event::kHandshake, out_sh.size());
    co_await timeout_io::wait_write_with_timeout(*s, boost::asio::buffer(out_sh), cfg_.timeout.write, ec);
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
boost::asio::awaitable<void> remote_server::verify_client_finished(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                   const server_handshake_res& response,
                                                                   const reality::transcript& trans,
                                                                   const connection_context& ctx,
                                                                   boost::system::error_code& ec) const
{
    std::array<std::uint8_t, 5> header = {0};
    co_await read_tls_record_header_allow_ccs(s, header, ctx, cfg_.timeout.read, ec);
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
    co_await timeout_io::wait_read_with_timeout(*s, boost::asio::buffer(body), cfg_.timeout.read, ec);
    if (ec)
    {
        co_return;
    }

    const auto record = compose_tls_record(header, body);
    std::uint8_t ctype = 0;
    auto plaintext_result =
        reality::tls_record_layer::decrypt_record(response.cipher, response.c_hs_keys.first, response.c_hs_keys.second, 0, record, ctype);
    if (!plaintext_result)
    {
        const auto ec = plaintext_result.error();
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished decrypt failed {}", log_event::kHandshake, ec.message());
        co_return;
    }

    auto expected_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(
        response.hs_keys.client_handshake_traffic_secret, trans.finish(), response.negotiated_md);
    if (!expected_fin_verify)
    {
        const auto ec = expected_fin_verify.error();
        statistics::instance().inc_client_finished_failures();
        LOG_CTX_ERROR(ctx, "{} client finished verify data failed {}", log_event::kHandshake, ec.message());
        co_return;
    }

    if (!verify_client_finished_plaintext(*plaintext_result, ctype, *expected_fin_verify, ctx))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    co_return;
}

static std::optional<std::pair<std::string, std::string>> find_exact_sni_fallback(const std::vector<config::fallback_entry>& fallbacks,
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

static std::optional<std::pair<std::string, std::string>> find_wildcard_fallback(const std::vector<config::fallback_entry>& fallbacks)
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

std::pair<std::string, std::string> remote_server::find_fallback_target_by_sni(const std::string& sni) const
{
    if (const auto exact = find_exact_sni_fallback(cfg_.fallbacks, sni); exact.has_value())
    {
        return *exact;
    }
    if (const auto wildcard = find_wildcard_fallback(cfg_.fallbacks); wildcard.has_value())
    {
        return *wildcard;
    }
    return {};
}
}    // namespace mux
