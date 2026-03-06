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
    client_hello_info client_hello;
    std::uint16_t x25519_group = 0;
    std::vector<std::uint8_t> x25519_peer_pub;
    reality::transcript transcript;
    std::vector<std::uint8_t> server_random;
    std::vector<std::uint8_t> server_x25519_pub;
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

    if (reality_ctx.client_hello.sid_offset < 5)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail invalid sid offset {}", log_event::kAuth, reality_ctx.client_hello.sid_offset);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    out.aad.assign(reality_ctx.client_hello_record.begin() + 5, reality_ctx.client_hello_record.end());
    const std::uint32_t aad_sid_offset = reality_ctx.client_hello.sid_offset - 5;
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

handshake_crypto_result build_handshake_crypto(reality_context& reality_ctx,
                                               const std::uint16_t cipher_suite,
                                               const std::vector<std::uint8_t>& sign_key_bytes,
                                               boost::system::error_code& ec)
{
    ec.clear();
    handshake_crypto_result out;
    out.sh_msg = reality::construct_server_hello(reality_ctx.server_random,
                                                 reality_ctx.client_hello.session_id,
                                                 cipher_suite,
                                                 reality_ctx.x25519_group,
                                                 reality_ctx.server_x25519_pub);
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

    const auto enc_ext = reality::construct_encrypted_extensions("");
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

    const auto s_fin =
        reality::tls_key_schedule::compute_finished_verify_data(out.hs_keys.server_handshake_traffic_secret, reality_ctx.transcript.finish(), out.md, ec);
    if (ec)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} compute server finished failed {}", log_event::kHandshake, ec.message());
        return {};
    }
    reality_ctx.transcript.update(s_fin);

    std::vector<std::uint8_t> flight2_plain;
    flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    flight2_plain.insert(flight2_plain.end(), reality_ctx.cert_msg.begin(), reality_ctx.cert_msg.end());
    flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
    flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

    out.cipher = cipher_from_cipher_suite(cipher_suite);
    out.flight2_enc =
        reality::tls_record_layer::encrypt_record(out.cipher, out.s_hs_keys.first, out.s_hs_keys.second, 0, flight2_plain, reality::kContentTypeHandshake, ec);
    if (ec)
    {
        LOG_CTX_ERROR(reality_ctx.ctx, "{} auth fail flight2 encrypt failed {}", log_event::kAuth, ec.message());
        return {};
    }

    return out;
}

reality::auth_payload decrypt_auth_payload(reality_context& reality_ctx,
                                           const std::vector<std::uint8_t>& private_key,
                                           boost::system::error_code& ec)
{
    ec.clear();
    const auto inputs = build_auth_decrypt_inputs(reality_ctx, private_key, ec);
    if (ec)
    {
        return {};
    }
    reality_ctx.auth_key = inputs.auth_key;

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    auto pt = reality::crypto_util::aead_decrypt(
        auth_cipher, inputs.auth_key, inputs.nonce, reality_ctx.client_hello.session_id, inputs.aad, ec);
    if (ec || pt.size() != 16)
    {
        LOG_CTX_ERROR(
            reality_ctx.ctx, "{} auth fail decrypt failed tag mismatch pt size {}", log_event::kAuth, pt.size());
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
        LOG_CTX_WARN(reality_ctx.ctx, "{} replay attack detected", log_event::kAuth);
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

std::uint16_t select_reality_cipher_suite()
{
    return normalize_cipher_suite(reality::tls_consts::cipher::kTlsAes128GcmSha256);
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
    reality_context reality_ctx;
    reality_ctx.socket = std::move(s);
    reality_ctx.ctx = build_connection_context(reality_ctx.socket, conn_id);
    auto& ctx = reality_ctx.ctx;
    auto& buf = reality_ctx.client_hello_record;
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());
    boost::system::error_code ec;
    // tls handshake
    // step 1 tls header
    co_await read_tls_record_header(reality_ctx.socket, buf, cfg_.timeout.read, ec);
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
    co_await read_tls_record_body(reality_ctx.socket, buf, len, cfg_.timeout.read, ec);
    if (ec)
    {
        statistics::instance().inc_client_finished_failures();
        co_return;
    }
    LOG_CTX_DEBUG(ctx, "{} received client hello record size {}", log_event::kHandshake, buf.size());

    reality_ctx.client_hello = ch_parser::parse(buf);
    if (reality_ctx.client_hello.malformed_sni)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed sni extension", log_event::kAuth);
        co_return;
    }
    if (reality_ctx.client_hello.malformed_key_share)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail malformed key share extension", log_event::kAuth);
        co_return;
    }
    if (!reality_ctx.client_hello.is_tls13 || reality_ctx.client_hello.session_id.size() != 32)
    {
        LOG_CTX_ERROR(
            ctx, "{} auth fail is tls13 {} sid len {}", log_event::kAuth, reality_ctx.client_hello.is_tls13, reality_ctx.client_hello.session_id.size());
        co_return;
    }
    if (reality_ctx.client_hello.random.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail random len {}", log_event::kAuth, reality_ctx.client_hello.random.size());
        co_return;
    }
    if (reality_ctx.client_hello.has_x25519_share && reality_ctx.client_hello.x25519_pub.size() == 32)
    {
        reality_ctx.x25519_group = reality::tls_consts::group::kX25519;
        reality_ctx.x25519_peer_pub = reality_ctx.client_hello.x25519_pub;
    }
    if (reality_ctx.x25519_peer_pub.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail missing valid x25519 key share", log_event::kAuth);
        co_return;
    }
    auto auth = decrypt_auth_payload(reality_ctx, private_key_, ec);
    if (ec)
    {
        co_return;
    }
    if (!verify_auth_payload_fields(auth, short_id_bytes_, reality_ctx))
    {
        co_return;
    }
    if (!verify_auth_timestamp(auth.timestamp, reality_ctx))
    {
        co_return;
    }

    if (!verify_replay_guard(replay_cache_, reality_ctx))
    {
        LOG_CTX_WARN(ctx, "{} auth failed sni {}", log_event::kAuth, reality_ctx.client_hello.sni);
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, reality_ctx.client_hello.sni);
    if (buf.size() <= 5)
    {
        LOG_CTX_ERROR(ctx, "{} buffer too short", log_event::kHandshake);
        co_return;
    }
    reality_ctx.transcript.update(std::vector<std::uint8_t>(buf.begin() + 5, buf.end()));
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
    response.handshake_hash = reality_ctx.transcript.finish();

    auto app_sec = reality::tls_key_schedule::derive_application_secrets(
        response.hs_keys.master_secret, response.handshake_hash, response.negotiated_md, ec);
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
    auto tunnel =
        std::make_shared<mux_tunnel_impl>(std::move(*reality_ctx.socket), io_context_, std::move(engine), cfg_, group_, conn_id, ctx.trace_id());

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

boost::asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(reality_context& reality_ctx,
                                                                                                      boost::system::error_code& ec)
{
    server_handshake_res res;
    auto& ctx = reality_ctx.ctx;
    const auto key_pair = key_rotator_.get_current_key();
    if (key_pair == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} key rotation unavailable", log_event::kHandshake);
        ec = boost::asio::error::fault;
        co_return res;
    }
    const std::uint8_t* public_key = key_pair->public_key;
    const std::uint8_t* private_key = key_pair->private_key;

    reality_ctx.server_random = generate_server_random(ec);
    if (ec)
    {
        co_return res;
    }

    LOG_CTX_TRACE(ctx,
                  "{} generated ephemeral key {}",
                  log_event::kHandshake,
                  reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32)));

    reality_ctx.server_shared_secret =
        reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), reality_ctx.x25519_peer_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        co_return res;
    }
    reality_ctx.server_x25519_pub.assign(public_key, public_key + 32);

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
    reality_ctx.cert_msg = reality::construct_certificate(cert_der);

    const std::uint16_t cipher_suite = select_reality_cipher_suite();
    auto crypto = build_handshake_crypto(
        reality_ctx, cipher_suite, std::vector<std::uint8_t>(reality_cert_private_key_.begin(), reality_cert_private_key_.end()), ec);
    if (ec)
    {
        co_return res;
    }
    LOG_CTX_INFO(ctx, "generated sh msg size {}", crypto.sh_msg.size());
    const auto out_sh = compose_server_hello_flight(crypto.sh_msg, crypto.flight2_enc);
    LOG_CTX_INFO(ctx, "total out sh size {}", out_sh.size());
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
    auto plaintext = reality::tls_record_layer::decrypt_record(
        response.cipher, response.c_hs_keys.first, response.c_hs_keys.second, 0, record, ctype, ec);
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
