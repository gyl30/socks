#include <span>
#include <array>
#include <cctype>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstring>
#include <utility>
#include <optional>
#include <algorithm>

extern "C"
{
#include <openssl/evp.h>
}
#include <boost/asio.hpp>
extern "C"
{
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}
#include <boost/asio/awaitable.hpp>

#include "log.h"
#include "config.h"
#include "tls/core.h"
#include "constants.h"
#include "net_utils.h"
#include "replay_cache.h"
#include "reality/types.h"
#include "site_material.h"
#include "tls/ch_parser.h"
#include "tls/transcript.h"
#include "tls/crypto_util.h"
#include "tls/server_name.h"
#include "tls/cipher_suite.h"
#include "tls/key_schedule.h"
#include "tls/record_layer.h"
#include "tls/handshake_builder.h"
#include "tls/handshake_message.h"
#include "tls/record_validation.h"
#include "reality/handshake/auth.h"
#include "reality/handshake/server_handshaker.h"
namespace reality
{

namespace
{

struct server_log_context
{
    uint32_t conn_id = 0;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string sni;
};

const char* server_log_sni(const server_log_context& log_context)
{
    if (!log_context.sni.empty())
    {
        return log_context.sni.c_str();
    }
    return "unknown";
}

server_log_context make_server_log_context(const server_handshake_context& handshake_ctx)
{
    return server_log_context{
        .conn_id = handshake_ctx.conn_id,
        .local_addr = handshake_ctx.local_addr,
        .local_port = handshake_ctx.local_port,
        .remote_addr = handshake_ctx.remote_addr,
        .remote_port = handshake_ctx.remote_port,
        .sni = handshake_ctx.sni,
    };
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

bool verify_client_hello_sni(const tls::client_hello_info& client_hello, const mux::config& cfg)
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

[[nodiscard]] bool is_invalid_sni(const std::string& sni) { return !tls::valid_sni_hostname(sni); }

struct server_handshake_state
{
    server_log_context log_context;
    std::vector<uint8_t> client_hello_record;
    std::vector<uint8_t> client_hello_handshake;
    tls::client_hello_info client_hello;
    uint16_t key_share_group = 0;
    std::vector<uint8_t> mlkem768_peer_pub;
    std::vector<uint8_t> x25519_peer_pub;
    tls::transcript transcript;
    std::vector<uint8_t> server_random;
    std::vector<uint8_t> server_key_share_data;
    std::vector<uint8_t> server_shared_secret;
    std::vector<uint8_t> auth_key;
    std::vector<uint8_t> cert_msg;
};

server_accept_result make_decision_result(const accept_mode mode, std::string reason, const server_handshake_state& state)
{
    server_accept_result result;
    result.mode = mode;
    result.decision_reason = std::move(reason);
    if (mode == accept_mode::kFallbackToTarget)
    {
        result.decision_context.client_hello_record = state.client_hello_record;
    }
    return result;
}

boost::asio::awaitable<void> read_tls_record_header(
    boost::asio::ip::tcp::socket& socket, std::vector<uint8_t>& buf, uint64_t start_ms, uint32_t timeout, boost::system::error_code& ec)
{
    while (buf.size() < tls::kTlsRecordHeaderSize)
    {
        std::vector<uint8_t> header_remaining(tls::kTlsRecordHeaderSize - buf.size());
        const auto read_timeout = mux::net::remaining_timeout_seconds(start_ms, timeout, ec);
        if (ec)
        {
            co_return;
        }
        auto read_size = co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(header_remaining), read_timeout, ec);
        if (ec)
        {
            co_return;
        }
        header_remaining.resize(read_size);
        buf.insert(buf.end(), header_remaining.begin(), header_remaining.end());
    }
    co_return;
}

boost::asio::awaitable<void> read_tls_record_body(boost::asio::ip::tcp::socket& socket,
                                                  std::vector<uint8_t>& buf,
                                                  uint32_t payload_len,
                                                  uint64_t start_ms,
                                                  uint32_t timeout,
                                                  boost::system::error_code& ec)
{
    while (buf.size() < tls::kTlsRecordHeaderSize + payload_len)
    {
        std::vector<uint8_t> extra(tls::kTlsRecordHeaderSize + payload_len - buf.size());
        const auto read_timeout = mux::net::remaining_timeout_seconds(start_ms, timeout, ec);
        if (ec)
        {
            co_return;
        }
        const auto read_size = co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(extra), read_timeout, ec);
        if (ec)
        {
            co_return;
        }
        extra.resize(read_size);
        buf.insert(buf.end(), extra.begin(), extra.end());
    }
    co_return;
}

const char* validate_client_hello_record_header(
    const std::vector<uint8_t>& record_buf, const server_log_context& log_context, boost::system::error_code& ec)
{
    if (record_buf[1] != 0x03 || record_buf[2] != 0x03)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid tls record version {} {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  record_buf[1],
                  record_buf[2]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "invalid_tls_record_version";
    }

    return nullptr;
}

const char* validate_client_hello_ccs_record(const std::vector<uint8_t>& record_buf,
                                             uint16_t record_len,
                                             uint32_t& ccs_count,
                                             const server_log_context& log_context,
                                             boost::system::error_code& ec)
{
    if (ccs_count >= constants::tls_limits::kMaxCompatCcsRecords)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} too many ccs records {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  ccs_count);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "tls13_ccs_too_many";
    }

    ccs_count++;
    if (record_len != 1)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid ccs length {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  record_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "tls13_ccs_len_invalid";
    }

    const std::array<uint8_t, 5> header = {record_buf[0], record_buf[1], record_buf[2], record_buf[3], record_buf[4]};
    const auto ccs_body = record_buf[tls::kTlsRecordHeaderSize];
    if (!tls::is_valid_tls13_compat_ccs(header, ccs_body))
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid ccs body {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  ccs_body);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "tls13_ccs_body_invalid";
    }

    return nullptr;
}

const char* validate_client_hello_handshake_record(
    const std::vector<uint8_t>& record_buf,
    uint16_t record_len,
    std::size_t record_count,
    std::size_t max_records,
    const server_log_context& log_context,
    boost::system::error_code& ec)
{
    if (record_buf[0] != 0x16)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} unexpected tls record type {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  record_buf[0]);
        ec = boost::asio::error::invalid_argument;
        return "unexpected_tls_record_type";
    }
    if (record_len > tls::kMaxTlsPlaintextLen)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello record too large {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  record_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return "client_hello_record_too_large";
    }
    if (record_len == 0)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello record empty",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "client_hello_record_empty";
    }
    if (record_count >= max_records)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello record too many {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  record_count);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "client_hello_record_too_many";
    }

    return nullptr;
}

const char* append_client_hello_record(const std::vector<uint8_t>& record_buf,
                                       std::vector<uint8_t>& wire_buf,
                                       std::vector<uint8_t>& handshake_buf,
                                       std::size_t max_wire_len,
                                       std::size_t max_handshake_len,
                                       bool& handshake_complete,
                                       const server_log_context& log_context,
                                       boost::system::error_code& ec)
{
    handshake_complete = false;
    if (record_buf.size() > max_wire_len - wire_buf.size())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello wire too large {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  wire_buf.size() + record_buf.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return "client_hello_wire_too_large";
    }

    wire_buf.insert(wire_buf.end(), record_buf.begin(), record_buf.end());
    handshake_buf.insert(handshake_buf.end(), record_buf.begin() + static_cast<std::ptrdiff_t>(tls::kTlsRecordHeaderSize), record_buf.end());
    if (handshake_buf.size() < 4)
    {
        return nullptr;
    }
    if (handshake_buf[0] != 0x01)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} unexpected client hello type {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  handshake_buf[0]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "unexpected_client_hello_type";
    }

    const auto hello_msg_len =
        (static_cast<uint32_t>(handshake_buf[1]) << 16) | (static_cast<uint32_t>(handshake_buf[2]) << 8) | static_cast<uint32_t>(handshake_buf[3]);
    const auto total_len = static_cast<std::size_t>(hello_msg_len) + 4;
    if (total_len > max_handshake_len)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello message too large {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  total_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return "client_hello_message_too_large";
    }
    if (handshake_buf.size() < total_len)
    {
        return nullptr;
    }
    if (handshake_buf.size() != total_len)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello message has trailing data {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  handshake_buf.size() - total_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return "client_hello_message_has_trailing_data";
    }

    handshake_complete = true;
    return nullptr;
}

boost::asio::awaitable<const char*> read_client_hello_handshake(boost::asio::ip::tcp::socket& socket,
                                                                std::vector<uint8_t>& wire_buf,
                                                                std::vector<uint8_t>& handshake_buf,
                                                                uint32_t timeout,
                                                                std::size_t max_handshake_len,
                                                                const server_log_context& log_context,
                                                                boost::system::error_code& ec)
{
    ec.clear();
    wire_buf.clear();
    handshake_buf.clear();
    const auto handshake_start_ms = mux::net::now_ms();
    std::size_t record_count = 0;
    const auto max_records =
        std::max<std::size_t>(1, (max_handshake_len + tls::kMaxTlsPlaintextLen - 1) / static_cast<std::size_t>(tls::kMaxTlsPlaintextLen));
    const auto max_wire_len = max_handshake_len + (max_records * tls::kTlsRecordHeaderSize);
    uint32_t ccs_count = 0;

    while (true)
    {
        std::vector<uint8_t> record_buf;
        co_await read_tls_record_header(socket, record_buf, handshake_start_ms, timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof && record_count == 0 && handshake_buf.empty())
            {
                LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} sni {} peer closed before tls record header",
                         mux::log_event::kConnClose,
                         log_context.conn_id,
                         log_context.local_addr,
                         log_context.local_port,
                         log_context.remote_addr,
                         log_context.remote_port,
                         server_log_sni(log_context));
                co_return "read_tls_record_header_failed";
            }
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} read tls record header failed {}",
                      mux::log_event::kHandshake,
                      log_context.conn_id,
                      log_context.local_addr,
                      log_context.local_port,
                      log_context.remote_addr,
                      log_context.remote_port,
                      server_log_sni(log_context),
                      ec.message());
            co_return "read_tls_record_header_failed";
        }
        if (const auto* error_reason = validate_client_hello_record_header(record_buf, log_context, ec); error_reason != nullptr)
        {
            co_return error_reason;
        }

        const auto record_len = static_cast<uint16_t>((record_buf[3] << 8) | record_buf[4]);
        if (record_buf[0] == 0x14)
        {
            co_await read_tls_record_body(socket, record_buf, record_len, handshake_start_ms, timeout, ec);
            if (ec)
            {
                LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} read tls record body failed {}",
                          mux::log_event::kHandshake,
                          log_context.conn_id,
                          log_context.local_addr,
                          log_context.local_port,
                          log_context.remote_addr,
                          log_context.remote_port,
                          server_log_sni(log_context),
                          ec.message());
                co_return "read_tls_record_body_failed";
            }
            if (const auto* error_reason = validate_client_hello_ccs_record(record_buf, record_len, ccs_count, log_context, ec);
                error_reason != nullptr)
            {
                co_return error_reason;
            }
            continue;
        }

        if (const auto* error_reason =
                validate_client_hello_handshake_record(record_buf, record_len, record_count, max_records, log_context, ec);
            error_reason != nullptr)
        {
            co_return error_reason;
        }
        record_count++;

        co_await read_tls_record_body(socket, record_buf, record_len, handshake_start_ms, timeout, ec);
        if (ec)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} read tls record body failed {}",
                      mux::log_event::kHandshake,
                      log_context.conn_id,
                      log_context.local_addr,
                      log_context.local_port,
                      log_context.remote_addr,
                      log_context.remote_port,
                      server_log_sni(log_context),
                      ec.message());
            co_return "read_tls_record_body_failed";
        }

        bool handshake_complete = false;
        if (const auto* error_reason =
                append_client_hello_record(record_buf, wire_buf, handshake_buf, max_wire_len, max_handshake_len, handshake_complete, log_context, ec);
            error_reason != nullptr)
        {
            co_return error_reason;
        }
        if (handshake_complete)
        {
            co_return nullptr;
        }
    }
}

struct auth_inputs
{
    std::vector<uint8_t> auth_key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> aad;
};

auth_inputs build_auth_decrypt_inputs(const server_handshake_state& state,
                                      const std::vector<uint8_t>& server_private_key,
                                      boost::system::error_code& ec)
{
    ec.clear();
    auto shared = tls::crypto_util::x25519_derive(server_private_key, state.x25519_peer_pub, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail x25519 derive failed {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        return {};
    }

    if (state.client_hello.random.size() != 32 || state.client_hello.session_id.size() != constants::auth::kSessionIdLen ||
        state.client_hello.sid_offset == 0 || state.client_hello.sid_offset + constants::auth::kSessionIdLen > state.client_hello_handshake.size())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail invalid client hello fields",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const auto salt = std::vector<uint8_t>(state.client_hello.random.begin(), state.client_hello.random.begin() + 20);
    const auto reality_label_info = tls::crypto_util::hex_to_bytes("5245414c495459");
    auto pseudo_random_key = tls::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }
    auto auth_key = tls::crypto_util::hkdf_expand(pseudo_random_key, reality_label_info, 16, EVP_sha256(), ec);
    if (ec)
    {
        return {};
    }

    auth_inputs out;
    out.auth_key = std::move(auth_key);
    out.nonce.assign(state.client_hello.random.begin() + 20, state.client_hello.random.end());
    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} sni {} auth key derived",
              mux::log_event::kAuth,
              state.log_context.conn_id,
              state.log_context.local_addr,
              state.log_context.local_port,
              state.log_context.remote_addr,
              state.log_context.remote_port,
              server_log_sni(state.log_context));

    if (state.client_hello.sid_offset == 0)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail invalid sid offset {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.sid_offset);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    out.aad = state.client_hello_handshake;
    const uint32_t aad_sid_offset = state.client_hello.sid_offset;
    if (aad_sid_offset + constants::auth::kSessionIdLen > out.aad.size())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail aad size mismatch",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::fill_n(out.aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);
    return out;
}

reality::auth_payload decrypt_auth_payload(server_handshake_state& state, const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    const auto inputs = build_auth_decrypt_inputs(state, private_key, ec);
    if (ec)
    {
        return {};
    }
    state.auth_key = inputs.auth_key;

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    auto plaintext = tls::crypto_util::aead_decrypt(auth_cipher, inputs.auth_key, inputs.nonce, state.client_hello.session_id, inputs.aad, ec);
    if (ec || plaintext.size() != 16)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail decrypt failed tag mismatch pt size {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  plaintext.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }

    auto payload = parse_auth_payload(plaintext);
    if (!payload)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    return *payload;
}

bool verify_auth_payload_fields(const auth_payload& auth, const std::vector<uint8_t>& short_id_bytes, const server_handshake_state& state)
{
    (void)state;
    if (auth.version_x != 1 || auth.version_y != 0 || auth.version_z != 0)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail version mismatch {}.{}.{}",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 auth.version_x,
                 auth.version_y,
                 auth.version_z);
        return false;
    }

    if (short_id_bytes.empty())
    {
        return true;
    }

    if (short_id_bytes.size() > kShortIdMaxLen)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail short id length invalid {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  short_id_bytes.size());
        return false;
    }

    std::array<uint8_t, kShortIdMaxLen> expected_short_id = {};
    std::ranges::copy(short_id_bytes, expected_short_id.begin());
    if (CRYPTO_memcmp(auth.short_id.data(), expected_short_id.data(), expected_short_id.size()) != 0)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail short id mismatch",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return false;
    }
    return true;
}

bool verify_auth_timestamp(uint32_t timestamp, const server_handshake_state& state)
{
    (void)state;
    const auto now_tp = std::chrono::system_clock::now();
    const auto ts_tp = std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
    const auto diff = (now_tp > ts_tp) ? (now_tp - ts_tp) : (ts_tp - now_tp);
    const auto diff_sec = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
    const auto max_diff = std::chrono::seconds(constants::auth::kMaxClockSkewSec);
    if (diff > max_diff)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} clock skew too large diff {}s",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 diff_sec);
        return false;
    }
    return true;
}

bool verify_replay_guard(mux::replay_cache& replay_cache, const server_handshake_state& state)
{
    if (!replay_cache.check_and_insert(state.client_hello.session_id))
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} replay attack detected",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return false;
    }
    return true;
}

struct handshake_crypto_result
{
    tls::handshake_keys hs_keys;
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> s_hs_keys;
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_hs_keys;
    const EVP_CIPHER* cipher = nullptr;
    const EVP_MD* md = nullptr;
    std::vector<uint8_t> sh_msg;
    std::vector<uint8_t> flight2_plain;
};

uint16_t normalize_cipher_suite(uint16_t cipher_suite)
{
    if (cipher_suite != 0x1301 && cipher_suite != 0x1302 && cipher_suite != 0x1303)
    {
        return 0x1301;
    }
    return cipher_suite;
}

handshake_crypto_result build_handshake_crypto(server_handshake_state& state,
                                               uint16_t cipher_suite,
                                               const std::string& alpn,
                                               std::span<const uint16_t> server_hello_extension_order,
                                               std::span<const uint16_t> encrypted_extension_order,
                                               bool include_encrypted_extensions_padding,
                                               const std::optional<uint16_t> encrypted_extensions_padding_len,
                                               const std::vector<uint8_t>& sign_key_bytes,
                                               boost::system::error_code& ec)
{
    ec.clear();
    handshake_crypto_result out;
    const auto suite = tls::select_tls13_suite(cipher_suite);
    if (!suite.has_value())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} unsupported tls13 cipher suite 0x{:04x}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  cipher_suite);
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    out.sh_msg = tls::construct_server_hello(state.server_random,
                                             state.client_hello.session_id,
                                             cipher_suite,
                                             state.key_share_group,
                                             state.server_key_share_data,
                                             server_hello_extension_order);
    state.transcript.update(out.sh_msg);

    out.md = suite->md;
    state.transcript.set_protocol_hash(out.md);
    out.hs_keys = tls::key_schedule::derive_handshake_keys(state.server_shared_secret, state.transcript.finish(), out.md, ec);
    if (ec)
    {
        return {};
    }

    const auto key_len = suite->key_len;
    out.c_hs_keys =
        tls::key_schedule::derive_traffic_keys(out.hs_keys.client_handshake_traffic_secret, ec, key_len, constants::crypto::kIvLen, out.md);
    if (ec)
    {
        return {};
    }
    out.s_hs_keys =
        tls::key_schedule::derive_traffic_keys(out.hs_keys.server_handshake_traffic_secret, ec, key_len, constants::crypto::kIvLen, out.md);
    if (ec)
    {
        return {};
    }

    const auto enc_ext =
        tls::construct_encrypted_extensions(alpn, encrypted_extension_order, include_encrypted_extensions_padding, encrypted_extensions_padding_len);
    state.transcript.update(enc_ext);
    state.transcript.update(state.cert_msg);

    const tls::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), 32));
    if (sign_key == nullptr)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} failed to load private key",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::fault;
        return {};
    }

    const auto cv = tls::construct_certificate_verify(sign_key.get(), state.transcript.finish());
    if (cv.empty())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} certificate verify construct failed",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::fault;
        return {};
    }
    state.transcript.update(cv);

    const auto s_fin_verify =
        tls::key_schedule::compute_finished_verify_data(out.hs_keys.server_handshake_traffic_secret, state.transcript.finish(), out.md, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} compute server finished failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        return {};
    }
    const auto s_fin = tls::construct_finished(s_fin_verify);
    if (s_fin.empty())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} server finished construct failed",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::fault;
        return {};
    }
    state.transcript.update(s_fin);

    out.cipher = suite->cipher;
    out.flight2_plain.insert(out.flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    out.flight2_plain.insert(out.flight2_plain.end(), state.cert_msg.begin(), state.cert_msg.end());
    out.flight2_plain.insert(out.flight2_plain.end(), cv.begin(), cv.end());
    out.flight2_plain.insert(out.flight2_plain.end(), s_fin.begin(), s_fin.end());

    return out;
}

std::vector<uint8_t> generate_server_random(boost::system::error_code& ec)
{
    ec.clear();
    std::vector<uint8_t> server_random(32, 0);
    if (RAND_bytes(server_random.data(), 32) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
        return {};
    }
    return server_random;
}

std::vector<uint8_t> build_reality_bound_certificate(const std::vector<uint8_t>& cert_template,
                                                     const std::vector<uint8_t>& auth_key,
                                                     const std::vector<uint8_t>& cert_public_key,
                                                     boost::system::error_code& ec)
{
    ec.clear();
    auto template_signature = tls::crypto_util::extract_certificate_signature(cert_template, ec);
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

    auto reality_signature = tls::crypto_util::hmac_sha512(auth_key, cert_public_key, ec);
    if (ec)
    {
        return {};
    }
    if (reality_signature.size() != template_signature.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<uint8_t> cert_der = cert_template;
    std::ranges::copy(reality_signature, cert_der.begin() + static_cast<std::ptrdiff_t>(signature_offset));
    return cert_der;
}

bool client_offers_cipher_suite(const tls::client_hello_info& hello, uint16_t cipher_suite)
{
    return std::ranges::find(hello.cipher_suites, cipher_suite) != hello.cipher_suites.end();
}

bool client_offers_alpn(const tls::client_hello_info& hello, const std::string& alpn)
{
    return std::ranges::find(hello.alpn_protocols, alpn) != hello.alpn_protocols.end();
}

bool client_offers_signature_scheme(const tls::client_hello_info& hello, uint16_t scheme)
{
    return std::ranges::find(hello.signature_algorithms, scheme) != hello.signature_algorithms.end();
}

std::vector<std::vector<uint8_t>> build_reality_certificate_chain(const std::vector<uint8_t>& leaf_cert_der, const site_material* site_material)
{
    std::vector<std::vector<uint8_t>> cert_chain;
    cert_chain.push_back(leaf_cert_der);
    if (site_material == nullptr)
    {
        return cert_chain;
    }

    const auto& cached_chain = site_material->certificate_chain;
    const auto cached_begin = (!cached_chain.empty() && cached_chain.front() == leaf_cert_der) ? cached_chain.begin() + 1 : cached_chain.begin();
    cert_chain.insert(cert_chain.end(), cached_begin, cached_chain.end());
    return cert_chain;
}

std::optional<uint16_t> select_reality_cipher_suite(const tls::client_hello_info& hello, const site_material* site_material)
{
    if (site_material != nullptr)
    {
        const auto cached_cipher = normalize_cipher_suite(site_material->fingerprint.cipher_suite);
        if (client_offers_cipher_suite(hello, cached_cipher))
        {
            return cached_cipher;
        }
    }

    for (const auto cipher_suite : constants::tls_limits::kFallbackCipherSuites)
    {
        if (client_offers_cipher_suite(hello, cipher_suite))
        {
            return cipher_suite;
        }
    }
    return std::nullopt;
}

std::string select_reality_alpn(const tls::client_hello_info& hello, const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return {};
    }
    const auto& cached_alpn = site_material->fingerprint.alpn;
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

template <typename Predicate>
std::vector<uint16_t> select_extension_order(const site_material* site_material,
                                             const std::vector<uint16_t> site_material::*extension_types_member,
                                             Predicate&& should_keep)
{
    if (site_material == nullptr)
    {
        return {};
    }
    std::vector<uint16_t> out;
    for (const auto ext_type : site_material->*extension_types_member)
    {
        if (should_keep(ext_type))
        {
            out.push_back(ext_type);
        }
    }
    return out;
}

std::vector<uint16_t> select_server_hello_extension_order(const site_material* site_material)
{
    return select_extension_order(
        site_material,
        &site_material::server_hello_extension_types,
        [](uint16_t ext_type) { return ext_type == tls::consts::ext::kSupportedVersions || ext_type == tls::consts::ext::kKeyShare; });
}

std::vector<uint16_t> select_encrypted_extensions_order(const site_material* site_material)
{
    return select_extension_order(
        site_material,
        &site_material::encrypted_extension_types,
        [](uint16_t ext_type) { return ext_type == tls::consts::ext::kAlpn || ext_type == tls::consts::ext::kPadding; });
}

bool should_include_encrypted_extensions_padding(const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return true;
    }
    return std::ranges::find(site_material->encrypted_extension_types, tls::consts::ext::kPadding) != site_material->encrypted_extension_types.end();
}

std::optional<uint16_t> select_encrypted_extensions_padding_len(const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return std::nullopt;
    }
    return site_material->encrypted_extensions_padding_len;
}

bool should_send_change_cipher_spec(const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return true;
    }
    return site_material->sends_change_cipher_spec;
}

std::vector<uint16_t> select_encrypted_handshake_record_sizes(const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return {};
    }
    return site_material->encrypted_handshake_record_sizes;
}

std::size_t select_reality_certificate_chain_size(const site_material* site_material)
{
    if (site_material == nullptr)
    {
        return 1;
    }
    return 1 + site_material->certificate_chain.size();
}

boost::asio::awaitable<void> consume_tls13_compat_ccs(boost::asio::ip::tcp::socket& socket,
                                                      const std::array<uint8_t, 5>& header,
                                                      uint32_t timeout_sec,
                                                      const server_log_context& log_context,
                                                      boost::system::error_code& ec)
{
    std::array<uint8_t, 1> ccs_body = {0};
    co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(ccs_body), timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (!tls::is_valid_tls13_compat_ccs(header, ccs_body[0]))
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid ccs body {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  ccs_body[0]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    co_return;
}

boost::asio::awaitable<void> read_tls_record_header_allow_ccs(boost::asio::ip::tcp::socket& socket,
                                                              std::array<uint8_t, 5>& header,
                                                              uint32_t timeout_sec,
                                                              const server_log_context& log_context,
                                                              boost::system::error_code& ec)
{
    co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(header), timeout_sec, ec);
    if (ec)
    {
        co_return;
    }
    if (header[1] != 0x03 || header[2] != 0x03)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid tls record version {} {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  header[1],
                  header[2]);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }

    uint32_t ccs_count = 0;
    while (header[0] == 0x14)
    {
        if (ccs_count >= constants::tls_limits::kMaxCompatCcsRecords)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} too many ccs records {}",
                      mux::log_event::kHandshake,
                      log_context.conn_id,
                      log_context.local_addr,
                      log_context.local_port,
                      log_context.remote_addr,
                      log_context.remote_port,
                      server_log_sni(log_context),
                      ccs_count);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        ccs_count++;

        const auto ccs_len = static_cast<uint16_t>((header[3] << 8) | header[4]);
        if (ccs_len != 1)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid ccs length {}",
                      mux::log_event::kHandshake,
                      log_context.conn_id,
                      log_context.local_addr,
                      log_context.local_port,
                      log_context.remote_addr,
                      log_context.remote_port,
                      server_log_sni(log_context),
                      ccs_len);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
        co_await consume_tls13_compat_ccs(socket, header, timeout_sec, log_context, ec);
        if (ec)
        {
            co_return;
        }

        co_await mux::net::wait_read_with_timeout(socket, boost::asio::buffer(header), timeout_sec, ec);
        if (ec)
        {
            co_return;
        }
        if (header[1] != 0x03 || header[2] != 0x03)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} invalid tls record version {} {}",
                      mux::log_event::kHandshake,
                      log_context.conn_id,
                      log_context.local_addr,
                      log_context.local_port,
                      log_context.remote_addr,
                      log_context.remote_port,
                      server_log_sni(log_context),
                      header[1],
                      header[2]);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return;
        }
    }

    co_return;
}

std::vector<uint8_t> compose_tls_record(const std::array<uint8_t, 5>& header, const std::vector<uint8_t>& body)
{
    std::vector<uint8_t> out(header.size() + body.size());
    std::memcpy(out.data(), header.data(), header.size());
    std::memcpy(out.data() + header.size(), body.data(), body.size());
    return out;
}

bool verify_client_finished_plaintext(
    const std::vector<uint8_t>& plaintext, uint8_t content_type, const std::vector<uint8_t>& expected_verify, const server_log_context& log_context)
{
    if (content_type != tls::kContentTypeHandshake || plaintext.size() < 4 || plaintext[0] != 0x14)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished verification failed type {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  static_cast<int>(content_type));
        return false;
    }

    const uint32_t msg_len =
        (static_cast<uint32_t>(plaintext[1]) << 16) | (static_cast<uint32_t>(plaintext[2]) << 8) | static_cast<uint32_t>(plaintext[3]);
    if (msg_len != expected_verify.size() || plaintext.size() != 4 + msg_len)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished length invalid {}",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context),
                  plaintext.size());
        return false;
    }
    if (CRYPTO_memcmp(plaintext.data() + 4, expected_verify.data(), expected_verify.size()) != 0)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished hmac verification failed",
                  mux::log_event::kHandshake,
                  log_context.conn_id,
                  log_context.local_addr,
                  log_context.local_port,
                  log_context.remote_addr,
                  log_context.remote_port,
                  server_log_sni(log_context));
        return false;
    }
    return true;
}

std::vector<uint8_t> compose_server_hello_flight(const std::vector<uint8_t>& sh_msg,
                                                 const std::vector<uint8_t>& flight2_plain,
                                                 bool send_change_cipher_spec,
                                                 std::span<const uint16_t> encrypted_handshake_record_sizes,
                                                 const EVP_CIPHER* cipher,
                                                 const std::pair<std::vector<uint8_t>, std::vector<uint8_t>>& s_hs_keys,
                                                 boost::system::error_code& ec)
{
    ec.clear();
    std::vector<uint8_t> out_sh;
    const auto sh_rec = tls::write_record_header(tls::kContentTypeHandshake, static_cast<uint16_t>(sh_msg.size()));
    out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
    out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
    if (send_change_cipher_spec)
    {
        out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    }

    std::size_t offset = 0;
    uint64_t seq = 0;
    const tls::cipher_context record_ctx;
    const traffic_key_material key_material{
        .key = s_hs_keys.first,
        .iv = s_hs_keys.second,
    };
    const auto append_encrypted_chunk = [&](std::size_t len) -> bool
    {
        if (len == 0 || offset >= flight2_plain.size())
        {
            return true;
        }

        const auto remaining = flight2_plain.size() - offset;
        if (len > remaining)
        {
            ec = boost::asio::error::message_size;
            return false;
        }

        const auto end = offset + len;
        const std::vector<uint8_t> chunk(flight2_plain.begin() + static_cast<std::ptrdiff_t>(offset),
                                         flight2_plain.begin() + static_cast<std::ptrdiff_t>(end));
        tls::record_layer::encrypt_tls_record(record_ctx, cipher, key_material, seq++, chunk, tls::kContentTypeHandshake, out_sh, ec);
        if (ec)
        {
            return false;
        }
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

struct authenticated_handshake_plan
{
    handshake_crypto_result crypto;
    uint16_t cipher_suite = 0;
    std::string selected_alpn;
    bool has_cached_material = false;
    std::size_t cert_chain_size = 1;
    bool send_change_cipher_spec = true;
    std::vector<uint16_t> encrypted_handshake_record_sizes;
};

boost::asio::awaitable<bool> read_client_hello_or_decide(const server_handshake_context& handshake_ctx,
                                                         server_handshake_state& state,
                                                         const mux::config& cfg,
                                                         server_accept_result& result,
                                                         boost::system::error_code& ec)
{
    if (handshake_ctx.socket == nullptr)
    {
        ec = boost::asio::error::bad_descriptor;
        co_return false;
    }

    const auto* read_failure_reason = co_await read_client_hello_handshake(*handshake_ctx.socket,
                                                                           state.client_hello_record,
                                                                           state.client_hello_handshake,
                                                                           cfg.timeout.read,
                                                                           constants::tls_limits::kMaxUnauthenticatedClientHelloLen,
                                                                           state.log_context,
                                                                           ec);
    if (read_failure_reason != nullptr)
    {
        ec.clear();
        result = make_decision_result(accept_mode::kFallbackToTarget, read_failure_reason, state);
        co_return false;
    }

    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} sni {} received client hello wire size {} handshake size {}",
              mux::log_event::kHandshake,
              state.log_context.conn_id,
              state.log_context.local_addr,
              state.log_context.local_port,
              state.log_context.remote_addr,
              state.log_context.remote_port,
              server_log_sni(state.log_context),
              state.client_hello_record.size(),
              state.client_hello_handshake.size());
    state.client_hello = tls::client_hello_parser::parse(state.client_hello_handshake);
    co_return true;
}

std::optional<server_accept_result> validate_client_hello_sni_and_extensions(server_handshake_context& handshake_ctx,
                                                                             server_handshake_state& state,
                                                                             const mux::config& cfg)
{
    if (state.client_hello.malformed_sni)
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail malformed sni extension drop",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kReject, "malformed_sni", state);
    }
    if (is_invalid_sni(state.client_hello.sni))
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail invalid sni drop",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kReject, "invalid_sni", state);
    }

    handshake_ctx.sni = state.client_hello.sni;
    state.log_context.sni = handshake_ctx.sni;
    if (state.client_hello.malformed_extensions)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail malformed extensions block",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "malformed_extensions", state);
    }
    if (!verify_client_hello_sni(state.client_hello, cfg))
    {
        const auto client_sni = state.client_hello.sni.empty() ? std::string("empty") : state.client_hello.sni;
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail server name mismatch client {} expected {}",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 client_sni,
                 cfg.reality.sni);
        return make_decision_result(accept_mode::kFallbackToTarget, "server_name_mismatch", state);
    }
    if (state.client_hello.malformed_key_share)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail malformed key share extension",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "malformed_key_share", state);
    }
    if (state.client_hello.malformed_supported_groups || state.client_hello.malformed_supported_versions ||
        state.client_hello.malformed_renegotiation_info)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail malformed tls13 extensions supported groups {} supported versions {} renegotiation info {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.malformed_supported_groups,
                  state.client_hello.malformed_supported_versions,
                  state.client_hello.malformed_renegotiation_info);
        return make_decision_result(accept_mode::kFallbackToTarget, "malformed_tls13_extensions", state);
    }
    if (state.client_hello.malformed_signature_algorithms)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail malformed signature algorithms extension",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "malformed_signature_algorithms", state);
    }

    return std::nullopt;
}

std::optional<server_accept_result> validate_client_hello_tls13_requirements(server_handshake_state& state)
{
    if (state.client_hello.signature_algorithms.empty())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail missing signature algorithms extension",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "missing_signature_algorithms", state);
    }
    if (!client_offers_signature_scheme(state.client_hello, tls::consts::sig_alg::kEd25519))
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail missing ed25519 signature algorithm",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "missing_ed25519_signature_algorithm", state);
    }
    if (!state.client_hello.is_tls13 || state.client_hello.session_id.size() != constants::auth::kSessionIdLen)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail is tls13 {} sid len {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.is_tls13,
                  state.client_hello.session_id.size());
        return make_decision_result(accept_mode::kFallbackToTarget, "invalid_tls13_client_hello", state);
    }
    if (state.client_hello.random.size() != 32)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail random len {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.random.size());
        return make_decision_result(accept_mode::kFallbackToTarget, "invalid_client_random", state);
    }
    if (client_offers_cipher_suite(state.client_hello, tls::consts::cipher::kTlsFallbackScsv))
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail unexpected tls fallback scsv",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "unexpected_tls_fallback_scsv", state);
    }
    if (state.client_hello.compression_methods.size() != 1)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail illegal tls13 compression method count {}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.compression_methods.size());
        return make_decision_result(accept_mode::kFallbackToTarget, "illegal_tls13_compression_methods", state);
    }
    if (state.client_hello.compression_methods[0] != 0x00)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail illegal tls13 compression method {:02x}",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  state.client_hello.compression_methods[0]);
        return make_decision_result(accept_mode::kFallbackToTarget, "illegal_tls13_compression_methods", state);
    }
    if (!state.client_hello.secure_renegotiation.empty())
    {
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail non-empty renegotiation info len {}",
                 mux::log_event::kAuth,
                 state.log_context.conn_id,
                 state.log_context.local_addr,
                 state.log_context.local_port,
                 state.log_context.remote_addr,
                 state.log_context.remote_port,
                 server_log_sni(state.log_context),
                 state.client_hello.secure_renegotiation.size());
        return make_decision_result(accept_mode::kFallbackToTarget, "non_empty_renegotiation_info", state);
    }

    return std::nullopt;
}

std::optional<server_accept_result> extract_client_key_share(server_handshake_state& state)
{
    if (state.client_hello.key_share_group == tls::consts::group::kX25519MLKEM768 &&
        state.client_hello.x25519_mlkem768_share.size() == tls::kMlkem768PublicKeySize + 32)
    {
        state.key_share_group = tls::consts::group::kX25519MLKEM768;
        state.mlkem768_peer_pub.assign(state.client_hello.x25519_mlkem768_share.begin(),
                                       state.client_hello.x25519_mlkem768_share.begin() + static_cast<std::ptrdiff_t>(tls::kMlkem768PublicKeySize));
        state.x25519_peer_pub.assign(state.client_hello.x25519_mlkem768_share.end() - 32, state.client_hello.x25519_mlkem768_share.end());
    }
    else if (state.client_hello.key_share_group == tls::consts::group::kX25519 && state.client_hello.x25519_pub.size() == 32)
    {
        state.key_share_group = tls::consts::group::kX25519;
        state.x25519_peer_pub = state.client_hello.x25519_pub;
    }

    if (state.x25519_peer_pub.size() != 32)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} auth fail missing valid x25519 key share",
                  mux::log_event::kAuth,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "missing_x25519_share", state);
    }

    return std::nullopt;
}

std::optional<server_accept_result> authenticate_client_hello(server_handshake_state& state,
                                                              const std::vector<uint8_t>& private_key,
                                                              const std::vector<uint8_t>& short_id_bytes,
                                                              boost::system::error_code& ec)
{
    auto auth = decrypt_auth_payload(state, private_key, ec);
    if (ec)
    {
        ec.clear();
        return make_decision_result(accept_mode::kFallbackToTarget, "decrypt_auth_payload_failed", state);
    }
    if (!verify_auth_payload_fields(auth, short_id_bytes, state))
    {
        return make_decision_result(accept_mode::kFallbackToTarget, "verify_auth_payload_failed", state);
    }
    if (!verify_auth_timestamp(auth.timestamp, state))
    {
        return make_decision_result(accept_mode::kFallbackToTarget, "verify_auth_timestamp_failed", state);
    }

    return std::nullopt;
}

std::optional<server_accept_result> finalize_client_hello_authentication(server_handshake_state& state, mux::replay_cache& replay_cache)
{
    LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} sni {} client hello selected key share group 0x{:04x} {} client hybrid {} client x25519 {}",
             mux::log_event::kHandshake,
             state.log_context.conn_id,
             state.log_context.local_addr,
             state.log_context.local_port,
             state.log_context.remote_addr,
             state.log_context.remote_port,
             server_log_sni(state.log_context),
             state.key_share_group,
             tls::named_group_name(state.key_share_group),
             state.client_hello.has_x25519_mlkem768_share,
             state.client_hello.has_x25519_share);
    if (state.client_hello_handshake.size() < 4)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} buffer too short",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return make_decision_result(accept_mode::kFallbackToTarget, "client_hello_message_too_short", state);
    }
    if (!verify_replay_guard(replay_cache, state))
    {
        return make_decision_result(accept_mode::kReject, "replay_attack", state);
    }

    state.transcript.update(state.client_hello_handshake);
    return std::nullopt;
}

std::optional<server_accept_result> validate_client_hello_and_authenticate(server_handshake_context& handshake_ctx,
                                                                           server_handshake_state& state,
                                                                           const mux::config& cfg,
                                                                           const std::vector<uint8_t>& private_key,
                                                                           const std::vector<uint8_t>& short_id_bytes,
                                                                           mux::replay_cache& replay_cache,
                                                                           boost::system::error_code& ec)
{
    if (auto result = validate_client_hello_sni_and_extensions(handshake_ctx, state, cfg); result.has_value())
    {
        return result;
    }
    if (auto result = validate_client_hello_tls13_requirements(state); result.has_value())
    {
        return result;
    }
    if (auto result = extract_client_key_share(state); result.has_value())
    {
        return result;
    }
    if (auto result = authenticate_client_hello(state, private_key, short_id_bytes, ec); result.has_value())
    {
        return result;
    }

    return finalize_client_hello_authentication(state, replay_cache);
}

authenticated_handshake_plan prepare_authenticated_handshake(server_handshake_state& state,
                                                             const site_material* site_material,
                                                             const std::array<uint8_t, 32>& reality_cert_private_key,
                                                             const std::vector<uint8_t>& reality_cert_public_key,
                                                             const std::vector<uint8_t>& reality_cert_template,
                                                             boost::system::error_code& ec)
{
    ec.clear();
    authenticated_handshake_plan plan;
    std::array<uint8_t, 32> ephemeral_public_key = {};
    std::array<uint8_t, 32> ephemeral_private_key = {};
    const struct private_key_cleaner
    {
        std::array<uint8_t, 32>& key;

        ~private_key_cleaner() { OPENSSL_cleanse(key.data(), key.size()); }
    } cleaner{ephemeral_private_key};

    if (!tls::crypto_util::generate_x25519_keypair(ephemeral_public_key.data(), ephemeral_private_key.data()))
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} generate ephemeral x25519 key failed",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::fault;
        return {};
    }

    state.server_random = generate_server_random(ec);
    if (ec)
    {
        return {};
    }

    LOG_TRACE("event {} conn_id {} local {}:{} remote {}:{} sni {} generated ephemeral key {}",
              mux::log_event::kHandshake,
              state.log_context.conn_id,
              state.log_context.local_addr,
              state.log_context.local_port,
              state.log_context.remote_addr,
              state.log_context.remote_port,
              server_log_sni(state.log_context),
              tls::crypto_util::bytes_to_hex(std::vector<uint8_t>(ephemeral_public_key.begin(), ephemeral_public_key.end())));

    auto x25519_shared =
        tls::crypto_util::x25519_derive(std::vector<uint8_t>(ephemeral_private_key.begin(), ephemeral_private_key.end()), state.x25519_peer_pub, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} x25519 derive failed",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        return {};
    }

    if (state.key_share_group == tls::consts::group::kX25519MLKEM768)
    {
        std::vector<uint8_t> mlkem768_shared;
        auto ciphertext = tls::crypto_util::mlkem768_encapsulate(state.mlkem768_peer_pub, mlkem768_shared, ec);
        if (ec)
        {
            LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} mlkem768 encapsulate failed {}",
                      mux::log_event::kHandshake,
                      state.log_context.conn_id,
                      state.log_context.local_addr,
                      state.log_context.local_port,
                      state.log_context.remote_addr,
                      state.log_context.remote_port,
                      server_log_sni(state.log_context),
                      ec.message());
            return {};
        }
        state.server_shared_secret = std::move(mlkem768_shared);
        state.server_shared_secret.insert(state.server_shared_secret.end(), x25519_shared.begin(), x25519_shared.end());
        state.server_key_share_data = std::move(ciphertext);
        state.server_key_share_data.insert(state.server_key_share_data.end(), ephemeral_public_key.begin(), ephemeral_public_key.end());
    }
    else
    {
        state.server_shared_secret = std::move(x25519_shared);
        state.server_key_share_data.assign(ephemeral_public_key.begin(), ephemeral_public_key.end());
    }

    if (state.auth_key.empty() || reality_cert_public_key.size() != 32 || reality_cert_template.empty())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} reality certificate identity unavailable",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::fault;
        return {};
    }

    auto cert_der = build_reality_bound_certificate(reality_cert_template, state.auth_key, reality_cert_public_key, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} build reality certificate failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        return {};
    }

    plan.has_cached_material = (site_material != nullptr);
    const auto cert_chain = build_reality_certificate_chain(cert_der, site_material);
    state.cert_msg = tls::construct_certificate(cert_chain);

    const auto cipher_suite = select_reality_cipher_suite(state.client_hello, site_material);
    if (!cipher_suite.has_value())
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} no mutual tls13 cipher suite",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context));
        ec = boost::asio::error::no_protocol_option;
        return {};
    }
    plan.cipher_suite = *cipher_suite;
    plan.selected_alpn = select_reality_alpn(state.client_hello, site_material);
    const auto server_hello_extension_order = select_server_hello_extension_order(site_material);
    const auto encrypted_extension_order = select_encrypted_extensions_order(site_material);
    const bool include_ee_padding = should_include_encrypted_extensions_padding(site_material);
    const auto encrypted_extensions_padding_len = select_encrypted_extensions_padding_len(site_material);
    plan.send_change_cipher_spec = should_send_change_cipher_spec(site_material);
    plan.encrypted_handshake_record_sizes = select_encrypted_handshake_record_sizes(site_material);
    plan.cert_chain_size = select_reality_certificate_chain_size(site_material);

    LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} sni {} success path material cache {} certs {} group 0x{:04x} {} key share len {} cipher 0x{:04x} alpn '{}' sh exts {} ee exts {} ee padding {} ee padding len {} ccs {} hs records {}",
             mux::log_event::kHandshake,
             state.log_context.conn_id,
             state.log_context.local_addr,
             state.log_context.local_port,
             state.log_context.remote_addr,
             state.log_context.remote_port,
             server_log_sni(state.log_context),
             plan.has_cached_material,
             plan.cert_chain_size,
             state.key_share_group,
             tls::named_group_name(state.key_share_group),
             state.server_key_share_data.size(),
             plan.cipher_suite,
             plan.selected_alpn,
             server_hello_extension_order.size(),
             encrypted_extension_order.size(),
             include_ee_padding,
             encrypted_extensions_padding_len.value_or(0),
             plan.send_change_cipher_spec,
             plan.encrypted_handshake_record_sizes.size());

    plan.crypto = build_handshake_crypto(state,
                                         plan.cipher_suite,
                                         plan.selected_alpn,
                                         server_hello_extension_order,
                                         encrypted_extension_order,
                                         include_ee_padding,
                                         encrypted_extensions_padding_len,
                                         std::vector<uint8_t>(reality_cert_private_key.begin(), reality_cert_private_key.end()),
                                         ec);
    return plan;
}

boost::asio::awaitable<bool> complete_authenticated_handshake(const server_handshake_context& handshake_ctx,
                                                              const server_handshake_state& state,
                                                              const mux::config& cfg,
                                                              const authenticated_handshake_plan& plan,
                                                              authenticated_session& authenticated,
                                                              boost::system::error_code& ec)
{
    ec.clear();
    const auto out_sh = compose_server_hello_flight(plan.crypto.sh_msg,
                                                    plan.crypto.flight2_plain,
                                                    plan.send_change_cipher_spec,
                                                    plan.encrypted_handshake_record_sizes,
                                                    plan.crypto.cipher,
                                                    plan.crypto.s_hs_keys,
                                                    ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} compose server hello flight failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        co_return false;
    }

    LOG_DEBUG("event {} conn_id {} local {}:{} remote {}:{} sni {} sending server hello flight size {}",
              mux::log_event::kHandshake,
              state.log_context.conn_id,
              state.log_context.local_addr,
              state.log_context.local_port,
              state.log_context.remote_addr,
              state.log_context.remote_port,
              server_log_sni(state.log_context),
              out_sh.size());
    co_await mux::net::wait_write_with_timeout(*handshake_ctx.socket, boost::asio::buffer(out_sh), cfg.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} write server hello failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        co_return false;
    }

    std::array<uint8_t, 5> header = {0};
    co_await read_tls_record_header_allow_ccs(*handshake_ctx.socket, header, cfg.timeout.read, state.log_context, ec);
    if (ec)
    {
        co_return false;
    }

    const auto body_len = static_cast<uint16_t>((header[3] << 8) | header[4]);
    if (body_len > constants::tls_limits::kMaxCiphertextRecordLen)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished record too large {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  body_len);
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return false;
    }

    std::vector<uint8_t> body(body_len);
    co_await mux::net::wait_read_with_timeout(*handshake_ctx.socket, boost::asio::buffer(body), cfg.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }

    const auto record = compose_tls_record(header, body);
    uint8_t content_type = 0;
    auto plaintext =
        tls::record_layer::decrypt_record(plan.crypto.cipher, plan.crypto.c_hs_keys.first, plan.crypto.c_hs_keys.second, 0, record, content_type, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished decrypt failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        co_return false;
    }

    auto expected_fin_verify = tls::key_schedule::compute_finished_verify_data(
        plan.crypto.hs_keys.client_handshake_traffic_secret, state.transcript.finish(), plan.crypto.md, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} local {}:{} remote {}:{} sni {} client finished verify data failed {}",
                  mux::log_event::kHandshake,
                  state.log_context.conn_id,
                  state.log_context.local_addr,
                  state.log_context.local_port,
                  state.log_context.remote_addr,
                  state.log_context.remote_port,
                  server_log_sni(state.log_context),
                  ec.message());
        co_return false;
    }

    if (!verify_client_finished_plaintext(plaintext, content_type, expected_fin_verify, state.log_context))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return false;
    }

    auto app_sec = tls::key_schedule::derive_application_secrets(plan.crypto.hs_keys.master_secret, state.transcript.finish(), plan.crypto.md, ec);
    if (ec)
    {
        co_return false;
    }

    authenticated.secrets = {
        .c_app_secret = std::move(app_sec.first),
        .s_app_secret = std::move(app_sec.second),
    };
    authenticated.negotiated = {
        .cipher_suite = plan.cipher_suite,
        .key_share_group = state.key_share_group,
        .negotiated_alpn = plan.selected_alpn,
        .md = plan.crypto.md,
        .cipher = plan.crypto.cipher,
    };
    co_return true;
}

}    // namespace

server_handshaker::server_handshaker(const dependencies& deps)
    : cfg_(deps.cfg),
      private_key_(deps.private_key),
      short_id_bytes_(deps.short_id_bytes),
      replay_cache_(deps.replay_cache),
      site_material_(deps.site_material_ptr),
      reality_cert_private_key_(deps.reality_cert_private_key),
      reality_cert_public_key_(deps.reality_cert_public_key),
      reality_cert_template_(deps.reality_cert_template)
{
}

boost::asio::awaitable<server_accept_result> server_handshaker::accept(server_handshake_context& handshake_ctx, boost::system::error_code& ec) const
{
    ec.clear();
    server_accept_result result;
    server_handshake_state state;
    state.log_context = make_server_log_context(handshake_ctx);

    if (!(co_await read_client_hello_or_decide(handshake_ctx, state, cfg_, result, ec)))
    {
        co_return result;
    }

    const auto decision = validate_client_hello_and_authenticate(handshake_ctx, state, cfg_, private_key_, short_id_bytes_, replay_cache_, ec);
    if (decision.has_value())
    {
        co_return *decision;
    }

    const auto plan =
        prepare_authenticated_handshake(state, site_material_, reality_cert_private_key_, reality_cert_public_key_, reality_cert_template_, ec);
    if (ec)
    {
        co_return result;
    }

    if (!(co_await complete_authenticated_handshake(handshake_ctx, state, cfg_, plan, result.authenticated, ec)))
    {
        co_return result;
    }

    result.mode = accept_mode::kAuthenticated;
    co_return result;
}

}    // namespace reality
