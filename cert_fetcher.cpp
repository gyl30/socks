#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <optional>
#include <system_error>

#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/connect.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "log.h"
#include "crypto_util.h"
#include "log_context.h"
#include "cert_fetcher.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "reality_fingerprint.h"

namespace reality
{

namespace
{
constexpr std::size_t kMaxMsgSize = 64L * 1024;
constexpr std::size_t kMaxEncryptedRecordLen = 18432;

struct negotiated_suite
{
    const EVP_CIPHER* cipher = nullptr;
    const EVP_MD* md = nullptr;
    std::size_t key_len = 16;
};

bool extract_server_hello_message(const std::vector<std::uint8_t>& sh_body, std::vector<std::uint8_t>& sh_real)
{
    if (sh_body.size() < 4)
    {
        return false;
    }

    const std::uint32_t msg_len = (sh_body[1] << 16) | (sh_body[2] << 8) | sh_body[3];
    const std::uint32_t full_msg_len = msg_len + 4;
    if (sh_body.size() < full_msg_len)
    {
        return false;
    }

    sh_real.assign(sh_body.begin(), sh_body.begin() + static_cast<std::ptrdiff_t>(full_msg_len));
    return true;
}

bool parse_server_hello_cipher_suite(const std::vector<std::uint8_t>& sh_real, std::uint16_t& cipher_suite)
{
    if (sh_real.size() <= 38)
    {
        return false;
    }

    std::size_t cipher_offset = 39;
    const std::uint8_t sid_len_val = sh_real[38];
    cipher_offset += sid_len_val;
    if (sh_real.size() < cipher_offset + 2)
    {
        return false;
    }

    cipher_suite = static_cast<std::uint16_t>((sh_real[cipher_offset] << 8) | sh_real[cipher_offset + 1]);
    return true;
}

std::optional<negotiated_suite> select_negotiated_suite(const std::uint16_t cipher_suite, const mux::connection_context& ctx)
{
    if (cipher_suite == 0x1301)
    {
        LOG_CTX_INFO(ctx, "{} selected tls_aes_128_gcm_sha256 0x1301", mux::log_event::kCert);
        return negotiated_suite{.cipher = EVP_aes_128_gcm(), .md = EVP_sha256(), .key_len = 16};
    }
    if (cipher_suite == 0x1302)
    {
        LOG_CTX_INFO(ctx, "{} selected tls_aes_256_gcm_sha384 0x1302", mux::log_event::kCert);
        return negotiated_suite{.cipher = EVP_aes_256_gcm(), .md = EVP_sha384(), .key_len = 32};
    }
    if (cipher_suite == 0x1303)
    {
        LOG_CTX_INFO(ctx, "{} selected tls_chacha20_poly1305_sha256 0x1303", mux::log_event::kCert);
        return negotiated_suite{.cipher = EVP_chacha20_poly1305(), .md = EVP_sha256(), .key_len = 32};
    }
    return std::nullopt;
}

std::pair<std::uint8_t, std::span<std::uint8_t>> empty_record_result()
{
    return std::make_pair(0, std::span<std::uint8_t>{});
}

std::pair<std::uint8_t, std::span<std::uint8_t>> copy_plaintext_record(std::vector<std::uint8_t>& pt_buf, const std::vector<std::uint8_t>& rec)
{
    if (pt_buf.size() < rec.size())
    {
        pt_buf.resize(rec.size());
    }
    std::memcpy(pt_buf.data(), rec.data(), rec.size());
    return std::make_pair(kContentTypeChangeCipherSpec, std::span<std::uint8_t>(pt_buf.data(), rec.size()));
}

std::vector<std::uint8_t> build_encrypted_record_bytes(const std::uint8_t* head, const std::vector<std::uint8_t>& rec)
{
    std::vector<std::uint8_t> ciphertext_record(5 + rec.size());
    std::memcpy(ciphertext_record.data(), head, 5);
    std::memcpy(ciphertext_record.data() + 5, rec.data(), rec.size());
    return ciphertext_record;
}

std::error_code derive_server_record_protection(const std::vector<std::uint8_t>& sh_real,
                                                const negotiated_suite& suite,
                                                transcript& trans,
                                                const std::uint8_t* client_private,
                                                const mux::connection_context& ctx,
                                                const EVP_CIPHER*& negotiated_cipher,
                                                std::vector<std::uint8_t>& dec_key,
                                                std::vector<std::uint8_t>& dec_iv)
{
    constexpr std::size_t iv_len = 12;

    const auto server_pub = extract_server_public_key(sh_real);
    std::error_code ec;
    auto shared = crypto_util::x25519_derive(std::vector<std::uint8_t>(client_private, client_private + 32), server_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", mux::log_event::kCert);
        return ec;
    }

    auto hs_keys = tls_key_schedule::derive_handshake_keys(shared, trans.finish(), suite.md, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} derive keys failed", mux::log_event::kCert);
        return ec;
    }

    auto s_hs_keys = tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, suite.key_len, iv_len, suite.md);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} derive traffic keys failed", mux::log_event::kCert);
        return ec;
    }

    negotiated_cipher = suite.cipher;
    dec_key = std::move(s_hs_keys.first);
    dec_iv = std::move(s_hs_keys.second);
    return std::error_code{};
}
}

void handshake_reassembler::append(std::span<const std::uint8_t> data) { buffer_.insert(buffer_.end(), data.begin(), data.end()); }

bool handshake_reassembler::next(std::vector<std::uint8_t>& out, std::error_code& ec)
{
    ec.clear();
    if (buffer_.size() < 4)
    {
        return false;
    }

    const std::uint32_t msg_len =
        (static_cast<std::uint32_t>(buffer_[1]) << 16) | (static_cast<std::uint32_t>(buffer_[2]) << 8) | static_cast<std::uint32_t>(buffer_[3]);

    if (msg_len > kMaxMsgSize)
    {
        buffer_.clear();
        ec = std::make_error_code(std::errc::message_size);
        return false;
    }

    const std::uint32_t full_len = 4 + msg_len;
    if (buffer_.size() < full_len)
    {
        return false;
    }

    out.assign(buffer_.begin(), buffer_.begin() + full_len);
    buffer_.erase(buffer_.begin(), buffer_.begin() + full_len);
    return true;
}

std::string cert_fetcher::hex(const std::vector<std::uint8_t>& data) { return crypto_util::bytes_to_hex(data); }

std::string cert_fetcher::hex(const std::uint8_t* data, std::size_t len)
{
    return crypto_util::bytes_to_hex(std::vector<std::uint8_t>(data, data + len));
}

asio::awaitable<std::optional<fetch_result>> cert_fetcher::fetch(
    asio::io_context& io_context, std::string host, std::uint16_t port, std::string sni, const std::string& trace_id)
{
    fetch_session session(io_context, std::move(host), port, std::move(sni), trace_id);
    co_return co_await session.run();
}

cert_fetcher::fetch_session::fetch_session(
    asio::io_context& io_context, std::string host, const std::uint16_t port, std::string sni, const std::string& trace_id)
    : io_context_(io_context), socket_(io_context_), host_(std::move(host)), port_(port), sni_(std::move(sni))
{
    ctx_.trace_id(trace_id);
    ctx_.target_host(host_);
    ctx_.target_port(port);
    ctx_.sni(sni_);
}

asio::awaitable<std::optional<fetch_result>> cert_fetcher::fetch_session::run()
{
    LOG_CTX_INFO(ctx_, "{} starting fetch", mux::log_event::kCert);

    if (const auto ec = co_await connect(); ec)
    {
        co_return std::nullopt;
    }

    if (const auto ec = co_await perform_handshake_start(); ec)
    {
        co_return std::nullopt;
    }

    auto cert = co_await find_certificate();
    if (cert.empty())
    {
        co_return std::nullopt;
    }

    co_return fetch_result{.cert_msg = std::move(cert), .fingerprint = fingerprint_};
}

asio::awaitable<std::error_code> cert_fetcher::fetch_session::connect()
{
    asio::ip::tcp::resolver resolver(io_context_);
    auto [res_ec, eps] = co_await resolver.async_resolve(host_, std::to_string(port_), asio::as_tuple(asio::use_awaitable));
    if (res_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} resolve failed {}", mux::log_event::kCert, res_ec.message());
        co_return res_ec;
    }

    auto [conn_ec, ep] = co_await asio::async_connect(socket_, eps, asio::as_tuple(asio::use_awaitable));
    if (conn_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} connect failed {}", mux::log_event::kCert, conn_ec.message());
        co_return conn_ec;
    }
    co_return std::error_code{};
}

asio::awaitable<std::error_code> cert_fetcher::fetch_session::perform_handshake_start()
{
    std::vector<std::uint8_t> client_random(32);
    std::vector<std::uint8_t> session_id(32);
    if (!init_handshake_material(client_random, session_id))
    {
        co_return asio::error::operation_aborted;
    }

    auto spec = fingerprint_factory::get(fingerprint_type::kChrome120);
    auto ch = client_hello_builder::build(spec, session_id, client_random, std::vector<std::uint8_t>(client_public_, client_public_ + 32), sni_);

    if (const auto write_ec = co_await send_client_hello_record(ch); write_ec)
    {
        co_return write_ec;
    }

    trans_.update(ch);

    auto [read_ec, sh_body] = co_await read_record_plaintext();
    if (read_ec)
    {
        co_return read_ec;
    }
    if (!validate_server_hello_body(sh_body))
    {
        co_return asio::error::fault;
    }

    co_return process_server_hello(sh_body);
}

bool cert_fetcher::fetch_session::init_handshake_material(std::vector<std::uint8_t>& client_random, std::vector<std::uint8_t>& session_id)
{
    if (!crypto_util::generate_x25519_keypair(client_public_, client_private_))
    {
        return false;
    }
    if (RAND_bytes(client_random.data(), static_cast<int>(client_random.size())) != 1)
    {
        return false;
    }
    if (RAND_bytes(session_id.data(), static_cast<int>(session_id.size())) != 1)
    {
        return false;
    }
    return true;
}

asio::awaitable<std::error_code> cert_fetcher::fetch_session::send_client_hello_record(const std::vector<std::uint8_t>& client_hello)
{
    auto ch_record = write_record_header(kContentTypeHandshake, static_cast<std::uint16_t>(client_hello.size()));
    ch_record.insert(ch_record.end(), client_hello.begin(), client_hello.end());

    const auto [write_ec, write_n] = co_await asio::async_write(socket_, asio::buffer(ch_record), asio::as_tuple(asio::use_awaitable));
    (void)write_n;
    if (write_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write ch failed {}", mux::log_event::kCert, write_ec.message());
        co_return write_ec;
    }
    co_return std::error_code{};
}

bool cert_fetcher::fetch_session::validate_server_hello_body(const std::vector<std::uint8_t>& sh_body) const
{
    if (!sh_body.empty())
    {
        return true;
    }
    LOG_CTX_ERROR(ctx_, "{} server hello empty", mux::log_event::kCert);
    return false;
}

asio::awaitable<std::vector<std::uint8_t>> cert_fetcher::fetch_session::find_certificate()
{
    handshake_reassembler assembler;
    std::vector<std::uint8_t> pt_buf(kMaxTlsPlaintextLen + 256);
    std::vector<std::uint8_t> msg;
    std::vector<std::uint8_t> cert_msg;

    for (int i = 0; i < 100; ++i)
    {
        std::error_code ec;
        if (!(co_await append_next_handshake_record(assembler, pt_buf, i, ec)))
        {
            break;
        }
        if (consume_handshake_messages(assembler, msg, cert_msg, ec))
        {
            co_return cert_msg;
        }
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} assembler error {}", mux::log_event::kCert, ec.message());
            break;
        }
    }

    LOG_CTX_WARN(ctx_, "{} certificate not found", mux::log_event::kCert);
    co_return std::vector<std::uint8_t>{};
}

asio::awaitable<bool> cert_fetcher::fetch_session::append_next_handshake_record(handshake_reassembler& assembler,
                                                                                 std::vector<std::uint8_t>& pt_buf,
                                                                                 const int record_index,
                                                                                 std::error_code& ec)
{
    auto [type, pt_data] = co_await read_record(pt_buf, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} read record {} failed {}", mux::log_event::kCert, record_index, ec.message());
        co_return false;
    }

    if (type == kContentTypeChangeCipherSpec || type != kContentTypeHandshake)
    {
        co_return true;
    }

    assembler.append(pt_data);
    co_return true;
}

bool cert_fetcher::fetch_session::consume_handshake_messages(handshake_reassembler& assembler,
                                                             std::vector<std::uint8_t>& msg,
                                                             std::vector<std::uint8_t>& cert_msg,
                                                             std::error_code& ec)
{
    while (assembler.next(msg, ec))
    {
        if (process_handshake_message(msg, cert_msg))
        {
            return true;
        }
    }
    return false;
}

bool cert_fetcher::fetch_session::process_handshake_message(const std::vector<std::uint8_t>& msg, std::vector<std::uint8_t>& cert_msg)
{
    const std::uint8_t msg_type = msg[0];
    const std::uint32_t msg_len = (msg[1] << 16) | (msg[2] << 8) | msg[3];
    LOG_CTX_INFO(ctx_, "{} found handshake 0x{:02x} len {}", mux::log_event::kCert, msg_type, msg_len);

    if (msg_type == 0x08)
    {
        if (auto alpn = extract_alpn_from_encrypted_extensions(msg); alpn)
        {
            LOG_CTX_INFO(ctx_, "{} learned alpn {}", mux::log_event::kCert, *alpn);
            fingerprint_.alpn = *alpn;
        }
    }
    else if (msg_type == 0x0b)
    {
        LOG_CTX_INFO(ctx_, "{} found certificate len {}", mux::log_event::kCert, msg_len);
        cert_msg = msg;
        return true;
    }

    trans_.update(msg);
    return false;
}

std::error_code cert_fetcher::fetch_session::process_server_hello(const std::vector<std::uint8_t>& sh_body)
{
    std::vector<std::uint8_t> sh_real;
    if (!extract_server_hello_message(sh_body, sh_real))
    {
        LOG_CTX_ERROR(ctx_, "{} server hello too short {}", mux::log_event::kCert, sh_body.size());
        return asio::error::fault;
    }

    if (auto cs = extract_cipher_suite_from_server_hello(sh_real); cs)
    {
        fingerprint_.cipher_suite = *cs;
    }

    trans_.update(sh_real);

    std::uint16_t cipher_suite = 0;
    if (!parse_server_hello_cipher_suite(sh_real, cipher_suite))
    {
        return asio::error::fault;
    }

    const auto suite = select_negotiated_suite(cipher_suite, ctx_);
    if (!suite.has_value())
    {
        LOG_CTX_ERROR(ctx_, "{} unsupported cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);
        return asio::error::no_protocol_option;
    }

    trans_.set_protocol_hash(suite->md);
    return derive_server_record_protection(sh_real, *suite, trans_, client_private_, ctx_, negotiated_cipher_, dec_key_, dec_iv_);
}

asio::awaitable<std::pair<std::error_code, std::vector<std::uint8_t>>> cert_fetcher::fetch_session::read_record_plaintext()
{
    std::uint8_t head[5];
    auto [ec, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} read header failed {}", mux::log_event::kCert, ec.message());
        co_return std::make_pair(ec, std::vector<std::uint8_t>{});
    }

    if (head[0] != kContentTypeHandshake)
    {
        LOG_CTX_ERROR(ctx_, "{} expected handshake type {}", mux::log_event::kCert, head[0]);
        co_return std::make_pair(asio::error::fault, std::vector<std::uint8_t>{});
    }

    const std::uint16_t len = (head[3] << 8) | head[4];
    std::vector<std::uint8_t> body(len);
    auto [ec2, n2] = co_await asio::async_read(socket_, asio::buffer(body), asio::as_tuple(asio::use_awaitable));
    if (ec2)
    {
        LOG_CTX_ERROR(ctx_, "{} read body failed {}", mux::log_event::kCert, ec2.message());
        co_return std::make_pair(ec2, std::vector<std::uint8_t>{});
    }

    co_return std::make_pair(std::error_code{}, std::move(body));
}

bool cert_fetcher::fetch_session::validate_record_length(const std::uint16_t len, std::error_code& out_ec) const
{
    if (len <= kMaxEncryptedRecordLen)
    {
        return true;
    }
    out_ec = std::make_error_code(std::errc::message_size);
    return false;
}

asio::awaitable<bool> cert_fetcher::fetch_session::read_record_body(const std::uint16_t len,
                                                                     std::vector<std::uint8_t>& rec,
                                                                     std::error_code& out_ec)
{
    rec.assign(len, 0);
    auto [body_ec, body_n] = co_await asio::async_read(socket_, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
    (void)body_n;
    if (body_ec)
    {
        out_ec = body_ec;
        co_return false;
    }
    co_return true;
}

std::pair<std::uint8_t, std::span<std::uint8_t>> cert_fetcher::fetch_session::decrypt_application_record(const std::uint8_t head[5],
                                                                                                           const std::vector<std::uint8_t>& rec,
                                                                                                           std::vector<std::uint8_t>& pt_buf,
                                                                                                           std::error_code& out_ec)
{
    auto ciphertext_record = build_encrypted_record_bytes(head, rec);
    std::uint8_t type = 0;
    const std::uint32_t pt_len =
        tls_record_layer::decrypt_record(decrypt_ctx_, negotiated_cipher_, dec_key_, dec_iv_, seq_++, ciphertext_record, pt_buf, type, out_ec);
    if (out_ec)
    {
        return empty_record_result();
    }
    return std::make_pair(type, std::span<std::uint8_t>(pt_buf.data(), pt_len));
}

std::pair<std::uint8_t, std::span<std::uint8_t>> cert_fetcher::fetch_session::handle_record_by_content_type(const std::uint8_t head[5],
                                                                                                              const std::vector<std::uint8_t>& rec,
                                                                                                              std::vector<std::uint8_t>& pt_buf,
                                                                                                              std::error_code& out_ec)
{
    switch (head[0])
    {
        case kContentTypeChangeCipherSpec:
            return copy_plaintext_record(pt_buf, rec);

        case kContentTypeApplicationData:
            return decrypt_application_record(head, rec, pt_buf, out_ec);

        case kContentTypeAlert:
            LOG_CTX_WARN(ctx_, "{} received plaintext alert", mux::log_event::kCert);
            out_ec = asio::error::connection_reset;
            return empty_record_result();

        default:
            out_ec = asio::error::invalid_argument;
            return empty_record_result();
    }
}

asio::awaitable<std::pair<std::uint8_t, std::span<std::uint8_t>>> cert_fetcher::fetch_session::read_record(std::vector<std::uint8_t>& pt_buf,
                                                                                                           std::error_code& out_ec)
{
    out_ec.clear();
    std::uint8_t head[5];
    auto [ec, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        out_ec = ec;
        co_return empty_record_result();
    }

    const std::uint16_t len = (head[3] << 8) | head[4];
    if (!validate_record_length(len, out_ec))
    {
        co_return empty_record_result();
    }

    std::vector<std::uint8_t> rec;
    if (!co_await read_record_body(len, rec, out_ec))
    {
        co_return empty_record_result();
    }
    co_return handle_record_by_content_type(head, rec, pt_buf, out_ec);
}

}    // namespace reality
