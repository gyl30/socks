#include <span>
#include <vector>
#include <string>
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
#include "reality_core.h"
#include "cert_fetcher.h"
#include "tls_record_layer.h"
#include "tls_key_schedule.h"
#include "reality_messages.h"
#include "reality_fingerprint.h"

namespace reality
{

namespace
{
constexpr std::size_t kMaxMsgSize = 64L * 1024;
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
    asio::any_io_executor ex, std::string host, std::uint16_t port, std::string sni, const std::string& trace_id)
{
    fetch_session session(ex, std::move(host), port, std::move(sni), trace_id);
    co_return co_await session.run();
}

cert_fetcher::fetch_session::fetch_session(
    const asio::any_io_executor& ex, std::string host, const std::uint16_t port, std::string sni, const std::string& trace_id)
    : socket_(ex), host_(std::move(host)), port_(port), sni_(std::move(sni))
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
    asio::ip::tcp::resolver resolver(socket_.get_executor());
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
    if (!crypto_util::generate_x25519_keypair(client_public_, client_private_))
    {
        co_return asio::error::operation_aborted;
    }
    std::vector<std::uint8_t> client_random(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        co_return asio::error::operation_aborted;
    }
    std::vector<std::uint8_t> session_id(32);
    if (RAND_bytes(session_id.data(), 32) != 1)
    {
        co_return asio::error::operation_aborted;
    }

    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    auto ch = ClientHelloBuilder::build(spec, session_id, client_random, std::vector<std::uint8_t>(client_public_, client_public_ + 32), sni_);

    auto ch_rec = write_record_header(kContentTypeHandshake, static_cast<std::uint16_t>(ch.size()));
    ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());

    auto [write_ec, wn] = co_await asio::async_write(socket_, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));
    if (write_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} write ch failed {}", mux::log_event::kCert, write_ec.message());
        co_return write_ec;
    }

    trans_.update(ch);

    auto [read_ec, sh_body] = co_await read_record_plaintext();
    if (read_ec)
    {
        co_return read_ec;
    }
    if (sh_body.empty())
    {
        LOG_CTX_ERROR(ctx_, "{} server hello empty", mux::log_event::kCert);
        co_return asio::error::fault;
    }

    co_return process_server_hello(sh_body);
}

asio::awaitable<std::vector<std::uint8_t>> cert_fetcher::fetch_session::find_certificate()
{
    handshake_reassembler assembler;
    std::vector<std::uint8_t> pt_buf(kMaxTlsPlaintextLen + 256);
    std::vector<std::uint8_t> msg;

    for (int i = 0; i < 100; ++i)
    {
        std::error_code ec;
        auto [type, pt_data] = co_await read_record(pt_buf, ec);
        if (ec)
        {
            LOG_CTX_ERROR(ctx_, "{} read record {} failed {}", mux::log_event::kCert, i, ec.message());
            break;
        }

        if (type == kContentTypeChangeCipherSpec)
        {
            continue;
        }
        if (type != kContentTypeHandshake)
        {
            continue;
        }

        assembler.append(pt_data);

        while (assembler.next(msg, ec))
        {
            std::uint8_t msg_type = msg[0];
            std::uint32_t msg_len = (msg[1] << 16) | (msg[2] << 8) | msg[3];

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
                co_return msg;
            }

            trans_.update(msg);
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

std::error_code cert_fetcher::fetch_session::process_server_hello(const std::vector<std::uint8_t>& sh_body)
{
    const std::uint32_t msg_len = (sh_body[1] << 16) | (sh_body[2] << 8) | sh_body[3];
    const std::uint32_t full_msg_len = msg_len + 4;

    if (sh_body.size() < full_msg_len)
    {
        return asio::error::fault;
    }

    std::vector<std::uint8_t> sh_real(sh_body.begin(), sh_body.begin() + full_msg_len);

    if (auto cs = extract_cipher_suite_from_server_hello(sh_real); cs)
    {
        fingerprint_.cipher_suite = *cs;
    }

    trans_.update(sh_real);

    std::size_t cipher_offset = 39;
    if (sh_real.size() <= 38)
    {
        return asio::error::fault;
    }
    const std::uint8_t sid_len_val = sh_real[38];
    cipher_offset += sid_len_val;

    if (sh_real.size() < cipher_offset + 2)
    {
        return asio::error::fault;
    }
    std::uint16_t cipher_suite = (sh_real[cipher_offset] << 8) | sh_real[cipher_offset + 1];

    const EVP_CIPHER* negotiated_cipher = nullptr;
    const EVP_MD* negotiated_md = nullptr;
    std::size_t key_len = 16;
    const std::size_t iv_len = 12;

    if (cipher_suite == 0x1301)
    {
        LOG_CTX_INFO(ctx_, "{} selected tls_aes_128_gcm_sha256 0x1301", mux::log_event::kCert);
        negotiated_cipher = EVP_aes_128_gcm();
        negotiated_md = EVP_sha256();
        key_len = 16;
    }
    else if (cipher_suite == 0x1302)
    {
        LOG_CTX_INFO(ctx_, "{} selected tls_aes_256_gcm_sha384 0x1302", mux::log_event::kCert);
        negotiated_cipher = EVP_aes_256_gcm();
        negotiated_md = EVP_sha384();
        key_len = 32;
    }
    else if (cipher_suite == 0x1303)
    {
        LOG_CTX_INFO(ctx_, "{} selected tls_chacha20_poly1305_sha256 0x1303", mux::log_event::kCert);
        negotiated_cipher = EVP_chacha20_poly1305();
        negotiated_md = EVP_sha256();
        key_len = 32;
    }
    else
    {
        LOG_CTX_ERROR(ctx_, "{} unsupported cipher suite 0x{:04x}", mux::log_event::kCert, cipher_suite);
        return asio::error::no_protocol_option;
    }

    trans_.set_protocol_hash(negotiated_md);

    auto server_pub = extract_server_public_key(sh_real);
    std::error_code ec;
    auto shared = crypto_util::x25519_derive(std::vector<std::uint8_t>(client_private_, client_private_ + 32), server_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} x25519 derive failed", mux::log_event::kCert);
        return ec;
    }

    auto hs_keys = tls_key_schedule::derive_handshake_keys(shared, trans_.finish(), negotiated_md, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} derive keys failed", mux::log_event::kCert);
        return ec;
    }

    auto s_hs_keys = tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, negotiated_md);

    negotiated_cipher_ = negotiated_cipher;
    dec_key_ = s_hs_keys.first;
    dec_iv_ = s_hs_keys.second;

    return std::error_code{};
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

asio::awaitable<std::pair<std::uint8_t, std::span<std::uint8_t>>> cert_fetcher::fetch_session::read_record(std::vector<std::uint8_t>& pt_buf,
                                                                                                           std::error_code& out_ec)
{
    std::uint8_t head[5];
    auto [ec, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        out_ec = ec;
        co_return std::make_pair(0, std::span<std::uint8_t>{});
    }

    const std::uint16_t len = (head[3] << 8) | head[4];

    if (len > 18432)
    {
        out_ec = std::make_error_code(std::errc::message_size);
        co_return std::make_pair(0, std::span<std::uint8_t>{});
    }

    std::vector<std::uint8_t> rec(len);
    auto [ec2, n2] = co_await asio::async_read(socket_, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
    if (ec2)
    {
        out_ec = ec2;
        co_return std::make_pair(0, std::span<std::uint8_t>{});
    }

    if (head[0] == kContentTypeChangeCipherSpec)
    {
        if (pt_buf.size() < len)
        {
            pt_buf.resize(len);
        }
        std::memcpy(pt_buf.data(), rec.data(), len);
        co_return std::make_pair(kContentTypeChangeCipherSpec, std::span<std::uint8_t>(pt_buf.data(), len));
    }

    if (head[0] == kContentTypeApplicationData)
    {
        std::vector<std::uint8_t> cth(5 + len);
        std::memcpy(cth.data(), head, 5);
        std::memcpy(cth.data() + 5, rec.data(), len);

        std::uint8_t type;
        const std::uint32_t pt_len =
            tls_record_layer::decrypt_record(decrypt_ctx_, negotiated_cipher_, dec_key_, dec_iv_, seq_++, cth, pt_buf, type, out_ec);

        if (out_ec)
        {
            co_return std::make_pair(0, std::span<std::uint8_t>{});
        }
        co_return std::make_pair(type, std::span<std::uint8_t>(pt_buf.data(), pt_len));
    }

    if (head[0] == kContentTypeAlert)
    {
        LOG_CTX_WARN(ctx_, "{} received plaintext alert", mux::log_event::kCert);
        out_ec = asio::error::connection_reset;
        co_return std::make_pair(0, std::span<std::uint8_t>{});
    }

    out_ec = asio::error::invalid_argument;
    co_return std::make_pair(0, std::span<std::uint8_t>{});
}

}    // namespace reality
