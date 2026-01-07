#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <vector>
#include "reality_core.h"
#include "mux_tunnel.h"
#include "log.h"
#include "prefixed_stream.h"
#include "context_pool.h"

namespace mux
{

struct ClientHelloData
{
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> random;
    std::vector<uint8_t> x25519_pub;
    bool is_tls13 = false;
};

class CHParser
{
   public:
    static ClientHelloData parse(const std::vector<uint8_t>& buf)
    {
        ClientHelloData info;
        if (buf.size() < 44)
            return info;
        if (buf[0] != 22)
            return info;

        const uint8_t* p = buf.data() + 5;
        if (p[0] != 1)
            return info;

        info.random.assign(p + 6, p + 38);

        uint8_t sid_len = p[38];
        if (sid_len != 32)
            return info;
        info.session_id.assign(p + 39, p + 39 + 32);

        size_t offset = 5 + 39 + sid_len;
        if (offset + 2 > buf.size())
            return info;
        uint16_t cs_len = (buf[offset] << 8) | buf[offset + 1];
        offset += 2 + cs_len;

        if (offset + 1 > buf.size())
            return info;
        uint8_t comp_len = buf[offset];
        offset += 1 + comp_len;

        if (offset + 2 > buf.size())
            return info;
        uint16_t ext_len = (buf[offset] << 8) | buf[offset + 1];
        offset += 2;

        size_t end = offset + ext_len;
        if (end > buf.size())
            return info;

        while (offset + 4 <= end)
        {
            uint16_t etype = (buf[offset] << 8) | buf[offset + 1];
            uint16_t elen = (buf[offset + 2] << 8) | buf[offset + 3];
            offset += 4;

            if (etype == 51)
            {
                size_t kp = offset + 2;
                while (kp + 4 <= offset + elen)
                {
                    uint16_t group = (buf[kp] << 8) | buf[kp + 1];
                    uint16_t klen = (buf[kp + 2] << 8) | buf[kp + 3];
                    kp += 4;
                    if (group == 0x001d && klen == 32)
                    {
                        info.x25519_pub.assign(buf.data() + kp, buf.data() + kp + 32);
                        info.is_tls13 = true;
                        break;
                    }
                    kp += klen;
                }
            }
            offset += elen;
        }
        return info;
    }
};

class remote_session : public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_tunnel_interface> tunnel, uint32_t id, boost::asio::any_io_executor ex)
        : tunnel_(tunnel), executor_(ex), resolver_(ex)
    {
    }

    boost::asio::awaitable<void> start(std::vector<uint8_t> syn_data) { co_return; }

   private:
    std::shared_ptr<mux_tunnel_interface> tunnel_;
    boost::asio::any_io_executor executor_;
    boost::asio::ip::tcp::resolver resolver_;
};

class remote_server
{
   public:
    remote_server(io_context_pool& pool, uint16_t port, std::string fb_host, std::string fb_port, std::string auth_key_hex)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fallback_host_(std::move(fb_host)),
          fallback_port_(std::move(fb_port)),
          ssl_ctx_(boost::asio::ssl::context::tlsv13_server)
    {
        server_private_key_ = reality::CryptoUtil::hex_to_bytes(auth_key_hex);

        LOG_INFO("Scraping certificate from {}:{}", fallback_host_, fallback_port_);
        if (cert_manager_.fetch_real_cert(fallback_host_, fallback_port_))
        {
            cert_manager_.generate_reality_cert(server_private_key_);
            LOG_INFO("REALITY Certificate Ready.");
        }
        else
        {
            LOG_ERROR("Failed to fetch REALITY cert!");
        }

        SSL_CTX_set_min_proto_version(ssl_ctx_.native_handle(), TLS1_3_VERSION);
        const uint8_t alpn[] = "\x02h2\x08http/1.1";
        SSL_CTX_set_alpn_protos(ssl_ctx_.native_handle(), alpn, sizeof(alpn) - 1);
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

   private:
    boost::asio::awaitable<void> accept_loop()
    {
        while (true)
        {
            auto sock = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [ec] = co_await acceptor_.async_accept(*sock, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec)
            {
                boost::asio::co_spawn(
                    pool_.get_io_context(), [this, sock]() mutable { return handle_connection(sock); }, boost::asio::detached);
            }
        }
    }

    boost::asio::awaitable<void> handle_connection(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        std::vector<uint8_t> buffer(4096);
        auto [ec, n] = co_await socket->async_read_some(boost::asio::buffer(buffer), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
            co_return;
        buffer.resize(n);

        auto info = CHParser::parse(buffer);
        bool authorized = false;

        if (info.is_tls13 && !info.x25519_pub.empty())
        {
            auto shared = reality::CryptoUtil::x25519_derive(server_private_key_, info.x25519_pub);
            if (!shared.empty())
            {
                std::vector<uint8_t> salt(info.random.begin(), info.random.begin() + 20);
                std::vector<uint8_t> info_str(reality::K_REALITY_INFO, reality::K_REALITY_INFO + 7);

                uint8_t aead_key[32];
                HKDF(aead_key, 32, EVP_sha256(), shared.data(), 32, salt.data(), salt.size(), info_str.data(), info_str.size());

                std::vector<uint8_t> key_vec(aead_key, aead_key + 32);
                std::vector<uint8_t> nonce(info.random.begin() + 20, info.random.end());
                std::vector<uint8_t> aad(buffer.begin() + 5, buffer.end());

                auto plaintext = reality::CryptoUtil::aes_gcm_decrypt(key_vec, nonce, info.session_id, aad);
                if (!plaintext.empty())
                {
                    authorized = true;
                    LOG_INFO("REALITY Auth Success!");
                }
            }
        }

        if (authorized)
        {
            co_await handle_hijack(socket, buffer);
        }
        else
        {
            co_await handle_fallback(socket, buffer);
        }
    }

    boost::asio::awaitable<void> handle_hijack(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::vector<uint8_t> prefix)
    {
        PrefixedStream<boost::asio::ip::tcp::socket> p_stream(std::move(*socket), std::move(prefix));
        auto ssl_stream = std::make_shared<boost::asio::ssl::stream<PrefixedStream<boost::asio::ip::tcp::socket>>>(std::move(p_stream), ssl_ctx_);

        cert_manager_.apply_to_ssl(ssl_stream->native_handle());

        auto [ec] = co_await ssl_stream->async_handshake(boost::asio::ssl::stream_base::server, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("Handshake failed: {}", ec.message());
            co_return;
        }

        auto tunnel = std::make_shared<mux_tunnel_impl<PrefixedStream<boost::asio::ip::tcp::socket>>>(std::move(*ssl_stream));
        tunnel->set_syn_handler(
            [this, tunnel](uint32_t id, std::vector<uint8_t> p) -> boost::asio::awaitable<void>
            {
                auto& session_ctx = pool_.get_io_context();
                auto session = std::make_shared<remote_session>(tunnel, id, session_ctx.get_executor());
                boost::asio::co_spawn(
                    session_ctx, [session, p = std::move(p)]() mutable { return session->start(std::move(p)); }, boost::asio::detached);
                co_return;
            });
        co_await tunnel->run();
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> client, std::vector<uint8_t> prefix)
    {
        LOG_DEBUG("Fallback to {}:{}", fallback_host_, fallback_port_);
        boost::asio::ip::tcp::socket target(client->get_executor());
        boost::asio::ip::tcp::resolver res(client->get_executor());
        auto [ec, eps] = co_await res.async_resolve(fallback_host_, fallback_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec)
        {
            auto [ec2, ep] = co_await boost::asio::async_connect(target, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec2)
            {
                co_await boost::asio::async_write(target, boost::asio::buffer(prefix), boost::asio::as_tuple(boost::asio::use_awaitable));
                auto transfer = [](boost::asio::ip::tcp::socket& from, boost::asio::ip::tcp::socket& to) -> boost::asio::awaitable<void>
                {
                    std::array<char, 8192> data;
                    while (true)
                    {
                        auto [e, n] = co_await from.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
                        if (e)
                            break;
                        co_await boost::asio::async_write(to, boost::asio::buffer(data, n), boost::asio::as_tuple(boost::asio::use_awaitable));
                    }
                };
                using boost::asio::experimental::awaitable_operators::operator||;
                co_await (transfer(*client, target) || transfer(target, *client));
            }
        }
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fallback_host_, fallback_port_;
    std::vector<uint8_t> server_private_key_;
    reality::CertManager cert_manager_;
    boost::asio::ssl::context ssl_ctx_;
};

}    // namespace mux

#endif
