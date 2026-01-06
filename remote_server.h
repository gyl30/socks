#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/as_tuple.hpp>
#include <memory>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include "mux_tunnel.h"
#include "mux_protocol.h"
#include "context_pool.h"
#include "log.h"
#include "tls_parser.h"
#include "prefixed_stream.h"
#include "reality_core.h"

namespace mux
{

class remote_session : public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_tunnel_interface> tunnel, std::uint32_t stream_id, boost::asio::any_io_executor ex)
        : tunnel_(tunnel), stream_id_(stream_id), executor_(ex), resolver_(ex)
    {
    }

    [[nodiscard]] boost::asio::awaitable<void> start(std::vector<std::uint8_t> syn_data)
    {
        SynPayload req;
        if (!SynPayload::decode(syn_data.data(), syn_data.size(), req))
            co_return;

        LOG_INFO("session {} req cmd {} target {}:{}", stream_id_, req.socks_cmd, req.addr, req.port);

        stream_ = tunnel_->accept_stream(stream_id_);
        if (stream_ == nullptr)
            co_return;

        if (req.socks_cmd == 0x01)
            co_await do_connect(req.addr, req.port);
        else if (req.socks_cmd == 0x03)
            co_await do_udp_associate(req.addr, req.port);
        else
        {
            co_await send_ack(0x07, "0.0.0.0", 0);
            co_await stream_->close();
        }
    }

   private:
    [[nodiscard]] boost::asio::awaitable<void> do_connect(const std::string& host, std::uint16_t port)
    {
        auto tcp_socket = std::make_shared<boost::asio::ip::tcp::socket>(executor_);
        bool connected = false;

        auto [ec, eps] = co_await resolver_.async_resolve(host, std::to_string(port), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec)
        {
            auto [ec2, ep] = co_await boost::asio::async_connect(*tcp_socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec2)
            {
                tcp_socket->set_option(boost::asio::ip::tcp::no_delay(true));
                connected = true;
            }
        }

        if (!connected)
        {
            co_await send_ack(0x04, "0.0.0.0", 0);
            co_await stream_->close();
            co_return;
        }

        auto local_ep = tcp_socket->local_endpoint();
        co_await send_ack(0x00, local_ep.address().to_string(), local_ep.port());

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer_tcp_to_stream(tcp_socket) || transfer_stream_to_tcp(tcp_socket));

        tcp_socket->close();
        co_await stream_->close();
    }

    [[nodiscard]] boost::asio::awaitable<void> send_ack(std::uint8_t rep, std::string addr, std::uint16_t port)
    {
        AckPayload ack{rep, addr, port};
        auto buf = ack.encode();
        FrameHeader h{stream_id_, static_cast<std::uint16_t>(buf.size()), CMD_ACK};
        co_await tunnel_->send_frame(h, std::move(buf));
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_tcp_to_stream(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    {
        std::vector<std::uint8_t> data(16384);
        while (true)
        {
            auto [ec, n] = co_await sock->async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                break;
            data.resize(n);
            if (auto e = co_await stream_->send_data(std::move(data)))
                break;
            data.resize(16384);
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_tcp(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    {
        while (true)
        {
            auto [ec, data] = co_await stream_->async_read_some();
            if (ec || data.empty())
                break;
            auto [e2, n] = co_await boost::asio::async_write(*sock, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
                break;
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> do_udp_associate(const std::string&, std::uint16_t)
    {
        auto udp_socket = std::make_shared<boost::asio::ip::udp::socket>(executor_, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
        co_await send_ack(0x00, "0.0.0.0", udp_socket->local_endpoint().port());
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer_udp_to_stream(udp_socket) || transfer_stream_to_udp(udp_socket));
        udp_socket->close();
        co_await stream_->close();
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_udp(std::shared_ptr<boost::asio::ip::udp::socket> udp_sock)
    {
        while (true)
        {
            auto [ec, data] = co_await stream_->async_read_some();
            if (ec || data.empty())
                break;
            if (data.size() < 10 || data[2] != 0x00)
                continue;
            std::size_t header_len = 0;
            boost::asio::ip::udp::endpoint target;
            if (data[3] == 0x01)
            {
                boost::asio::ip::address_v4::bytes_type b;
                std::memcpy(b.data(), &data[4], 4);
                std::uint16_t p = 0;
                std::memcpy(&p, &data[8], 2);
                target = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(b), ntohs(p));
                header_len = 10;
            }
            else
                continue;
            auto [e2, n] = co_await udp_sock->async_send_to(
                boost::asio::buffer(data.data() + header_len, data.size() - header_len), target, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
                break;
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_udp_to_stream(std::shared_ptr<boost::asio::ip::udp::socket> udp_sock)
    {
        std::vector<std::uint8_t> buf(65536);
        boost::asio::ip::udp::endpoint sender;
        while (true)
        {
            auto [ec, len] =
                co_await udp_sock->async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                break;
            std::vector<std::uint8_t> packet;
            packet.reserve(len + 10);
            packet.push_back(0);
            packet.push_back(0);
            packet.push_back(0);
            packet.push_back(0x01);
            auto b = sender.address().to_v4().to_bytes();
            packet.insert(packet.end(), b.begin(), b.end());
            const std::uint16_t p = htons(sender.port());
            const auto* pp = reinterpret_cast<const std::uint8_t*>(&p);
            packet.push_back(pp[0]);
            packet.push_back(pp[1]);
            packet.insert(packet.end(), buf.begin(), buf.begin() + len);
            if (auto e = co_await stream_->send_data(std::move(packet)))
                break;
        }
    }

    std::shared_ptr<mux_tunnel_interface> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    std::uint32_t stream_id_;
    boost::asio::any_io_executor executor_;
    boost::asio::ip::tcp::resolver resolver_;
};

class remote_server
{
   public:
    remote_server(io_context_pool& pool, std::uint16_t port, std::string fallback_host, std::string fallback_port, std::string auth_key_hex)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          ssl_context_(boost::asio::ssl::context::tlsv13_server),
          fallback_host_(std::move(fallback_host)),
          fallback_port_(std::move(fallback_port))
    {
        for (unsigned int i = 0; i < auth_key_hex.length(); i += 2)
        {
            std::string byteString = auth_key_hex.substr(i, 2);
            auth_key_.push_back((uint8_t)strtol(byteString.c_str(), NULL, 16));
        }
    }

    void start()
    {
        boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached);
        LOG_INFO("remote server started (REALITY Mode)");
    }

   private:
    [[nodiscard]] boost::asio::awaitable<void> accept_loop()
    {
        while (true)
        {
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [ec] = co_await acceptor_.async_accept(*socket, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                continue;
            boost::asio::co_spawn(
                pool_.get_io_context(), [this, socket]() mutable { return handle_connection(socket); }, boost::asio::detached);
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> handle_connection(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        std::vector<uint8_t> buffer(4096);
        auto [ec, n] = co_await socket->async_read_some(boost::asio::buffer(buffer), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
            co_return;
        buffer.resize(n);

        bool hijack = false;
        auto info = reality::TlsParser::parse_client_hello(buffer);

        if (info && info->is_tls_handshake && info->session_id.size() == 32)
        {
            std::vector<uint8_t> plaintext = reality::CryptoUtil::aes_cfb_decrypt(auth_key_, info->session_id);
            if (plaintext.size() == 32)
            {
                uint64_t ts_net;
                std::memcpy(&ts_net, plaintext.data(), 8);
                uint64_t ts = __builtin_bswap64(ts_net);

                int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (std::abs((int64_t)ts - now) < 60)
                {
                    LOG_INFO("REALITY Auth Success");
                    hijack = true;
                }
            }
        }

        if (hijack)
        {
            co_await handle_hijack(socket, std::move(buffer));
        }
        else
        {
            co_await handle_fallback(socket, std::move(buffer));
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> handle_hijack(std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::vector<uint8_t> initial_data)
    {
        auto [cert, pkey] = reality::CryptoUtil::generate_ephemeral_cert();

        PrefixedStream<boost::asio::ip::tcp::socket> p_stream(std::move(*socket), std::move(initial_data));
        auto ssl_stream = std::make_shared<boost::asio::ssl::stream<PrefixedStream<boost::asio::ip::tcp::socket>>>(std::move(p_stream), ssl_context_);

        SSL* ssl = ssl_stream->native_handle();
        SSL_use_certificate(ssl, cert);
        SSL_use_PrivateKey(ssl, pkey);
        if (SSL_check_private_key(ssl) != 1)
        {
            LOG_ERROR("Cert check failed");
            X509_free(cert);
            EVP_PKEY_free(pkey);
            co_return;
        }

        auto [ec] = co_await ssl_stream->async_handshake(boost::asio::ssl::stream_base::server, boost::asio::as_tuple(boost::asio::use_awaitable));

        X509_free(cert);
        EVP_PKEY_free(pkey);

        if (ec)
        {
            LOG_WARN("ssl handshake failed {}", ec.message());
            co_return;
        }

        auto tunnel = std::make_shared<mux_tunnel_impl<PrefixedStream<boost::asio::ip::tcp::socket>>>(std::move(*ssl_stream));
        tunnel->set_syn_handler(
            [this, tunnel](std::uint32_t stream_id, std::vector<std::uint8_t> payload) -> boost::asio::awaitable<void>
            {
                auto& session_ctx = pool_.get_io_context();
                auto session = std::make_shared<remote_session>(tunnel, stream_id, session_ctx.get_executor());
                boost::asio::co_spawn(
                    session_ctx, [session, p = std::move(payload)]() mutable { return session->start(std::move(p)); }, boost::asio::detached);
                co_return;
            });

        co_await tunnel->run();
    }

    [[nodiscard]] boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> client_sock,
                                                               std::vector<uint8_t> initial_data)
    {
        LOG_INFO("REALITY: Fallback traffic");
        boost::asio::ip::tcp::socket dest_sock(client_sock->get_executor());
        boost::asio::ip::tcp::resolver resolver(client_sock->get_executor());

        auto [ec, eps] = co_await resolver.async_resolve(fallback_host_, fallback_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
            co_return;

        auto [ec2, ep] = co_await boost::asio::async_connect(dest_sock, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
            co_return;

        auto [ec3, n] =
            co_await boost::asio::async_write(dest_sock, boost::asio::buffer(initial_data), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
            co_return;

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer(*client_sock, dest_sock) || transfer(dest_sock, *client_sock));
    }

    boost::asio::awaitable<void> transfer(boost::asio::ip::tcp::socket& from, boost::asio::ip::tcp::socket& to)
    {
        std::array<char, 8192> data;
        while (true)
        {
            auto [ec, n] = co_await from.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                break;
            auto [ec2, n2] = co_await boost::asio::async_write(to, boost::asio::buffer(data, n), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
                break;
        }
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_context_;
    std::string fallback_host_;
    std::string fallback_port_;
    std::vector<uint8_t> auth_key_;
};

}    // namespace mux

#endif
