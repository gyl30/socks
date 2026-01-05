#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <memory>
#include <string>
#include "mux_tunnel.h"
#include "mux_protocol.h"
#include "protocol.h"
#include "log.h"

namespace mux
{

class LocalSession : public std::enable_shared_from_this<LocalSession>
{
   public:
    LocalSession(boost::asio::ip::tcp::socket socket, std::shared_ptr<MuxTunnel> tunnel) : socket_(std::move(socket)), tunnel_(tunnel)
    {
        socket_.set_option(boost::asio::ip::tcp::no_delay(true));
    }

    boost::asio::awaitable<void> start()
    {
        auto self = shared_from_this();
        try
        {
            co_await handshake();
            auto [cmd, addr, port] = co_await read_request();
            co_await connect_remote(cmd, addr, port);
        }
        catch (const std::exception& e)
        {
            LOG_WARN("local session error: {}", e.what());
        }
    }

   private:
    boost::asio::awaitable<void> handshake()
    {
        std::uint8_t version;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::use_awaitable);
        if (version != socks::VER)
            throw std::runtime_error("invalid socks version");

        std::uint8_t nmethods;
        co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::use_awaitable);

        std::vector<std::uint8_t> methods(nmethods);
        co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::use_awaitable);

        const std::uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
    }

    boost::asio::awaitable<std::tuple<std::uint8_t, std::string, std::uint16_t>> read_request()
    {
        std::uint8_t head[4];
        co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::use_awaitable);

        std::uint8_t cmd = head[1];
        std::string host;
        std::uint16_t port;

        if (head[3] == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type bytes;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
            host = boost::asio::ip::address_v4(bytes).to_string();
        }
        else if (head[3] == socks::ATYP_DOMAIN)
        {
            std::uint8_t len;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::use_awaitable);
            host.resize(len);
            co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::use_awaitable);
        }
        else if (head[3] == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
            host = boost::asio::ip::address_v6(bytes).to_string();
        }
        else
        {
            throw std::runtime_error("unsupported address type");
        }

        co_await boost::asio::async_read(socket_, boost::asio::buffer(&port, 2), boost::asio::use_awaitable);
        port = ntohs(port);

        co_return std::make_tuple(cmd, host, port);
    }

    boost::asio::awaitable<void> connect_remote(std::uint8_t cmd, const std::string& host, std::uint16_t port)
    {
        auto stream = tunnel_->create_stream();
        LOG_INFO("creating stream {} for target {}:{}", stream->get_id(), host, port);

        mux::syn_payload syn;
        syn.socks_cmd = cmd;
        syn.addr = host;
        syn.port = port;
        auto syn_buf = syn.encode();

        {
            mux::frame_header h;
            h.stream_id = stream->get_id();
            h.length = static_cast<std::uint16_t>(syn_buf.size());
            h.command = mux::CMD_SYN;
            co_await tunnel_->send_frame(h, std::move(syn_buf));
        }

        auto ack_buf = co_await stream->async_read_some();
        if (ack_buf.empty())
        {
            co_return;
        }

        auto ack = mux::ack_payload::decode(ack_buf.data(), ack_buf.size());
        if (ack.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("remote refused stream {}: rep={}", stream->get_id(), ack.socks_rep);
            co_await reply_browser(ack.socks_rep, "0.0.0.0", 0);
            co_return;
        }

        co_await reply_browser(socks::REP_SUCCESS, "0.0.0.0", 0);

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (transfer_socket_to_stream(stream) && transfer_stream_to_socket(stream));
    }

    boost::asio::awaitable<void> reply_browser(std::uint8_t rep, std::string bound_ip, std::uint16_t bound_port)
    {
        std::vector<std::uint8_t> resp = {socks::VER, rep, 0x00, socks::ATYP_IPV4};
        resp.push_back(0);
        resp.push_back(0);
        resp.push_back(0);
        resp.push_back(0);
        std::uint16_t p = htons(bound_port);
        const std::uint8_t* pp = reinterpret_cast<const std::uint8_t*>(&p);
        resp.push_back(pp[0]);
        resp.push_back(pp[1]);
        co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::use_awaitable);
    }

    boost::asio::awaitable<void> transfer_socket_to_stream(std::shared_ptr<MuxStream> stream)
    {
        try
        {
            while (true)
            {
                std::vector<std::uint8_t> data(16384);

                std::size_t n = co_await socket_.async_read_some(boost::asio::buffer(data), boost::asio::use_awaitable);

                data.resize(n);
                co_await stream->send_data(std::move(data));
            }
        }
        catch (...)
        {
            co_await stream->close();
        }
    }

    boost::asio::awaitable<void> transfer_stream_to_socket(std::shared_ptr<MuxStream> stream)
    {
        try
        {
            while (true)
            {
                auto payload = co_await stream->async_read_some();
                if (payload.empty())
                    break;
                co_await boost::asio::async_write(socket_, boost::asio::buffer(payload), boost::asio::use_awaitable);
            }
        }
        catch (...)
        {
            socket_.close();
        }
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<MuxTunnel> tunnel_;
};

class LocalClient
{
   public:
    LocalClient(boost::asio::io_context& ctx, const std::string& remote_host, const std::string& remote_port, std::uint16_t local_port)
        : ctx_(ctx), remote_host_(remote_host), remote_port_(remote_port), local_port_(local_port), acceptor_(ctx)
    {
    }

    void start() { boost::asio::co_spawn(ctx_, run(), boost::asio::detached); }

   private:
    boost::asio::awaitable<void> run()
    {
        boost::asio::ip::tcp::resolver resolver(ctx_);
        auto endpoints = co_await resolver.async_resolve(remote_host_, remote_port_, boost::asio::use_awaitable);

        boost::asio::ip::tcp::socket socket(ctx_);
        co_await boost::asio::async_connect(socket, endpoints, boost::asio::use_awaitable);

        tunnel_ = std::make_shared<MuxTunnel>(std::move(socket));
        boost::asio::co_spawn(ctx_, tunnel_->run(), boost::asio::detached);

        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), local_port_);
        acceptor_.open(ep.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(ep);
        acceptor_.listen();

        LOG_INFO("local client listening on {}", local_port_);

        while (true)
        {
            auto peer = co_await acceptor_.async_accept(boost::asio::use_awaitable);
            auto session = std::make_shared<LocalSession>(std::move(peer), tunnel_);
            boost::asio::co_spawn(ctx_, [session]() { return session->start(); }, boost::asio::detached);
        }
    }

    boost::asio::io_context& ctx_;
    std::string remote_host_;
    std::string remote_port_;
    std::uint16_t local_port_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<MuxTunnel> tunnel_;
};

}    // namespace mux

#endif
