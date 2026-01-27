#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include <memory>
#include <asio.hpp>
#include "log.h"
#include "router.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"

namespace mux
{

class router;

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(asio::ip::tcp::socket socket,
                  std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                  std::shared_ptr<router> router,
                  uint32_t sid)
        : sid_(sid), socket_(std::move(socket)), router_(std::move(router)), tunnel_manager_(std::move(tunnel_manager))
    {
    }

    void start()
    {
        auto self = shared_from_this();
        asio::co_spawn(socket_.get_executor(), [self]() mutable -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
    }

   private:
    asio::awaitable<void> run()
    {
        if (!co_await handshake())
        {
            LOG_WARN("socks session {} handshake failed", sid_);
            co_return;
        }

        auto [ok, host, port, cmd] = co_await read_request();
        if (!ok)
        {
            LOG_WARN("socks session {} request invalid", sid_);
            co_return;
        }

        if (cmd == socks::CMD_CONNECT)
        {
            auto tcp_sess = std::make_shared<tcp_socks_session>(std::move(socket_), tunnel_manager_, router_, sid_);
            tcp_sess->start(host, port);
        }
        else if (cmd == socks::CMD_UDP_ASSOCIATE)
        {
            auto udp_sess = std::make_shared<udp_socks_session>(std::move(socket_), tunnel_manager_, sid_);
            udp_sess->start(host, port);
        }
        else
        {
            LOG_WARN("socks session {} cmd {} unsupported", sid_, cmd);
        }
    }

    asio::awaitable<bool> handshake()
    {
        uint8_t ver_nmethods[2];
        auto [e, n] = co_await asio::async_read(socket_, asio::buffer(ver_nmethods, 2), asio::as_tuple(asio::use_awaitable));
        if (e || ver_nmethods[0] != socks::VER)
        {
            LOG_ERROR("socks session {} handshake failed", sid_);
            co_return false;
        }

        std::vector<uint8_t> methods(ver_nmethods[1]);
        auto [method_error, n2] = co_await asio::async_read(socket_, asio::buffer(methods), asio::as_tuple(asio::use_awaitable));
        if (method_error)
        {
            LOG_ERROR("socks methods read failed {}", method_error.message());
            co_return false;
        }

        uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [response_error, n3] = co_await asio::async_write(socket_, asio::buffer(resp), asio::as_tuple(asio::use_awaitable));
        if (response_error)
        {
            LOG_ERROR("socks session {} handshake failed {}", sid_, response_error.message());
        }
        co_return !response_error;
    }

    struct request_info
    {
        bool ok;
        std::string host;
        uint16_t port;
        uint8_t cmd;
    };

    asio::awaitable<request_info> read_request()
    {
        uint8_t head[4];
        auto [e, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            LOG_ERROR("socks session {} request read failed {}", sid_, e.message());
            co_return request_info{.ok = false, .host = "", .port = 0, .cmd = 0};
        }

        std::string host;
        if (head[3] == socks::ATYP_IPV4)
        {
            asio::ip::address_v4::bytes_type b;
            co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
            host = asio::ip::address_v4(b).to_string();
        }
        else if (head[3] == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            co_await asio::async_read(socket_, asio::buffer(&len, 1), asio::as_tuple(asio::use_awaitable));
            host.resize(len);
            co_await asio::async_read(socket_, asio::buffer(host), asio::as_tuple(asio::use_awaitable));
        }
        else if (head[3] == socks::ATYP_IPV6)
        {
            asio::ip::address_v6::bytes_type b;
            co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
            host = asio::ip::address_v6(b).to_string();
        }

        uint16_t port_n;
        co_await asio::async_read(socket_, asio::buffer(&port_n, 2), asio::as_tuple(asio::use_awaitable));
        LOG_INFO("socks session {} request {} {}", sid_, host, ntohs(port_n));
        co_return request_info{.ok = true, .host = host, .port = ntohs(port_n), .cmd = head[1]};
    }

   private:
    uint32_t sid_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
