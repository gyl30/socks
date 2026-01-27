#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <memory>
#include <vector>
#include <asio.hpp>
#include "log.h"
#include "router.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_tunnel.h"

namespace mux
{

class tcp_socks_session : public std::enable_shared_from_this<tcp_socks_session>
{
   public:
    tcp_socks_session(asio::ip::tcp::socket socket,
                      std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                      std::shared_ptr<router> router,
                      uint32_t sid)
        : sid_(sid), socket_(std::move(socket)), router_(std::move(router)), tunnel_manager_(std::move(tunnel_manager))
    {
    }

    void start(const std::string& host, uint16_t port)
    {
        auto self = shared_from_this();
        asio::co_spawn(
            socket_.get_executor(), [self, host, port]() mutable -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
    }

   private:
    asio::awaitable<void> run(std::string host, uint16_t port)
    {
        auto route = co_await router_->decide(host, socket_.get_executor());

        std::unique_ptr<upstream> backend;

        if (route == route_type::direct)
        {
            backend = std::make_unique<direct_upstream>(socket_.get_executor());
        }
        else if (route == route_type::proxy)
        {
            backend = std::make_unique<proxy_upstream>(tunnel_manager_);
        }
        else
        {
            LOG_WARN("{} blocked host {}", sid_, host);
            co_await reply_error(socks::REP_NOT_ALLOWED);
            co_return;
        }

        LOG_INFO("{} connecting to {}:{} via {}", sid_, host, port, (route == route_type::direct ? "direct" : "proxy"));
        if (!co_await backend->connect(host, port))
        {
            LOG_WARN("{} failed to connect to {}:{} via {}", sid_, host, port, (route == route_type::direct ? "direct" : "proxy"));
            co_await reply_error(socks::REP_HOST_UNREACH);
            co_return;
        }

        uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(rep), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_WARN("{} failed to write to client: {}", sid_, we.message());
            co_await backend->close();
            co_return;
        }

        LOG_INFO("{} connected to {}:{} via {}", sid_, host, port, (route == route_type::direct ? "direct" : "proxy"));
        using asio::experimental::awaitable_operators::operator&&;
        co_await (client_to_upstream(backend.get()) && upstream_to_client(backend.get()));
        co_await backend->close();
        LOG_INFO("{} finished", sid_);
    }

    asio::awaitable<void> reply_error(uint8_t code)
    {
        uint8_t err[] = {socks::VER, code, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
    }

    asio::awaitable<void> client_to_upstream(upstream* backend)
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            std::error_code ec;
            uint32_t n = co_await socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
            if (ec || n == 0)
            {
                LOG_WARN("{} failed to read from client {}", sid_, ec.message());
                break;
            }

            std::vector<uint8_t> chunk(buf.begin(), buf.begin() + n);
            auto written = co_await backend->write(chunk);
            if (written == 0)
            {
                LOG_WARN("{} failed to write to backend", sid_);
                break;
            }
        }
        LOG_INFO("{} client to upstream finished", sid_);
    }

    asio::awaitable<void> upstream_to_client(upstream* backend)
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            auto [ec, n] = co_await backend->read(buf);
            if (ec || n == 0)
            {
                LOG_WARN("{} failed to read from backend {}", sid_, ec.message());
                break;
            }

            auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(buf.data(), n), asio::as_tuple(asio::use_awaitable));
            if (we)
            {
                LOG_WARN("{} failed to write to client {}", sid_, we.message());
                break;
            }
        }
        LOG_INFO("{} upstream to client finished", sid_);
        std::error_code ignore;
        ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
        if (ignore)
        {
            LOG_WARN("{} failed to shutdown client {}", sid_, ignore.message());
        }
    }

   private:
    uint32_t sid_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
