#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "router.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "tcp_socks_session.h"

namespace mux
{

tcp_socks_session::tcp_socks_session(asio::ip::tcp::socket socket,
                                     std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                                     std::shared_ptr<router> router,
                                     const std::uint32_t sid)
    : socket_(std::move(socket)), router_(std::move(router)), tunnel_manager_(std::move(tunnel_manager))
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
}

void tcp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    const auto self = shared_from_this();
    asio::co_spawn(socket_.get_executor(), [self, host, port]() -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
}

asio::awaitable<void> tcp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    const auto route = co_await router_->decide(ctx_, host, socket_.get_executor());

    std::unique_ptr<upstream> backend = nullptr;

    if (route == route_type::direct)
    {
        backend = std::make_unique<direct_upstream>(socket_.get_executor(), ctx_);
    }
    else if (route == route_type::proxy)
    {
        backend = std::make_unique<proxy_upstream>(tunnel_manager_, ctx_);
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, host);
        co_await reply_error(socks::kRepNotAllowed);
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connecting {} {} via {}", log_event::kConnInit, host, port, (route == route_type::direct ? "direct" : "proxy"));
    if (!co_await backend->connect(host, port))
    {
        LOG_CTX_WARN(ctx_, "{} connect failed {} {} via {}", log_event::kConnInit, host, port, (route == route_type::direct ? "direct" : "proxy"));
        co_await reply_error(socks::kRepHostUnreach);
        co_return;
    }

    std::uint8_t rep[] = {socks::kVer, socks::kRepSuccess, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(rep), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_CTX_WARN(ctx_, "{} write to client failed {}", log_event::kDataSend, we.message());
        co_await backend->close();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, host, port, (route == route_type::direct ? "direct" : "proxy"));
    using asio::experimental::awaitable_operators::operator&&;
    co_await (client_to_upstream(backend.get()) && upstream_to_client(backend.get()));
    co_await backend->close();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

asio::awaitable<void> tcp_socks_session::reply_error(const std::uint8_t code)
{
    std::uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    (void)co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<void> tcp_socks_session::client_to_upstream(upstream* backend)
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        std::error_code ec;
        const std::uint32_t n = co_await socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from client {}", log_event::kSocks, ec.message());
            break;
        }

        const std::vector<std::uint8_t> chunk(buf.begin(), buf.begin() + n);
        const auto written = co_await backend->write(chunk);
        if (written == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to backend", log_event::kSocks);
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::kSocks);
}

asio::awaitable<void> tcp_socks_session::upstream_to_client(upstream* backend)
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        const auto [ec, n] = co_await backend->read(buf);
        if (ec || n == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from backend {}", log_event::kSocks, ec.message());
            break;
        }

        const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(buf.data(), n), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to client {}", log_event::kSocks, we.message());
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::kSocks);
    std::error_code ignore;
    ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    if (ignore)
    {
        LOG_CTX_WARN(ctx_, "{} failed to shutdown client {}", log_event::kSocks, ignore.message());
    }
}

}    // namespace mux
