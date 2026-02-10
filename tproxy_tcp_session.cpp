#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/buffer.hpp>
#include <asio/write.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "router.h"
#include "upstream.h"
#include "statistics.h"
#include "log_context.h"
#include "tproxy_tcp_session.h"

namespace mux
{

tproxy_tcp_session::tproxy_tcp_session(asio::ip::tcp::socket socket,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       std::shared_ptr<router> router,
                                       const std::uint32_t sid,
                                       const config& cfg,
                                       const asio::ip::tcp::endpoint& dst_ep)
    : socket_(std::move(socket)),
      idle_timer_(socket_.get_executor()),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      dst_ep_(dst_ep),
      timeout_config_(cfg.timeout),
      mark_(cfg.tproxy.mark)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ = std::chrono::steady_clock::now();
}

void tproxy_tcp_session::start()
{
    const auto self = shared_from_this();
    asio::co_spawn(socket_.get_executor(), [self]() -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
}

asio::awaitable<void> tproxy_tcp_session::run()
{
    const auto host = dst_ep_.address().to_string();
    const auto port = dst_ep_.port();
    const auto route = co_await router_->decide_ip(ctx_, host, dst_ep_.address(), socket_.get_executor());

    std::unique_ptr<upstream> backend = nullptr;

    if (route == route_type::direct)
    {
        backend = std::make_unique<direct_upstream>(socket_.get_executor(), ctx_, mark_);
    }
    else if (route == route_type::proxy)
    {
        const auto tunnel = tunnel_pool_->select_tunnel();
        if (tunnel == nullptr)
        {
            LOG_CTX_WARN(ctx_, "{} no active tunnel", log_event::kRoute);
            co_return;
        }
        backend = std::make_unique<proxy_upstream>(tunnel, ctx_);
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, host);
        statistics::instance().inc_routing_blocked();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connecting {} {} via {}", log_event::kConnInit, host, port, (route == route_type::direct ? "direct" : "proxy"));
    if (!co_await backend->connect(host, port))
    {
        LOG_CTX_WARN(ctx_, "{} connect failed {} {} via {}", log_event::kConnInit, host, port, (route == route_type::direct ? "direct" : "proxy"));
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, host, port, (route == route_type::direct ? "direct" : "proxy"));

    asio::co_spawn(socket_.get_executor(),
                   [self = shared_from_this(), backend = backend.get()]() -> asio::awaitable<void> { co_await self->idle_watchdog(backend); },
                   asio::detached);

    using asio::experimental::awaitable_operators::operator&&;
    co_await (client_to_upstream(backend.get()) && upstream_to_client(backend.get()));
    co_await backend->close();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

asio::awaitable<void> tproxy_tcp_session::client_to_upstream(upstream* backend)
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
        last_activity_time_ = std::chrono::steady_clock::now();
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::kSocks);
}

asio::awaitable<void> tproxy_tcp_session::upstream_to_client(upstream* backend)
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
        last_activity_time_ = std::chrono::steady_clock::now();
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::kSocks);
    std::error_code ignore;
    ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    if (ignore)
    {
        LOG_CTX_WARN(ctx_, "{} failed to shutdown client {}", log_event::kSocks, ignore.message());
    }
}

asio::awaitable<void> tproxy_tcp_session::idle_watchdog(upstream* backend)
{
    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - last_activity_time_ > std::chrono::seconds(timeout_config_.idle))
        {
            LOG_CTX_WARN(ctx_, "{} tcp session idle closing", log_event::kSocks);
            if (backend != nullptr)
            {
                co_await backend->close();
            }
            std::error_code ignore;
            ignore = socket_.close(ignore);
            break;
        }
    }
}

}    // namespace mux
