#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/experimental/channel_error.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "router.h"
#include "upstream.h"
#include "statistics.h"
#include "log_context.h"
#include "tproxy_tcp_session.h"

namespace mux
{

namespace
{

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] bool is_expected_shutdown_error(const std::error_code& ec)
{
    return ec == asio::error::not_connected || ec == asio::error::bad_descriptor;
}

[[nodiscard]] bool is_expected_client_read_error(const std::error_code& ec)
{
    return ec == asio::error::eof || ec == asio::error::operation_aborted || ec == asio::error::bad_descriptor;
}

[[nodiscard]] bool is_expected_backend_read_error(const std::error_code& ec)
{
    return ec == asio::error::eof || ec == asio::error::operation_aborted || ec == asio::experimental::error::channel_closed;
}

[[nodiscard]] const char* route_name(const route_type route)
{
    return route == route_type::kDirect ? "direct" : "proxy";
}

}    // namespace

tproxy_tcp_session::tproxy_tcp_session(asio::ip::tcp::socket socket,
                                       asio::io_context& io_context,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       std::shared_ptr<router> router,
                                       const std::uint32_t sid,
                                       const config& cfg,
                                       const asio::ip::tcp::endpoint& dst_ep)
    : io_context_(io_context),
      socket_(std::move(socket)),
      idle_timer_(io_context_),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      dst_ep_(dst_ep),
      timeout_config_(cfg.timeout),
      mark_(cfg.tproxy.mark)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_.store(now_ms(), std::memory_order_release);
}

void tproxy_tcp_session::start()
{
    const auto self = shared_from_this();
    asio::co_spawn(io_context_, [self]() -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
}

asio::awaitable<void> tproxy_tcp_session::run()
{
    const auto host = dst_ep_.address().to_string();
    const auto port = dst_ep_.port();
    const auto [route, backend] = co_await select_backend(host);
    if (backend == nullptr)
    {
        co_return;
    }

    if (!co_await connect_backend(backend, host, port, route))
    {
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, host, port, route_name(route));
    start_idle_watchdog(backend);

    using asio::experimental::awaitable_operators::operator&&;
    co_await (client_to_upstream(backend) && upstream_to_client(backend));
    co_await close_backend_once(backend);
    close_client_socket();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> tproxy_tcp_session::select_backend(const std::string& host)
{
    const auto route = co_await router_->decide_ip(ctx_, host, dst_ep_.address());
    if (route == route_type::kDirect)
    {
        const std::shared_ptr<upstream> backend = std::make_shared<direct_upstream>(io_context_, ctx_, mark_);
        co_return std::make_pair(route, backend);
    }

    if (route == route_type::kProxy)
    {
        const auto tunnel = tunnel_pool_->select_tunnel();
        if (tunnel == nullptr)
        {
            LOG_CTX_WARN(ctx_, "{} no active tunnel", log_event::kRoute);
            co_return std::make_pair(route, std::shared_ptr<upstream>(nullptr));
        }

        const std::shared_ptr<upstream> backend = std::make_shared<proxy_upstream>(tunnel, ctx_);
        co_return std::make_pair(route, backend);
    }

    LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, host);
    statistics::instance().inc_routing_blocked();
    co_return std::make_pair(route, std::shared_ptr<upstream>(nullptr));
}

asio::awaitable<bool> tproxy_tcp_session::connect_backend(const std::shared_ptr<upstream>& backend,
                                                          const std::string& host,
                                                          const std::uint16_t port,
                                                          const route_type route)
{
    LOG_CTX_INFO(ctx_, "{} connecting {} {} via {}", log_event::kConnInit, host, port, route_name(route));
    if (co_await backend->connect(host, port))
    {
        co_return true;
    }

    LOG_CTX_WARN(ctx_, "{} connect failed {} {} via {}", log_event::kConnInit, host, port, route_name(route));
    co_return false;
}

void tproxy_tcp_session::start_idle_watchdog(const std::shared_ptr<upstream>& backend)
{
    asio::co_spawn(
        io_context_,
        [self = shared_from_this(), backend]() -> asio::awaitable<void> { co_await self->idle_watchdog(backend); },
        asio::detached);
}

void tproxy_tcp_session::close_client_socket()
{
    std::error_code ec;
    idle_timer_.cancel();
    ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && !is_expected_shutdown_error(ec))
    {
        LOG_CTX_WARN(ctx_, "{} shutdown client failed {}", log_event::kSocks, ec.message());
    }

    ec = socket_.close(ec);
    if (ec && ec != asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close client failed {}", log_event::kSocks, ec.message());
    }
}

asio::awaitable<void> tproxy_tcp_session::client_to_upstream(std::shared_ptr<upstream> backend)
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        std::error_code ec;
        const std::uint32_t n = co_await socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0)
        {
            if (!ec)
            {
                LOG_CTX_DEBUG(ctx_, "{} client closed connection", log_event::kSocks);
            }
            else if (is_expected_client_read_error(ec))
            {
                LOG_CTX_DEBUG(ctx_, "{} read from client stopped {}", log_event::kSocks, ec.message());
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} failed to read from client {}", log_event::kSocks, ec.message());
            }
            break;
        }

        const std::vector<std::uint8_t> chunk(buf.begin(), buf.begin() + n);
        const auto written = co_await backend->write(chunk);
        if (written == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to backend", log_event::kSocks);
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::kSocks);
}

asio::awaitable<void> tproxy_tcp_session::upstream_to_client(std::shared_ptr<upstream> backend)
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        const auto [ec, n] = co_await backend->read(buf);
        if (ec || n == 0)
        {
            if (!ec)
            {
                LOG_CTX_DEBUG(ctx_, "{} backend closed connection", log_event::kSocks);
            }
            else if (is_expected_backend_read_error(ec))
            {
                LOG_CTX_DEBUG(ctx_, "{} read from backend stopped {}", log_event::kSocks, ec.message());
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} failed to read from backend {}", log_event::kSocks, ec.message());
            }
            break;
        }

        const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(buf.data(), n), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to client {}", log_event::kSocks, we.message());
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::kSocks);
    std::error_code ignore;
    ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    if (ignore && !is_expected_shutdown_error(ignore))
    {
        LOG_CTX_WARN(ctx_, "{} failed to shutdown client {}", log_event::kSocks, ignore.message());
    }
}

asio::awaitable<void> tproxy_tcp_session::close_backend_once(const std::shared_ptr<upstream>& backend)
{
    if (backend == nullptr)
    {
        co_return;
    }

    bool expected = false;
    if (!backend_closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        co_return;
    }

    co_await backend->close();
}

asio::awaitable<void> tproxy_tcp_session::idle_watchdog(std::shared_ptr<upstream> backend)
{
    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto current_ms = now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_.load(std::memory_order_acquire);
        const auto idle_timeout_ms = static_cast<std::uint64_t>(timeout_config_.idle) * 1000ULL;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} tcp session idle closing", log_event::kSocks);
            co_await close_backend_once(backend);
            std::error_code ignore;
            ignore = socket_.close(ignore);
            break;
        }
    }
}

}    // namespace mux
