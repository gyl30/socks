// NOLINTBEGIN(misc-include-cleaner)
#include <boost/asio/co_spawn.hpp>    // NOLINT(misc-include-cleaner): required for co_spawn declarations.
#include <chrono>
#include <boost/asio/io_context.hpp>
#include <atomic>
#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/redirect_error.hpp>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "config.h"
#include "log.h"
#include "router.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "log_context.h"
#include "tcp_socks_session.h"

namespace mux
{

namespace
{

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

[[nodiscard]] const char* route_name(const route_type route)
{
    return route == route_type::kDirect ? "direct" : "proxy";
}

}    // namespace

tcp_socks_session::tcp_socks_session(boost::asio::ip::tcp::socket socket,
                                     boost::asio::io_context& io_context,
                                     std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                                     std::shared_ptr<router> router,
                                     const std::uint32_t sid,
                                     const config::timeout_t& timeout_cfg,
                                     std::shared_ptr<void> active_connection_guard)
    : io_context_(io_context),
      socket_(std::move(socket)),
      idle_timer_(io_context_),
      router_(std::move(router)),
      tunnel_manager_(std::move(tunnel_manager)),
      active_connection_guard_(std::move(active_connection_guard)),
      timeout_config_(timeout_cfg)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_.store(now_ms(), std::memory_order_release);
}

void tcp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    boost::asio::co_spawn(io_context_, run_detached(shared_from_this(), host, port), boost::asio::detached);
}

boost::asio::awaitable<void> tcp_socks_session::run_detached(std::shared_ptr<tcp_socks_session> self,
                                                      std::string host,
                                                      const std::uint16_t port)
{
    co_await self->run(host, port);
}

boost::asio::awaitable<void> tcp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    if (router_ == nullptr)
    {
        LOG_CTX_ERROR(ctx_, "{} router unavailable", log_event::kRoute);
        co_await reply_error(socks::kRepGenFail);
        close_client_socket();
        co_return;
    }

    const auto route = co_await router_->decide(ctx_, host);
    const auto backend = create_backend(route);
    if (backend == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, host);
        statistics::instance().inc_routing_blocked();
        co_await reply_error(socks::kRepNotAllowed);
        close_client_socket();
        co_return;
    }

    if (!co_await connect_backend(backend, host, port, route))
    {
        co_await close_backend_once(backend);
        close_client_socket();
        co_return;
    }

    if (!co_await reply_success())
    {
        co_await close_backend_once(backend);
        close_client_socket();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, host, port, route_name(route));
    start_idle_watchdog(backend);
    using boost::asio::experimental::awaitable_operators::operator&&;
    co_await (client_to_upstream(backend) && upstream_to_client(backend));
    co_await close_backend_once(backend);
    close_client_socket();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

std::shared_ptr<upstream> tcp_socks_session::create_backend(const route_type route) const
{
    if (route == route_type::kDirect)
    {
        return std::make_shared<direct_upstream>(io_context_, ctx_, 0, timeout_config_.read);
    }
    if (route == route_type::kProxy)
    {
        return std::make_shared<proxy_upstream>(tunnel_manager_, ctx_);
    }
    return nullptr;
}

boost::asio::awaitable<bool> tcp_socks_session::connect_backend(const std::shared_ptr<upstream>& backend,
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
    co_await reply_error(socks::kRepHostUnreach);
    co_return false;
}

boost::asio::awaitable<bool> tcp_socks_session::reply_success()
{
    std::uint8_t rep[] = {socks::kVer, socks::kRepSuccess, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    const auto [we, wn] = co_await boost::asio::async_write(socket_, boost::asio::buffer(rep), boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)wn;
    if (!we)
    {
        co_return true;
    }

    LOG_CTX_WARN(ctx_, "{} write to client failed {}", log_event::kDataSend, we.message());
    co_return false;
}

void tcp_socks_session::start_idle_watchdog(const std::shared_ptr<upstream>& backend)
{
    boost::asio::co_spawn(io_context_, idle_watchdog_detached(shared_from_this(), backend), boost::asio::detached);
}

boost::asio::awaitable<void> tcp_socks_session::idle_watchdog_detached(std::shared_ptr<tcp_socks_session> self, std::shared_ptr<upstream> backend)
{
    co_await self->idle_watchdog(std::move(backend));
}

void tcp_socks_session::close_client_socket()
{
    boost::system::error_code ec;
    idle_timer_.cancel();
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_CTX_WARN(ctx_, "{} shutdown client failed {}", log_event::kSocks, ec.message());
    }

    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close client failed {}", log_event::kSocks, ec.message());
    }
}

boost::asio::awaitable<void> tcp_socks_session::reply_error(const std::uint8_t code)
{
    std::uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    (void)co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
}

boost::asio::awaitable<void> tcp_socks_session::client_to_upstream(std::shared_ptr<upstream> backend)
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        boost::system::error_code ec;
        const std::uint32_t n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || n == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from client {}", log_event::kSocks, ec.message());
            break;
        }

        std::size_t total_written = 0;
        bool write_failed = false;
        while (total_written < n)
        {
            const auto remaining = static_cast<std::size_t>(n - total_written);
            const auto written = co_await backend->write(buf.data() + total_written, remaining);
            if (written == 0 || written > remaining)
            {
                write_failed = true;
                break;
            }
            total_written += written;
        }
        if (write_failed)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to backend", log_event::kSocks);
            co_await close_backend_once(backend);
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::kSocks);
}

boost::asio::awaitable<void> tcp_socks_session::upstream_to_client(std::shared_ptr<upstream> backend)
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

        const auto [we, wn] = co_await boost::asio::async_write(socket_, boost::asio::buffer(buf.data(), n), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to client {}", log_event::kSocks, we.message());
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::kSocks);
    boost::system::error_code ignore;
    ignore = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
    if (ignore)
    {
        LOG_CTX_WARN(ctx_, "{} failed to shutdown client {}", log_event::kSocks, ignore.message());
    }
}

boost::asio::awaitable<void> tcp_socks_session::close_backend_once(const std::shared_ptr<upstream>& backend)
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

boost::asio::awaitable<void> tcp_socks_session::idle_watchdog(std::shared_ptr<upstream> backend)
{
    if (timeout_config_.idle == 0)
    {
        co_return;
    }

    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
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
            boost::system::error_code ignore;
            ignore = socket_.close(ignore);
            break;
        }
    }
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
