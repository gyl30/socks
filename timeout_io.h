#ifndef TIMEOUT_IO_H
#define TIMEOUT_IO_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include "log.h"

namespace mux::timeout_io
{

struct timed_tcp_read_result
{
    bool ok = false;
    bool timed_out = false;
    std::size_t read_size = 0;
    boost::system::error_code ec;
};

struct timed_tcp_write_result
{
    bool ok = false;
    bool timed_out = false;
    std::size_t write_size = 0;
    boost::system::error_code ec;
};

struct timed_tcp_resolve_result
{
    bool ok = false;
    bool timed_out = false;
    boost::asio::ip::tcp::resolver::results_type endpoints;
    boost::system::error_code ec;
};

struct timed_tcp_connect_result
{
    bool ok = false;
    bool timed_out = false;
    boost::asio::ip::tcp::endpoint endpoint;
    boost::system::error_code ec;
};

struct timed_udp_resolve_result
{
    bool ok = false;
    bool timed_out = false;
    boost::asio::ip::udp::resolver::results_type endpoints;
    boost::system::error_code ec;
};

struct socket_timeout_state
{
    std::shared_ptr<boost::asio::steady_timer> timer;
    std::shared_ptr<std::atomic<bool>> timed_out;
};

struct resolver_timeout_state
{
    std::shared_ptr<boost::asio::steady_timer> timer;
    std::shared_ptr<std::atomic<bool>> timed_out;
};

namespace detail
{

inline void log_socket_timeout_failure(const std::string_view scope, const char* action, const boost::system::error_code& ec)
{
    if (!ec || ec == boost::asio::error::bad_descriptor)
    {
        return;
    }
    if (scope.empty())
    {
        LOG_WARN("{} timeout socket failed {}", action, ec.message());
        return;
    }
    LOG_WARN("{} {} timeout socket failed {}", scope, action, ec.message());
}

inline void cancel_and_close_socket(boost::asio::ip::tcp::socket& socket, const std::string_view scope)
{
    boost::system::error_code cancel_ec;
    socket.cancel(cancel_ec);
    log_socket_timeout_failure(scope, "cancel", cancel_ec);

    boost::system::error_code close_ec;
    socket.close(close_ec);
    log_socket_timeout_failure(scope, "close", close_ec);
}

}    // namespace detail

inline socket_timeout_state arm_socket_timeout(boost::asio::ip::tcp::socket& socket,
                                               const std::chrono::milliseconds timeout,
                                               const std::string_view scope = {})
{
    if (timeout.count() <= 0)
    {
        return {};
    }

    auto timer = std::make_shared<boost::asio::steady_timer>(socket.get_executor());
    auto timed_out = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(timeout);
    timer->async_wait(
        [&socket, timed_out, scope](const boost::system::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timed_out->store(true, std::memory_order_release);
            detail::cancel_and_close_socket(socket, scope);
        });
    return socket_timeout_state{
        .timer = std::move(timer),
        .timed_out = std::move(timed_out)};
}

inline socket_timeout_state arm_socket_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                               const std::chrono::milliseconds timeout,
                                               const std::string_view scope = {})
{
    if (!socket)
    {
        return {};
    }
    if (timeout.count() <= 0)
    {
        return {};
    }

    auto timer = std::make_shared<boost::asio::steady_timer>(socket->get_executor());
    auto timed_out = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(timeout);
    timer->async_wait(
        [socket, timed_out, scope](const boost::system::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timed_out->store(true, std::memory_order_release);
            detail::cancel_and_close_socket(*socket, scope);
        });
    return socket_timeout_state{
        .timer = std::move(timer),
        .timed_out = std::move(timed_out)};
}

inline bool disarm_timeout(const socket_timeout_state& state)
{
    if (!state.timer || !state.timed_out)
    {
        return false;
    }
    (void)state.timer->cancel();
    return state.timed_out->load(std::memory_order_acquire);
}

inline resolver_timeout_state arm_resolver_timeout(boost::asio::ip::tcp::resolver& resolver, const std::chrono::milliseconds timeout)
{
    if (timeout.count() <= 0)
    {
        return {};
    }

    auto timer = std::make_shared<boost::asio::steady_timer>(resolver.get_executor());
    auto timed_out = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(timeout);
    timer->async_wait(
        [&resolver, timed_out](const boost::system::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timed_out->store(true, std::memory_order_release);
            resolver.cancel();
        });
    return resolver_timeout_state{
        .timer = std::move(timer),
        .timed_out = std::move(timed_out)};
}

inline resolver_timeout_state arm_resolver_timeout(boost::asio::ip::udp::resolver& resolver, const std::chrono::milliseconds timeout)
{
    if (timeout.count() <= 0)
    {
        return {};
    }

    auto timer = std::make_shared<boost::asio::steady_timer>(resolver.get_executor());
    auto timed_out = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(timeout);
    timer->async_wait(
        [&resolver, timed_out](const boost::system::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timed_out->store(true, std::memory_order_release);
            resolver.cancel();
        });
    return resolver_timeout_state{
        .timer = std::move(timer),
        .timed_out = std::move(timed_out)};
}

inline bool disarm_timeout(const resolver_timeout_state& state)
{
    if (!state.timer || !state.timed_out)
    {
        return false;
    }
    (void)state.timer->cancel();
    return state.timed_out->load(std::memory_order_acquire);
}

inline boost::asio::awaitable<timed_tcp_read_result> async_read_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                       const boost::asio::mutable_buffer buffer,
                                                                       const std::uint32_t timeout_sec,
                                                                       const bool require_full_buffer,
                                                                       const std::string_view scope = {})
{
    auto timeout_state = arm_socket_timeout(socket, std::chrono::seconds(timeout_sec), scope);
    boost::system::error_code read_ec;
    std::size_t read_size = 0;
    if (require_full_buffer)
    {
        const auto [exact_read_ec, exact_read_size] = co_await boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        read_ec = exact_read_ec;
        read_size = exact_read_size;
    }
    else
    {
        const auto [read_some_ec, read_some_size] = co_await socket.async_read_some(buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        read_ec = read_some_ec;
        read_size = read_some_size;
    }

    if (disarm_timeout(timeout_state))
    {
        co_return timed_tcp_read_result{
            .ok = false,
            .timed_out = true,
            .read_size = read_size,
            .ec = boost::asio::error::timed_out};
    }
    if (read_ec)
    {
        co_return timed_tcp_read_result{
            .ok = false,
            .read_size = read_size,
            .ec = read_ec};
    }
    co_return timed_tcp_read_result{
        .ok = true,
        .read_size = read_size};
}

inline boost::asio::awaitable<timed_tcp_read_result> async_read_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                       const boost::asio::mutable_buffer buffer,
                                                                       const std::uint32_t timeout_sec,
                                                                       const bool require_full_buffer,
                                                                       const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_read_result{
            .ok = false,
            .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_read_with_timeout(*socket, buffer, timeout_sec, require_full_buffer, scope);
}

inline boost::asio::awaitable<timed_tcp_write_result> async_write_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                         const boost::asio::const_buffer buffer,
                                                                         const std::uint32_t timeout_sec,
                                                                         const std::string_view scope = {})
{
    auto timeout_state = arm_socket_timeout(socket, std::chrono::seconds(timeout_sec), scope);
    const auto [write_ec, write_size] = co_await boost::asio::async_write(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (disarm_timeout(timeout_state))
    {
        co_return timed_tcp_write_result{
            .ok = false,
            .timed_out = true,
            .write_size = write_size,
            .ec = boost::asio::error::timed_out};
    }
    if (write_ec)
    {
        co_return timed_tcp_write_result{
            .ok = false,
            .write_size = write_size,
            .ec = write_ec};
    }
    co_return timed_tcp_write_result{
        .ok = true,
        .write_size = write_size};
}

inline boost::asio::awaitable<timed_tcp_write_result> async_write_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                         const boost::asio::const_buffer buffer,
                                                                         const std::uint32_t timeout_sec,
                                                                         const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_write_result{
            .ok = false,
            .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_write_with_timeout(*socket, buffer, timeout_sec, scope);
}

inline boost::asio::awaitable<timed_tcp_resolve_result> async_resolve_with_timeout(boost::asio::ip::tcp::resolver& resolver,
                                                                             const std::string& host,
                                                                             const std::string& port,
                                                                             const std::uint32_t timeout_sec)
{
    auto timeout_state = arm_resolver_timeout(resolver, std::chrono::seconds(timeout_sec));
    const auto [resolve_ec, endpoints] = co_await resolver.async_resolve(host, port, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (disarm_timeout(timeout_state))
    {
        co_return timed_tcp_resolve_result{
            .ok = false,
            .timed_out = true,
            .ec = boost::asio::error::timed_out};
    }
    if (resolve_ec)
    {
        co_return timed_tcp_resolve_result{
            .ok = false,
            .ec = resolve_ec};
    }
    co_return timed_tcp_resolve_result{
        .ok = true,
        .endpoints = endpoints};
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                             const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                                                             const std::uint32_t timeout_sec,
                                                                             const std::string_view scope = {})
{
    auto timeout_state = arm_socket_timeout(socket, std::chrono::seconds(timeout_sec), scope);
    const auto [connect_ec, endpoint] = co_await boost::asio::async_connect(socket, endpoints, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (disarm_timeout(timeout_state))
    {
        co_return timed_tcp_connect_result{
            .ok = false,
            .timed_out = true,
            .ec = boost::asio::error::timed_out};
    }
    if (connect_ec)
    {
        co_return timed_tcp_connect_result{
            .ok = false,
            .ec = connect_ec};
    }
    co_return timed_tcp_connect_result{
        .ok = true,
        .endpoint = endpoint};
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                             const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                                                             const std::uint32_t timeout_sec,
                                                                             const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_connect_result{
            .ok = false,
            .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_connect_with_timeout(*socket, endpoints, timeout_sec, scope);
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                             const boost::asio::ip::tcp::endpoint& endpoint,
                                                                             const std::uint32_t timeout_sec,
                                                                             const std::string_view scope = {})
{
    auto timeout_state = arm_socket_timeout(socket, std::chrono::seconds(timeout_sec), scope);
    const auto [connect_ec] = co_await socket.async_connect(endpoint, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (disarm_timeout(timeout_state))
    {
        co_return timed_tcp_connect_result{
            .ok = false,
            .timed_out = true,
            .ec = boost::asio::error::timed_out};
    }
    if (connect_ec)
    {
        co_return timed_tcp_connect_result{
            .ok = false,
            .ec = connect_ec};
    }
    co_return timed_tcp_connect_result{
        .ok = true,
        .endpoint = endpoint};
}

inline boost::asio::awaitable<timed_udp_resolve_result> async_resolve_with_timeout(boost::asio::ip::udp::resolver& resolver,
                                                                             const std::string& host,
                                                                             const std::string& port,
                                                                             const std::uint64_t timeout_ms)
{
    auto timeout_state = arm_resolver_timeout(resolver, std::chrono::milliseconds(timeout_ms));
    const auto [resolve_ec, endpoints] = co_await resolver.async_resolve(host, port, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (disarm_timeout(timeout_state))
    {
        co_return timed_udp_resolve_result{
            .ok = false,
            .timed_out = true,
            .ec = boost::asio::error::timed_out};
    }
    if (resolve_ec)
    {
        co_return timed_udp_resolve_result{
            .ok = false,
            .ec = resolve_ec};
    }
    co_return timed_udp_resolve_result{
        .ok = true,
        .endpoints = endpoints};
}

inline std::uint64_t timeout_seconds_to_milliseconds(const std::uint32_t timeout_sec)
{
    return static_cast<std::uint64_t>(timeout_sec) * 1000ULL;
}

}    // namespace mux::timeout_io

#endif
