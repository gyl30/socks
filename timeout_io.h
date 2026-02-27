#ifndef TIMEOUT_IO_H
#define TIMEOUT_IO_H

#include <chrono>
#include <memory>
#include <string>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <tuple>
#include <string_view>
#include <system_error>

#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

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
    cancel_ec = socket.cancel(cancel_ec);
    log_socket_timeout_failure(scope, "cancel", cancel_ec);

    boost::system::error_code close_ec;
    close_ec = socket.close(close_ec);
    log_socket_timeout_failure(scope, "close", close_ec);
}

inline boost::asio::awaitable<boost::system::error_code> async_timeout_wait(const std::chrono::steady_clock::duration timeout)
{
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(timeout);
    boost::system::error_code wait_ec;
    co_await timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, wait_ec));
    co_return wait_ec;
}

}    // namespace detail

inline boost::asio::awaitable<timed_tcp_read_result> async_read_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                             const boost::asio::mutable_buffer buffer,
                                                                             const std::uint32_t timeout_sec,
                                                                             const bool require_full_buffer,
                                                                             const std::string_view scope = {})
{
    auto do_read = [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code, std::size_t>>
    {
        if (require_full_buffer)
        {
            co_return co_await boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        }
        co_return co_await socket.async_read_some(buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_sec == 0)
    {
        const auto [read_ec, read_size] = co_await do_read();
        if (read_ec)
        {
            co_return timed_tcp_read_result{.ok = false, .timed_out = false, .read_size = read_size, .ec = read_ec};
        }
        co_return timed_tcp_read_result{.ok = true, .timed_out = false, .read_size = read_size, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto read_or_timeout = co_await (do_read() || detail::async_timeout_wait(std::chrono::seconds(timeout_sec)));
    if (read_or_timeout.index() == 0)
    {
        const auto [read_ec, read_size] = std::get<0>(read_or_timeout);
        if (read_ec)
        {
            co_return timed_tcp_read_result{.ok = false, .timed_out = false, .read_size = read_size, .ec = read_ec};
        }
        co_return timed_tcp_read_result{.ok = true, .timed_out = false, .read_size = read_size, .ec = {}};
    }

    const auto wait_ec = std::get<1>(read_or_timeout);
    if (wait_ec)
    {
        co_return timed_tcp_read_result{.ok = false, .timed_out = false, .read_size = 0, .ec = wait_ec};
    }
    detail::cancel_and_close_socket(socket, scope);
    co_return timed_tcp_read_result{.ok = false, .timed_out = true, .read_size = 0, .ec = boost::asio::error::timed_out};
}

inline boost::asio::awaitable<timed_tcp_read_result> async_read_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                             const boost::asio::mutable_buffer buffer,
                                                                             const std::uint32_t timeout_sec,
                                                                             const bool require_full_buffer,
                                                                             const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_read_result{.ok = false, .timed_out = false, .read_size = 0, .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_read_with_timeout(*socket, buffer, timeout_sec, require_full_buffer, scope);
}

inline boost::asio::awaitable<timed_tcp_write_result> async_write_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                               const boost::asio::const_buffer buffer,
                                                                               const std::uint32_t timeout_sec,
                                                                               const std::string_view scope = {})
{
    auto do_write = [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code, std::size_t>>
    {
        co_return co_await boost::asio::async_write(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_sec == 0)
    {
        const auto [write_ec, write_size] = co_await do_write();
        if (write_ec)
        {
            co_return timed_tcp_write_result{.ok = false, .timed_out = false, .write_size = write_size, .ec = write_ec};
        }
        co_return timed_tcp_write_result{.ok = true, .timed_out = false, .write_size = write_size, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto write_or_timeout = co_await (do_write() || detail::async_timeout_wait(std::chrono::seconds(timeout_sec)));
    if (write_or_timeout.index() == 0)
    {
        const auto [write_ec, write_size] = std::get<0>(write_or_timeout);
        if (write_ec)
        {
            co_return timed_tcp_write_result{.ok = false, .timed_out = false, .write_size = write_size, .ec = write_ec};
        }
        co_return timed_tcp_write_result{.ok = true, .timed_out = false, .write_size = write_size, .ec = {}};
    }

    const auto wait_ec = std::get<1>(write_or_timeout);
    if (wait_ec)
    {
        co_return timed_tcp_write_result{.ok = false, .timed_out = false, .write_size = 0, .ec = wait_ec};
    }
    detail::cancel_and_close_socket(socket, scope);
    co_return timed_tcp_write_result{.ok = false, .timed_out = true, .write_size = 0, .ec = boost::asio::error::timed_out};
}

inline boost::asio::awaitable<timed_tcp_write_result> async_write_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                               const boost::asio::const_buffer buffer,
                                                                               const std::uint32_t timeout_sec,
                                                                               const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_write_result{.ok = false, .timed_out = false, .write_size = 0, .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_write_with_timeout(*socket, buffer, timeout_sec, scope);
}

inline boost::asio::awaitable<timed_tcp_resolve_result> async_resolve_with_timeout(boost::asio::ip::tcp::resolver& resolver,
                                                                                   const std::string& host,
                                                                                   const std::string& port,
                                                                                   const std::uint32_t timeout_sec)
{
    auto do_resolve =
        [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code, boost::asio::ip::tcp::resolver::results_type>>
    {
        co_return co_await resolver.async_resolve(host, port, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_sec == 0)
    {
        const auto [resolve_ec, endpoints] = co_await do_resolve();
        if (resolve_ec)
        {
            co_return timed_tcp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = resolve_ec};
        }
        co_return timed_tcp_resolve_result{.ok = true, .timed_out = false, .endpoints = endpoints, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto resolve_or_timeout = co_await (do_resolve() || detail::async_timeout_wait(std::chrono::seconds(timeout_sec)));
    if (resolve_or_timeout.index() == 0)
    {
        const auto [resolve_ec, endpoints] = std::get<0>(resolve_or_timeout);
        if (resolve_ec)
        {
            co_return timed_tcp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = resolve_ec};
        }
        co_return timed_tcp_resolve_result{.ok = true, .timed_out = false, .endpoints = endpoints, .ec = {}};
    }

    const auto wait_ec = std::get<1>(resolve_or_timeout);
    if (wait_ec)
    {
        co_return timed_tcp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = wait_ec};
    }
    resolver.cancel();
    co_return timed_tcp_resolve_result{.ok = false, .timed_out = true, .endpoints = {}, .ec = boost::asio::error::timed_out};
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                                   const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                                                                   const std::uint32_t timeout_sec,
                                                                                   const std::string_view scope = {})
{
    auto do_connect = [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code, boost::asio::ip::tcp::endpoint>>
    {
        co_return co_await boost::asio::async_connect(socket, endpoints, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_sec == 0)
    {
        const auto [connect_ec, endpoint] = co_await do_connect();
        if (connect_ec)
        {
            co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = connect_ec};
        }
        co_return timed_tcp_connect_result{.ok = true, .timed_out = false, .endpoint = endpoint, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto connect_or_timeout = co_await (do_connect() || detail::async_timeout_wait(std::chrono::seconds(timeout_sec)));
    if (connect_or_timeout.index() == 0)
    {
        const auto [connect_ec, endpoint] = std::get<0>(connect_or_timeout);
        if (connect_ec)
        {
            co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = connect_ec};
        }
        co_return timed_tcp_connect_result{.ok = true, .timed_out = false, .endpoint = endpoint, .ec = {}};
    }

    const auto wait_ec = std::get<1>(connect_or_timeout);
    if (wait_ec)
    {
        co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = wait_ec};
    }
    detail::cancel_and_close_socket(socket, scope);
    co_return timed_tcp_connect_result{.ok = false, .timed_out = true, .endpoint = {}, .ec = boost::asio::error::timed_out};
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                                                                                   const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                                                                   const std::uint32_t timeout_sec,
                                                                                   const std::string_view scope = {})
{
    if (!socket)
    {
        co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = std::make_error_code(std::errc::invalid_argument)};
    }
    co_return co_await async_connect_with_timeout(*socket, endpoints, timeout_sec, scope);
}

inline boost::asio::awaitable<timed_tcp_connect_result> async_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                                   const boost::asio::ip::tcp::endpoint& endpoint,
                                                                                   const std::uint32_t timeout_sec,
                                                                                   const std::string_view scope = {})
{
    auto do_connect = [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code>>
    {
        co_return co_await socket.async_connect(endpoint, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_sec == 0)
    {
        const auto [connect_ec] = co_await do_connect();
        if (connect_ec)
        {
            co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = connect_ec};
        }
        co_return timed_tcp_connect_result{.ok = true, .timed_out = false, .endpoint = endpoint, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto connect_or_timeout = co_await (do_connect() || detail::async_timeout_wait(std::chrono::seconds(timeout_sec)));
    if (connect_or_timeout.index() == 0)
    {
        const auto [connect_ec] = std::get<0>(connect_or_timeout);
        if (connect_ec)
        {
            co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = connect_ec};
        }
        co_return timed_tcp_connect_result{.ok = true, .timed_out = false, .endpoint = endpoint, .ec = {}};
    }

    const auto wait_ec = std::get<1>(connect_or_timeout);
    if (wait_ec)
    {
        co_return timed_tcp_connect_result{.ok = false, .timed_out = false, .endpoint = {}, .ec = wait_ec};
    }
    detail::cancel_and_close_socket(socket, scope);
    co_return timed_tcp_connect_result{.ok = false, .timed_out = true, .endpoint = {}, .ec = boost::asio::error::timed_out};
}

inline boost::asio::awaitable<timed_udp_resolve_result> async_resolve_with_timeout(boost::asio::ip::udp::resolver& resolver,
                                                                                   const std::string& host,
                                                                                   const std::string& port,
                                                                                   const std::uint64_t timeout_ms)
{
    auto do_resolve =
        [&]() -> boost::asio::awaitable<std::tuple<boost::system::error_code, boost::asio::ip::udp::resolver::results_type>>
    {
        co_return co_await resolver.async_resolve(host, port, boost::asio::as_tuple(boost::asio::use_awaitable));
    };

    if (timeout_ms == 0)
    {
        const auto [resolve_ec, endpoints] = co_await do_resolve();
        if (resolve_ec)
        {
            co_return timed_udp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = resolve_ec};
        }
        co_return timed_udp_resolve_result{.ok = true, .timed_out = false, .endpoints = endpoints, .ec = {}};
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    auto resolve_or_timeout = co_await (do_resolve() || detail::async_timeout_wait(std::chrono::milliseconds(timeout_ms)));
    if (resolve_or_timeout.index() == 0)
    {
        const auto [resolve_ec, endpoints] = std::get<0>(resolve_or_timeout);
        if (resolve_ec)
        {
            co_return timed_udp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = resolve_ec};
        }
        co_return timed_udp_resolve_result{.ok = true, .timed_out = false, .endpoints = endpoints, .ec = {}};
    }

    const auto wait_ec = std::get<1>(resolve_or_timeout);
    if (wait_ec)
    {
        co_return timed_udp_resolve_result{.ok = false, .timed_out = false, .endpoints = {}, .ec = wait_ec};
    }
    resolver.cancel();
    co_return timed_udp_resolve_result{.ok = false, .timed_out = true, .endpoints = {}, .ec = boost::asio::error::timed_out};
}

inline std::uint64_t timeout_seconds_to_milliseconds(const std::uint32_t timeout_sec) { return static_cast<std::uint64_t>(timeout_sec) * 1000ULL; }

}    // namespace mux::timeout_io

#endif
