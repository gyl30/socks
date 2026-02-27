#ifndef SOCKS_TEST_UTIL_H
#define SOCKS_TEST_UTIL_H

#include <chrono>
#include <functional>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace mux::test
{

template <typename T>
T run_awaitable(boost::asio::io_context& ctx, boost::asio::awaitable<T> awaitable)
{
    std::optional<T> result;
    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [awaitable = std::move(awaitable), &result, &done]() mutable -> boost::asio::awaitable<void>
        {
            result.emplace(co_await std::move(awaitable));
            done = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    ctx.restart();
    if (!done || !result.has_value())
    {
        ADD_FAILURE() << "awaitable did not complete";
        return T{};
    }
    return std::move(*result);
}

inline void run_awaitable_void(boost::asio::io_context& ctx, boost::asio::awaitable<void> awaitable)
{
    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [awaitable = std::move(awaitable), &done]() mutable -> boost::asio::awaitable<void>
        {
            co_await std::move(awaitable);
            done = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    ctx.restart();
    if (!done)
    {
        ADD_FAILURE() << "awaitable did not complete";
    }
}

inline boost::asio::awaitable<bool> co_wait_predicate(std::function<bool()> predicate, const std::chrono::milliseconds poll_interval)
{
    auto executor = co_await boost::asio::this_coro::executor;
    if (predicate())
    {
        co_return true;
    }

    boost::asio::steady_timer timer(executor);
    auto wait_step = std::chrono::duration_cast<std::chrono::steady_clock::duration>(poll_interval);
    if (wait_step <= std::chrono::steady_clock::duration::zero())
    {
        wait_step = std::chrono::milliseconds(1);
    }
    while (!predicate())
    {
        timer.expires_after(wait_step);
        boost::system::error_code ec;
        co_await timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec && ec != boost::asio::error::operation_aborted)
        {
            co_return false;
        }
    }
    co_return true;
}

template <typename Predicate, typename Rep, typename Period>
bool co_wait_until(Predicate&& predicate,
                   const std::chrono::duration<Rep, Period>& timeout,
                   const std::chrono::milliseconds poll_interval = std::chrono::milliseconds(1))
{
    boost::asio::io_context ctx;
    const auto cast_timeout = std::chrono::duration_cast<std::chrono::steady_clock::duration>(timeout);
    return run_awaitable(ctx,
                         [predicate = std::function<bool()>(std::forward<Predicate>(predicate)), cast_timeout, poll_interval]()
                             mutable -> boost::asio::awaitable<bool>
                         {
                             using boost::asio::experimental::awaitable_operators::operator||;

                             auto executor = co_await boost::asio::this_coro::executor;
                             boost::asio::steady_timer timeout_timer(executor);
                             timeout_timer.expires_after(cast_timeout);

                             auto timeout_wait = [&timeout_timer]() -> boost::asio::awaitable<bool>
                             {
                                 boost::system::error_code ec;
                                 co_await timeout_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
                                 co_return false;
                             };

                             auto wait_result = co_await (co_wait_predicate(predicate, poll_interval) || timeout_wait());
                             if (wait_result.index() == 0)
                             {
                                 co_return std::get<0>(wait_result);
                             }
                             co_return std::get<1>(wait_result);
                         }());
}

inline bool open_ephemeral_tcp_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                                        const boost::asio::ip::address& bind_addr = boost::asio::ip::make_address("127.0.0.1"),
                                        const std::uint32_t max_attempts = 256,
                                        const std::chrono::milliseconds backoff = std::chrono::milliseconds(4),
                                        const int backlog = boost::asio::socket_base::max_listen_connections)
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            ec = acceptor.close(ec);
        }
        const auto protocol = bind_addr.is_v6() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4();
        ec = acceptor.open(protocol, ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(bind_addr, 0), ec);
        }
        if (!ec)
        {
            ec = acceptor.listen(backlog, ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

inline bool bind_ephemeral_tcp_socket(boost::asio::ip::tcp::socket& socket,
                                      const boost::asio::ip::address& bind_addr = boost::asio::ip::make_address("127.0.0.1"),
                                      const std::uint32_t max_attempts = 256,
                                      const std::chrono::milliseconds backoff = std::chrono::milliseconds(4))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        ec = socket.bind(boost::asio::ip::tcp::endpoint(bind_addr, 0), ec);
        if (!ec)
        {
            return true;
        }
        if (ec != boost::asio::error::address_in_use)
        {
            return false;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

}    // namespace mux::test

#endif
