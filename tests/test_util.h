#ifndef SOCKS_TEST_UTIL_H
#define SOCKS_TEST_UTIL_H

#include <chrono>
#include <vector>
#include <thread>
#include <utility>
#include <optional>
#include <cstdint>
#include <system_error>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

namespace mux::test
{

template <typename T>
T run_awaitable(boost::asio::io_context& ctx, boost::asio::awaitable<T> awaitable)
{
    std::optional<T> result;
    bool done = false;
    boost::asio::co_spawn(ctx,
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
    boost::asio::co_spawn(ctx,
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

inline bool open_ephemeral_tcp_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                                        const boost::asio::ip::address& bind_addr = boost::asio::ip::make_address("127.0.0.1"),
                                        const std::uint32_t max_attempts = 128,
                                        const std::chrono::milliseconds backoff = std::chrono::milliseconds(2))
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
            ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
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
                                      const std::uint32_t max_attempts = 128,
                                      const std::chrono::milliseconds backoff = std::chrono::milliseconds(2))
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
