#ifndef SOCKS_TEST_UTIL_H
#define SOCKS_TEST_UTIL_H

#include <chrono>
#include <vector>
#include <thread>
#include <utility>
#include <optional>
#include <cstdint>
#include <system_error>

#include <asio.hpp>
#include <gtest/gtest.h>

namespace mux::test
{

template <typename T>
T run_awaitable(asio::io_context& ctx, asio::awaitable<T> awaitable)
{
    std::optional<T> result;
    bool done = false;
    asio::co_spawn(ctx,
                   [awaitable = std::move(awaitable), &result, &done]() mutable -> asio::awaitable<void>
                   {
                       result.emplace(co_await std::move(awaitable));
                       done = true;
                       co_return;
                   },
                   asio::detached);
    ctx.run();
    ctx.restart();
    if (!done || !result.has_value())
    {
        ADD_FAILURE() << "awaitable did not complete";
        return T{};
    }
    return std::move(*result);
}

inline void run_awaitable_void(asio::io_context& ctx, asio::awaitable<void> awaitable)
{
    bool done = false;
    asio::co_spawn(ctx,
                   [awaitable = std::move(awaitable), &done]() mutable -> asio::awaitable<void>
                   {
                       co_await std::move(awaitable);
                       done = true;
                       co_return;
                   },
                   asio::detached);
    ctx.run();
    ctx.restart();
    if (!done)
    {
        ADD_FAILURE() << "awaitable did not complete";
    }
}

inline bool open_ephemeral_tcp_acceptor(asio::ip::tcp::acceptor& acceptor,
                                        const asio::ip::address& bind_addr = asio::ip::make_address("127.0.0.1"),
                                        const std::uint32_t max_attempts = 128,
                                        const std::chrono::milliseconds backoff = std::chrono::milliseconds(2))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        std::error_code ec;
        if (acceptor.is_open())
        {
            acceptor.close(ec);
        }
        const auto protocol = bind_addr.is_v6() ? asio::ip::tcp::v6() : asio::ip::tcp::v4();
        acceptor.open(protocol, ec);
        if (!ec)
        {
            acceptor.set_option(asio::socket_base::reuse_address(true), ec);
        }
        if (!ec)
        {
            acceptor.bind(asio::ip::tcp::endpoint(bind_addr, 0), ec);
        }
        if (!ec)
        {
            acceptor.listen(asio::socket_base::max_listen_connections, ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

inline bool bind_ephemeral_tcp_socket(asio::ip::tcp::socket& socket,
                                      const asio::ip::address& bind_addr = asio::ip::make_address("127.0.0.1"),
                                      const std::uint32_t max_attempts = 128,
                                      const std::chrono::milliseconds backoff = std::chrono::milliseconds(2))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        std::error_code ec;
        socket.bind(asio::ip::tcp::endpoint(bind_addr, 0), ec);
        if (!ec)
        {
            return true;
        }
        if (ec != asio::error::address_in_use)
        {
            return false;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

}                          

#endif
