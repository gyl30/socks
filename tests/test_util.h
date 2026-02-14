#ifndef SOCKS_TEST_UTIL_H
#define SOCKS_TEST_UTIL_H

#include <vector>
#include <utility>
#include <optional>

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

}                          

#endif
