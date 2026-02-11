#ifndef SOCKS_TEST_UTIL_H
#define SOCKS_TEST_UTIL_H

#include <vector>
#include <utility>
#include <exception>
#include <stdexcept>

#include <asio.hpp>

namespace mux::test
{

template <typename T>
T run_awaitable(asio::io_context& ctx, asio::awaitable<T> awaitable)
{
    T result;
    asio::co_spawn(ctx,
                   std::move(awaitable),
                   [&](std::exception_ptr e, T res)
                   {
                       if (e)
                       {
                           std::rethrow_exception(e);
                       }
                       result = std::move(res);
                   });
    ctx.run();
    ctx.restart();
    return result;
}

inline void run_awaitable_void(asio::io_context& ctx, asio::awaitable<void> awaitable)
{
    bool done = false;
    asio::co_spawn(ctx,
                   std::move(awaitable),
                   [&](std::exception_ptr e)
                   {
                       if (e)
                       {
                           std::rethrow_exception(e);
                       }
                       done = true;
                   });
    ctx.run();
    ctx.restart();
    if (!done)
    {
        throw std::runtime_error("awaitable did not complete");
    }
}

}                          

#endif
