#include <chrono>
#include <string>
#include <thread>
#include <cstdlib>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/this_coro.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include "cert_fetcher.h"

namespace
{
static void run_cmd(const char* cmd)
{
    const int ret = std::system(cmd);
    (void)ret;
}
}    // namespace

TEST(CertFetcherTest, BasicFetch)
{
    run_cmd(
        "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout key_cf.pem -out cert_cf.pem -days 365 -nodes -subj "
        "'/CN=localhost' 2>/dev/null");

    run_cmd("openssl s_server -key key_cf.pem -cert cert_cf.pem -accept 33445 -www -quiet -tls1_3 & echo $! > server_cf.pid");

    std::this_thread::sleep_for(std::chrono::seconds(1));

    asio::io_context ctx;
    bool finished = false;

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            const auto ex = co_await asio::this_coro::executor;
            const std::string dummy_pub_key(64, 'a');
            (void)co_await reality::cert_fetcher::fetch(ex, "127.0.0.1", 33445, "localhost", dummy_pub_key);
            finished = true;
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(5));
    timer.async_wait(
        [&](const std::error_code ec)
        {
            if (!ec)
            {
                ctx.stop();
            }
        });

    ctx.run();

    run_cmd("kill $(cat server_cf.pid) 2>/dev/null");
    run_cmd("rm key_cf.pem cert_cf.pem server_cf.pid");
}

TEST(CertFetcherTest, ConnectFail)
{
    asio::io_context ctx;
    bool finished = false;

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            const auto ex = co_await asio::this_coro::executor;
            const std::string dummy_pub_key(64, 'a');
            const auto res = co_await reality::cert_fetcher::fetch(ex, "127.0.0.1", 33446, "localhost", dummy_pub_key);
            EXPECT_FALSE(res.has_value());
            finished = true;
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(2));
    timer.async_wait(
        [&](const std::error_code ec)
        {
            if (!ec)
            {
                ctx.stop();
            }
        });

    ctx.run();
    EXPECT_TRUE(finished);
}
