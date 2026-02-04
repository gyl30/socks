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
#include <asio/write.hpp>

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

TEST(CertFetcherTest, ReassemblerLimits)
{
    reality::handshake_reassembler assembler;
    std::vector<uint8_t> msg;
    std::error_code ec;

    // Header with huge length (64K+1)
    std::vector<uint8_t> huge_header = {0x01, 0x01, 0x00, 0x01};
    assembler.append(huge_header);
    EXPECT_FALSE(assembler.next(msg, ec));
    EXPECT_EQ(ec, std::errc::message_size);
}

TEST(CertFetcherTest, MockServerScenarios)
{
    using asio::ip::tcp;
    asio::io_context ctx;

    // A helper to run a mock server that sends arbitrary bytes
    auto run_mock_server = [&](std::vector<uint8_t> data_to_send)
    {
        auto acceptor = std::make_shared<tcp::acceptor>(ctx, tcp::endpoint(tcp::v4(), 0));
        uint16_t port = acceptor->local_endpoint().port();

        asio::co_spawn(
            ctx,
            [acceptor, data_to_send]() -> asio::awaitable<void>
            {
                auto socket = co_await acceptor->async_accept(asio::use_awaitable);
                co_await asio::async_write(socket, asio::buffer(data_to_send), asio::use_awaitable);
                co_return;
            },
            asio::detached);

        return port;
    };

    // Scenario 1: Server sends non-handshake record when expecting SH
    {
        std::vector<uint8_t> bad_rec = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32};    // Alert
        uint16_t port = run_mock_server(bad_rec);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    // Scenario 2: Server sends malformed ServerHello (too short)
    {
        std::vector<uint8_t> short_sh = {0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01};
        uint16_t port = run_mock_server(short_sh);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }

    // Scenario 3: Server sends record with huge handshake length
    {
        // First we need to get past SH. We can't easily without a real handshake,
        // but we can try to trigger errors in read_record.

        // Let's send a record with length > 18432
        std::vector<uint8_t> long_rec = {0x16, 0x03, 0x03, 0x48, 0x01};    // len = 18433
        uint16_t port = run_mock_server(long_rec);

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void>
            {
                auto res = co_await reality::cert_fetcher::fetch(co_await asio::this_coro::executor, "127.0.0.1", port, "localhost", "test");
                EXPECT_FALSE(res.has_value());
                co_return;
            },
            asio::detached);
        ctx.run();
        ctx.restart();
    }
}
