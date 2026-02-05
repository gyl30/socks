#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/this_coro.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "cert_fetcher.h"

TEST(CertFetcherTest, BasicFetch)
{
    asio::io_context ctx;
    bool finished = false;

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            const auto ex = co_await asio::this_coro::executor;
            const auto res = co_await reality::cert_fetcher::fetch(ex, "www.google.com", 443, "www.google.com");
            if (res.has_value())
            {
                EXPECT_FALSE(res->cert_msg.empty());
            }
            finished = true;
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(10));
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

TEST(CertFetcherTest, ReassemblerLimits)
{
    reality::handshake_reassembler assembler;
    std::vector<std::uint8_t> msg;
    std::error_code ec;

    std::vector<std::uint8_t> huge_header = {0x01, 0x01, 0x00, 0x01};
    assembler.append(huge_header);
    EXPECT_FALSE(assembler.next(msg, ec));
    EXPECT_EQ(ec, std::errc::message_size);
}

TEST(CertFetcherTest, MockServerScenarios)
{
    using asio::ip::tcp;
    asio::io_context ctx;

    auto run_mock_server = [&](std::vector<std::uint8_t> data_to_send)
    {
        auto acceptor = std::make_shared<tcp::acceptor>(ctx, tcp::endpoint(tcp::v4(), 0));
        std::uint16_t port = acceptor->local_endpoint().port();

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

    {
        std::vector<std::uint8_t> bad_rec = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32};
        std::uint16_t port = run_mock_server(bad_rec);

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

    {
        std::vector<std::uint8_t> short_sh = {0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01};
        std::uint16_t port = run_mock_server(short_sh);

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

    {
        std::vector<std::uint8_t> long_rec = {0x16, 0x03, 0x03, 0x48, 0x01};
        std::uint16_t port = run_mock_server(long_rec);

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