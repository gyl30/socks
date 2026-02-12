#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>
#include <asio/experimental/channel_error.hpp>

#include "router.h"
#include "ip_matcher.h"
#include "domain_matcher.h"
#include "test_util.h"
#define private public
#include "tproxy_tcp_session.h"
#undef private

namespace
{

class direct_router : public mux::router
{
   public:
    direct_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();

        direct_ip_matcher()->add_rule("0.0.0.0/0");
        direct_ip_matcher()->add_rule("::/0");
        direct_ip_matcher()->optimize();
    }
};

class mock_upstream final : public mux::upstream
{
   public:
    bool connect_result = true;
    std::pair<std::error_code, std::size_t> read_result = {asio::error::eof, 0};
    std::size_t write_result = 0;
    int close_calls = 0;
    std::vector<std::uint8_t> last_write;

    asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override
    {
        (void)host;
        (void)port;
        co_return connect_result;
    }

    asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override
    {
        (void)buf;
        co_return read_result;
    }

    asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override
    {
        last_write = data;
        co_return write_result;
    }

    asio::awaitable<void> close() override
    {
        ++close_calls;
        co_return;
    }
};

}    // namespace

TEST(TproxyTcpSessionTest, DirectEcho)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    asio::ip::tcp::acceptor echo_acceptor(ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto echo_port = echo_acceptor.local_endpoint().port();

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket echo_socket = co_await echo_acceptor.async_accept(asio::use_awaitable);
            std::array<char, 64> buf = {};
            const auto [read_ec, n] = co_await echo_socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (!read_ec && n > 0)
            {
                co_await asio::async_write(echo_socket, asio::buffer(buf.data(), n), asio::use_awaitable);
            }
            co_return;
        },
        asio::detached);

    asio::ip::tcp::acceptor tproxy_acceptor(ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto tproxy_port = tproxy_acceptor.local_endpoint().port();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 3;

    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), echo_port);

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket sock = co_await tproxy_acceptor.async_accept(asio::use_awaitable);
            auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(sock), ctx, nullptr, router, 1, cfg, dst_ep);
            session->start();
            co_return;
        },
        asio::detached);

    std::atomic<bool> done{false};
    std::atomic<bool> ok{false};

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket client(ctx);
            std::error_code ec;
            co_await client.async_connect({asio::ip::make_address("127.0.0.1"), tproxy_port}, asio::redirect_error(asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            const std::string msg = "tproxy-echo";
            co_await asio::async_write(client, asio::buffer(msg), asio::redirect_error(asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            std::array<char, 32> buf = {};
            const auto [read_ec, n] = co_await client.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (!read_ec && n == msg.size() && std::string(buf.data(), n) == msg)
            {
                ok = true;
            }

            done = true;
            ctx.stop();
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(5));
    timer.async_wait(
        [&](const std::error_code& ec)
        {
            if (!ec)
            {
                ctx.stop();
            }
        });

    ctx.run();

    EXPECT_TRUE(done);
    EXPECT_TRUE(ok);
}

TEST(TproxyTcpSessionTest, StopReadDecisionBranches)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 80);

    auto session =
        std::make_shared<mux::tproxy_tcp_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 2, cfg, dst_ep);

    EXPECT_FALSE(session->should_stop_client_read(std::error_code(), 1));
    EXPECT_TRUE(session->should_stop_client_read(std::error_code(), 0));
    EXPECT_TRUE(session->should_stop_client_read(std::make_error_code(std::errc::invalid_argument), 0));

    EXPECT_FALSE(session->should_stop_backend_read(std::error_code(), 1));
    EXPECT_TRUE(session->should_stop_backend_read(std::error_code(), 0));
    EXPECT_TRUE(session->should_stop_backend_read(std::make_error_code(std::errc::invalid_argument), 0));
}

TEST(TproxyTcpSessionTest, StopReadDecisionExpectedErrors)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 80);

    auto session =
        std::make_shared<mux::tproxy_tcp_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 3, cfg, dst_ep);

    EXPECT_TRUE(session->should_stop_client_read(asio::error::eof, 0));
    EXPECT_TRUE(session->should_stop_client_read(asio::error::operation_aborted, 0));
    EXPECT_TRUE(session->should_stop_client_read(asio::error::bad_descriptor, 0));

    EXPECT_TRUE(session->should_stop_backend_read(asio::error::eof, 0));
    EXPECT_TRUE(session->should_stop_backend_read(asio::error::operation_aborted, 0));
    EXPECT_TRUE(session->should_stop_backend_read(asio::experimental::error::channel_closed, 0));
}

TEST(TproxyTcpSessionTest, CloseBackendOnceIsIdempotent)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 80);
    auto session =
        std::make_shared<mux::tproxy_tcp_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 4, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    mux::test::run_awaitable_void(ctx, session->close_backend_once(backend));
    mux::test::run_awaitable_void(ctx, session->close_backend_once(backend));
    EXPECT_EQ(backend->close_calls, 1);
}

TEST(TproxyTcpSessionTest, WriteClientChunkToBackendTracksActivity)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 80);
    auto session =
        std::make_shared<mux::tproxy_tcp_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 5, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    const std::vector<std::uint8_t> buf = {0x01, 0x02, 0x03, 0x04};
    session->last_activity_time_ms_.store(1, std::memory_order_release);

    backend->write_result = 0;
    const auto fail = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 3));
    EXPECT_FALSE(fail);
    ASSERT_EQ(backend->last_write.size(), 3U);
    EXPECT_EQ(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);

    backend->write_result = 3;
    const auto ok = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 3));
    EXPECT_TRUE(ok);
    EXPECT_GT(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);

    backend->write_result = 4;
    const auto ok_full = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 4));
    EXPECT_TRUE(ok_full);
    EXPECT_GT(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);
}

TEST(TproxyTcpSessionTest, ConnectBackendReflectsUpstreamResult)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 80);
    auto session =
        std::make_shared<mux::tproxy_tcp_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 6, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    backend->connect_result = true;
    const auto connect_ok =
        mux::test::run_awaitable(ctx, session->connect_backend(backend, "127.0.0.1", 80, mux::route_type::kDirect));
    EXPECT_TRUE(connect_ok);

    backend->connect_result = false;
    const auto connect_fail =
        mux::test::run_awaitable(ctx, session->connect_backend(backend, "127.0.0.1", 80, mux::route_type::kDirect));
    EXPECT_FALSE(connect_fail);
}
