
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "router.h"
#include "test_util.h"
#include "ip_matcher.h"
#include "statistics.h"
#include "domain_matcher.h"

#define private public
#include "tproxy_tcp_session.h"

#undef private

extern "C" int __real_shutdown(int sockfd, int how);    
extern "C" int __real_close(int fd);                    

namespace
{

std::atomic<bool> g_fail_shutdown_once{false};
std::atomic<int> g_fail_shutdown_errno{EPERM};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

void fail_next_shutdown(const int err)
{
    g_fail_shutdown_errno.store(err, std::memory_order_release);
    g_fail_shutdown_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

struct tcp_socket_pair
{
    boost::asio::ip::tcp::socket client;
    boost::asio::ip::tcp::socket server;
};

bool open_ephemeral_tcp_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                                 const std::uint32_t max_attempts = 120,
                                 const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            acceptor.close(ec);
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
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

tcp_socket_pair make_tcp_socket_pair(boost::asio::io_context& io_context)
{
    for (std::uint32_t attempt = 0; attempt < 120; ++attempt)
    {
        boost::asio::ip::tcp::acceptor acceptor(io_context);
        if (!open_ephemeral_tcp_acceptor(acceptor, 1))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            continue;
        }

        boost::system::error_code ec;
        boost::asio::ip::tcp::socket client(io_context);
        boost::asio::ip::tcp::socket server(io_context);
        client.connect(acceptor.local_endpoint(), ec);
        if (ec)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            continue;
        }
        acceptor.accept(server, ec);
        if (ec)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            continue;
        }
        return tcp_socket_pair{.client = std::move(client), .server = std::move(server)};
    }
    return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
}

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

class block_router : public mux::router
{
   public:
    block_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();

        block_ip_matcher()->add_rule("0.0.0.0/0");
        block_ip_matcher()->add_rule("::/0");
        block_ip_matcher()->optimize();
    }
};

class proxy_router : public mux::router
{
   public:
    proxy_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();
    }
};

class mock_upstream final : public mux::upstream
{
   public:
    bool connect_result = true;
    std::pair<boost::system::error_code, std::size_t> read_result = {boost::asio::error::eof, 0};
    std::size_t write_result = 0;
    int close_calls = 0;
    std::size_t write_calls = 0;
    std::vector<std::uint8_t> last_write;
    std::vector<std::vector<std::uint8_t>> writes;

    boost::asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override
    {
        (void)host;
        (void)port;
        co_return connect_result;
    }

    boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override
    {
        (void)buf;
        co_return read_result;
    }

    boost::asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override
    {
        ++write_calls;
        last_write = data;
        writes.push_back(data);
        co_return write_result;
    }

    boost::asio::awaitable<void> close() override
    {
        ++close_calls;
        co_return;
    }
};

}    // namespace

extern "C" int __wrap_shutdown(int sockfd, int how)    
{
    if (g_fail_shutdown_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_shutdown_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_shutdown(sockfd, how);    
}

extern "C" int __wrap_close(int fd)    
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);    
}

TEST(TproxyTcpSessionTest, DirectEcho)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    boost::asio::ip::tcp::acceptor echo_acceptor(ctx);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(echo_acceptor));
    const auto echo_port = echo_acceptor.local_endpoint().port();

    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            boost::asio::ip::tcp::socket echo_socket = co_await echo_acceptor.async_accept(boost::asio::use_awaitable);
            std::array<char, 64> buf = {};
            const auto [read_ec, n] =
                co_await echo_socket.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!read_ec && n > 0)
            {
                co_await boost::asio::async_write(echo_socket, boost::asio::buffer(buf.data(), n), boost::asio::use_awaitable);
            }
            co_return;
        },
        boost::asio::detached);

    boost::asio::ip::tcp::acceptor tproxy_acceptor(ctx);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(tproxy_acceptor));
    const auto tproxy_port = tproxy_acceptor.local_endpoint().port();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 3;

    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), echo_port);

    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            boost::asio::ip::tcp::socket sock = co_await tproxy_acceptor.async_accept(boost::asio::use_awaitable);
            auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(sock), ctx, nullptr, router, 1, cfg, dst_ep);
            session->start();
            co_return;
        },
        boost::asio::detached);

    std::atomic<bool> done{false};
    std::atomic<bool> ok{false};

    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            boost::asio::ip::tcp::socket client(ctx);
            boost::system::error_code ec;
            co_await client.async_connect({boost::asio::ip::make_address("127.0.0.1"), tproxy_port},
                                          boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            const std::string msg = "tproxy-echo";
            co_await boost::asio::async_write(client, boost::asio::buffer(msg), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            std::array<char, 32> buf = {};
            const auto [read_ec, n] = co_await client.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!read_ec && n == msg.size() && std::string(buf.data(), n) == msg)
            {
                ok = true;
            }

            done = true;
            ctx.stop();
            co_return;
        },
        boost::asio::detached);

    boost::asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(5));
    timer.async_wait(
        [&](const boost::system::error_code& ec)
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
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);

    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 2, cfg, dst_ep);

    EXPECT_FALSE(session->should_stop_client_read(boost::system::error_code(), 1));
    EXPECT_TRUE(session->should_stop_client_read(boost::system::error_code(), 0));
    EXPECT_TRUE(session->should_stop_client_read(std::make_error_code(std::errc::invalid_argument), 0));

    EXPECT_FALSE(session->should_stop_backend_read(boost::system::error_code(), 1));
    EXPECT_TRUE(session->should_stop_backend_read(boost::system::error_code(), 0));
    EXPECT_TRUE(session->should_stop_backend_read(std::make_error_code(std::errc::invalid_argument), 0));
}

TEST(TproxyTcpSessionTest, StopReadDecisionExpectedErrors)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);

    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 3, cfg, dst_ep);

    EXPECT_TRUE(session->should_stop_client_read(boost::asio::error::eof, 0));
    EXPECT_TRUE(session->should_stop_client_read(boost::asio::error::operation_aborted, 0));
    EXPECT_TRUE(session->should_stop_client_read(boost::asio::error::bad_descriptor, 0));

    EXPECT_TRUE(session->should_stop_backend_read(boost::asio::error::eof, 0));
    EXPECT_TRUE(session->should_stop_backend_read(boost::asio::error::operation_aborted, 0));
    EXPECT_TRUE(session->should_stop_backend_read(boost::asio::experimental::error::channel_closed, 0));
}

TEST(TproxyTcpSessionTest, CloseBackendOnceIsIdempotent)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 4, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    mux::test::run_awaitable_void(ctx, session->close_backend_once(backend));
    mux::test::run_awaitable_void(ctx, session->close_backend_once(backend));
    EXPECT_EQ(backend->close_calls, 1);
}

TEST(TproxyTcpSessionTest, WriteClientChunkToBackendTracksActivity)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 5, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    const std::vector<std::uint8_t> buf = {0x01, 0x02, 0x03, 0x04};
    session->last_activity_time_ms_.store(1, std::memory_order_release);

    backend->write_result = 0;
    backend->writes.clear();
    const auto fail = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 3));
    EXPECT_FALSE(fail);
    ASSERT_EQ(backend->last_write.size(), 3U);
    EXPECT_EQ(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);

    backend->write_result = 3;
    backend->writes.clear();
    const auto ok = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 3));
    EXPECT_TRUE(ok);
    EXPECT_GT(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x01, 0x02, 0x03}));

    backend->write_result = 4;
    backend->writes.clear();
    const auto ok_full = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 4));
    EXPECT_TRUE(ok_full);
    EXPECT_GT(session->last_activity_time_ms_.load(std::memory_order_acquire), 1U);
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x01, 0x02, 0x03, 0x04}));

    backend->write_result = 2;
    backend->writes.clear();
    const auto ok_partial = mux::test::run_awaitable(ctx, session->write_client_chunk_to_backend(backend, buf, 4));
    EXPECT_TRUE(ok_partial);
    ASSERT_EQ(backend->writes.size(), 2U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x01, 0x02, 0x03, 0x04}));
    EXPECT_EQ(backend->writes[1], std::vector<std::uint8_t>({0x03, 0x04}));
}

TEST(TproxyTcpSessionTest, ClientToUpstreamClosesBackendWhenWriteFails)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 33, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    backend->write_result = 0;

    const std::uint8_t payload[] = {0x21, 0x43, 0x65};
    boost::asio::write(pair.client, boost::asio::buffer(payload));

    mux::test::run_awaitable_void(ctx, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x21, 0x43, 0x65}));
    EXPECT_EQ(backend->close_calls, 1);
}

TEST(TproxyTcpSessionTest, ConnectBackendReflectsUpstreamResult)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 6, cfg, dst_ep);

    auto backend = std::make_shared<mock_upstream>();
    backend->connect_result = true;
    const auto connect_ok = mux::test::run_awaitable(ctx, session->connect_backend(backend, "127.0.0.1", 80, mux::route_type::kDirect));
    EXPECT_TRUE(connect_ok);

    backend->connect_result = false;
    const auto connect_fail = mux::test::run_awaitable(ctx, session->connect_backend(backend, "127.0.0.1", 80, mux::route_type::kDirect));
    EXPECT_FALSE(connect_fail);
}

TEST(TproxyTcpSessionTest, SelectBackendDirectUsesConfiguredReadTimeout)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.timeout.read = 9;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 26, cfg, dst_ep);

    const auto [route, backend] = mux::test::run_awaitable(ctx, session->select_backend("127.0.0.1"));
    EXPECT_EQ(route, mux::route_type::kDirect);
    const auto direct_backend = std::dynamic_pointer_cast<mux::direct_upstream>(backend);
    ASSERT_NE(direct_backend, nullptr);
    EXPECT_EQ(direct_backend->timeout_sec_, 9U);
}

TEST(TproxyTcpSessionTest, SelectBackendDirectKeepsReadTimeoutZeroAsDisabled)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.timeout.read = 0;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 27, cfg, dst_ep);

    const auto [route, backend] = mux::test::run_awaitable(ctx, session->select_backend("127.0.0.1"));
    EXPECT_EQ(route, mux::route_type::kDirect);
    const auto direct_backend = std::dynamic_pointer_cast<mux::direct_upstream>(backend);
    ASSERT_NE(direct_backend, nullptr);
    EXPECT_EQ(direct_backend->timeout_sec_, 0U);
}

TEST(TproxyTcpSessionTest, SelectBackendProxyWithoutTunnelPoolReturnsNull)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, std::move(router), 28, cfg, dst_ep);

    const auto [route, backend] = mux::test::run_awaitable(ctx, session->select_backend("127.0.0.1"));
    EXPECT_EQ(route, mux::route_type::kProxy);
    EXPECT_EQ(backend, nullptr);
}

TEST(TproxyTcpSessionTest, SelectBackendReturnsBlockedWhenRouterMissing)
{
    boost::asio::io_context ctx;
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, nullptr, 29, cfg, dst_ep);

    const auto [route, backend] = mux::test::run_awaitable(ctx, session->select_backend("127.0.0.1"));
    EXPECT_EQ(route, mux::route_type::kBlock);
    EXPECT_EQ(backend, nullptr);
}

TEST(TproxyTcpSessionTest, RunClosesClientSocketWhenBackendConnectFails)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;

    boost::asio::ip::tcp::acceptor unused_acceptor(ctx);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(unused_acceptor));
    const auto unused_port = unused_acceptor.local_endpoint().port();
    boost::system::error_code close_ec;
    unused_acceptor.close(close_ec);

    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), unused_port);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 12, cfg, dst_ep);

    mux::test::run_awaitable_void(ctx, session->run());
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TproxyTcpSessionTest, RunClosesClientSocketWhenRouteBlocked)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<block_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);

    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 13, cfg, dst_ep);

    mux::test::run_awaitable_void(ctx, session->run());
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TproxyTcpSessionTest, RunRejectsInvalidDestinationBeforeRouting)
{
    boost::asio::io_context ctx;
    auto& stats = mux::statistics::instance();
    const auto blocked_before = stats.routing_blocked();

    {
        auto pair = make_tcp_socket_pair(ctx);
        auto router = std::make_shared<block_router>();
        mux::config const cfg;
        const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("0.0.0.0"), 80);
        auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 130, cfg, dst_ep);
        mux::test::run_awaitable_void(ctx, session->run());
        EXPECT_FALSE(session->socket_.is_open());
    }

    {
        auto pair = make_tcp_socket_pair(ctx);
        auto router = std::make_shared<block_router>();
        mux::config const cfg;
        const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 0);
        auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 131, cfg, dst_ep);
        mux::test::run_awaitable_void(ctx, session->run());
        EXPECT_FALSE(session->socket_.is_open());
    }

    EXPECT_EQ(stats.routing_blocked(), blocked_before);
}

TEST(TproxyTcpSessionTest, CloseClientSocketIgnoresExpectedErrors)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 7, cfg, dst_ep);

    fail_next_shutdown(ENOTCONN);
    fail_next_close(EBADF);
    session->close_client_socket();

    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

TEST(TproxyTcpSessionTest, CloseClientSocketHandlesUnexpectedErrors)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 8, cfg, dst_ep);

    fail_next_shutdown(EPERM);
    fail_next_close(EIO);
    session->close_client_socket();

    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

TEST(TproxyTcpSessionTest, ShutdownClientSendHandlesExpectedAndUnexpectedErrors)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config const cfg;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 9, cfg, dst_ep);

    fail_next_shutdown(EIO);
    session->shutdown_client_send();

    fail_next_shutdown(ENOTCONN);
    session->shutdown_client_send();

    fail_next_shutdown(EBADF);
    session->shutdown_client_send();

    session->close_client_socket();
    pair.client.close();
}

TEST(TproxyTcpSessionTest, StartIdleWatchdogSpawnsAndClosesIdleSocket)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.timeout.idle = 1;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 10, cfg, dst_ep);
    auto backend = std::make_shared<mock_upstream>();

    session->last_activity_time_ms_.store(0, std::memory_order_release);
    session->start_idle_watchdog(backend);
    ctx.run_for(std::chrono::milliseconds(1100));
    ctx.restart();

    EXPECT_EQ(backend->close_calls, 1);
    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

TEST(TproxyTcpSessionTest, StartIdleWatchdogSpawnsAndHandlesCancel)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.timeout.idle = 1;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 11, cfg, dst_ep);
    auto backend = std::make_shared<mock_upstream>();

    boost::asio::steady_timer cancel_timer(ctx);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait(
        [session](const boost::system::error_code&)
        {
            session->idle_timer_.cancel();
            boost::system::error_code ignore;
            session->socket_.close(ignore);
        });

    session->start_idle_watchdog(backend);
    ctx.run();
    ctx.restart();

    EXPECT_EQ(backend->close_calls, 0);
    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

TEST(TproxyTcpSessionTest, IdleWatchdogDisabledWhenIdleTimeoutZero)
{
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.timeout.idle = 0;
    const boost::asio::ip::tcp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 80);
    auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(pair.server), ctx, nullptr, std::move(router), 14, cfg, dst_ep);
    auto backend = std::make_shared<mock_upstream>();

    session->last_activity_time_ms_.store(0, std::memory_order_release);
    session->start_idle_watchdog(backend);
    ctx.run_for(std::chrono::milliseconds(1100));
    ctx.restart();

    EXPECT_EQ(backend->close_calls, 0);
    EXPECT_TRUE(session->socket_.is_open());

    session->close_client_socket();
    pair.client.close();
}
