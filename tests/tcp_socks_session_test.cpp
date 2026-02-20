// NOLINTBEGIN(misc-non-private-member-variables-in-classes, modernize-use-ranges, performance-unnecessary-value-param,
// readability-function-cognitive-complexity) NOLINTBEGIN(bugprone-unused-return-value, misc-include-cleaner)
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <array>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <utility>
#include <system_error>
#include <atomic>
#include <cerrno>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include <unistd.h>

extern "C"
{
#include <openssl/evp.h>
}

#define private public
#include "tcp_socks_session.h"
#undef private

#include "protocol.h"
#include "mux_codec.h"
#include "mux_tunnel.h"
#include "test_util.h"
#include "mock_mux_connection.h"

namespace
{

using ::testing::_;

std::atomic<bool> g_fail_shutdown_once{false};
std::atomic<int> g_fail_shutdown_errno{EIO};
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

class fake_upstream final : public mux::upstream
{
   public:
    bool connect_result = true;
    std::size_t write_result = 0;
    std::size_t close_calls = 0;
    std::vector<std::vector<std::uint8_t>> writes;
    std::vector<std::pair<boost::system::error_code, std::vector<std::uint8_t>>> read_sequence;

    boost::asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override
    {
        (void)host;
        (void)port;
        co_return connect_result;
    }

    boost::asio::awaitable<std::pair<boost::system::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override
    {
        if (read_sequence.empty())
        {
            co_return std::make_pair(boost::asio::error::eof, 0U);
        }
        auto [ec, data] = std::move(read_sequence.front());
        read_sequence.erase(read_sequence.begin());
        if (!ec && !data.empty())
        {
            if (buf.size() < data.size())
            {
                buf.resize(data.size());
            }
            std::copy(data.begin(), data.end(), buf.begin());
        }
        co_return std::make_pair(ec, data.size());
    }

    boost::asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override
    {
        writes.push_back(data);
        co_return write_result;
    }

    boost::asio::awaitable<void> close() override
    {
        ++close_calls;
        co_return;
    }
};

class configured_router final : public mux::router
{
   public:
    configured_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();
    }

    void add_block_domain(const std::string& domain) { block_domain_matcher()->add(domain); }

    void add_direct_cidr(const std::string& cidr) { direct_ip_matcher()->add_rule(cidr); }

    void add_proxy_domain(const std::string& domain) { proxy_domain_matcher()->add(domain); }
};

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

std::shared_ptr<mux::tcp_socks_session> make_tcp_session(boost::asio::io_context& io_context,
                                                         boost::asio::ip::tcp::socket socket,
                                                         std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel = nullptr)
{
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.idle = 1;
    return std::make_shared<mux::tcp_socks_session>(std::move(socket), io_context, std::move(tunnel), std::move(router), 1, timeout_cfg);
}

std::shared_ptr<mux::tcp_socks_session> make_tcp_session_with_router(
    boost::asio::io_context& io_context,
    boost::asio::ip::tcp::socket socket,
    std::shared_ptr<mux::router> router,
    std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel = nullptr,
    const std::uint32_t sid = 1,
    const std::uint16_t idle_timeout_sec = 1)
{
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.idle = idle_timeout_sec;
    return std::make_shared<mux::tcp_socks_session>(std::move(socket), io_context, std::move(tunnel), std::move(router), sid, timeout_cfg);
}

std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> make_test_tunnel(boost::asio::io_context& io_context,
                                                                                     const std::uint32_t conn_id = 9)
{
    return std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

TEST(TcpSocksSessionTest, CreateBackendReturnsNullForBlockRoute)
{
    boost::asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t const timeout_cfg{};

    auto session =
        std::make_shared<mux::tcp_socks_session>(boost::asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    EXPECT_EQ(session->create_backend(mux::route_type::kBlock), nullptr);
}

extern "C" int __real_shutdown(int fd, int how);    // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_close(int fd);                // NOLINT(bugprone-reserved-identifier)

extern "C" int __wrap_shutdown(int fd, int how)    // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_shutdown_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_shutdown_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_shutdown(fd, how);    // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_close(int fd)    // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);    // NOLINT(bugprone-reserved-identifier)
}

TEST(TcpSocksSessionTest, CreateBackendReturnsDirectAndProxy)
{
    boost::asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t const timeout_cfg{};

    auto session =
        std::make_shared<mux::tcp_socks_session>(boost::asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    EXPECT_NE(session->create_backend(mux::route_type::kDirect), nullptr);
    EXPECT_NE(session->create_backend(mux::route_type::kProxy), nullptr);
}

TEST(TcpSocksSessionTest, CreateBackendDirectUsesConfiguredReadTimeout)
{
    boost::asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.read = 7;

    auto session =
        std::make_shared<mux::tcp_socks_session>(boost::asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    const auto backend = session->create_backend(mux::route_type::kDirect);
    const auto direct_backend = std::dynamic_pointer_cast<mux::direct_upstream>(backend);
    ASSERT_NE(direct_backend, nullptr);
    EXPECT_EQ(direct_backend->timeout_sec_, 7U);
}

TEST(TcpSocksSessionTest, CreateBackendDirectKeepsReadTimeoutZeroAsDisabled)
{
    boost::asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.read = 0;

    auto session =
        std::make_shared<mux::tcp_socks_session>(boost::asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    const auto backend = session->create_backend(mux::route_type::kDirect);
    const auto direct_backend = std::dynamic_pointer_cast<mux::direct_upstream>(backend);
    ASSERT_NE(direct_backend, nullptr);
    EXPECT_EQ(direct_backend->timeout_sec_, 0U);
}

TEST(TcpSocksSessionTest, ReplySuccessWritesSocksResponse)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    EXPECT_TRUE(mux::test::run_awaitable(io_context, session->reply_success()));

    std::uint8_t res[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(res));
    EXPECT_EQ(res[0], socks::kVer);
    EXPECT_EQ(res[1], socks::kRepSuccess);
}

TEST(TcpSocksSessionTest, ReplySuccessFailsWhenServerSocketClosed)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    session->socket_.close();

    EXPECT_FALSE(mux::test::run_awaitable(io_context, session->reply_success()));
}

TEST(TcpSocksSessionTest, ConnectBackendSuccessAndFailure)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    auto backend_ok = std::make_shared<fake_upstream>();
    backend_ok->connect_result = true;
    EXPECT_TRUE(mux::test::run_awaitable(io_context, session->connect_backend(backend_ok, "example.com", 443, mux::route_type::kDirect)));

    auto backend_fail = std::make_shared<fake_upstream>();
    backend_fail->connect_result = false;
    EXPECT_FALSE(mux::test::run_awaitable(io_context, session->connect_backend(backend_fail, "example.com", 443, mux::route_type::kProxy)));

    std::uint8_t res[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(res));
    EXPECT_EQ(res[0], socks::kVer);
    EXPECT_EQ(res[1], socks::kRepHostUnreach);
}

TEST(TcpSocksSessionTest, CloseBackendOnceIsIdempotentAndHandlesNull)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    mux::test::run_awaitable_void(io_context, session->close_backend_once(backend));
    mux::test::run_awaitable_void(io_context, session->close_backend_once(backend));
    EXPECT_EQ(backend->close_calls, 1U);

    mux::test::run_awaitable_void(io_context, session->close_backend_once(nullptr));
    EXPECT_EQ(backend->close_calls, 1U);
}

TEST(TcpSocksSessionTest, ClientToUpstreamWritesDataAndStopsOnEof)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->write_result = 3;

    const std::uint8_t payload[] = {0x10, 0x20, 0x30};
    boost::asio::write(pair.client, boost::asio::buffer(payload));
    pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x10, 0x20, 0x30}));
    EXPECT_EQ(backend->close_calls, 0U);
}

TEST(TcpSocksSessionTest, ClientToUpstreamStopsWhenBackendWriteFails)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->write_result = 0;

    const std::uint8_t payload[] = {0x01, 0x02};
    boost::asio::write(pair.client, boost::asio::buffer(payload));

    mux::test::run_awaitable_void(io_context, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x01, 0x02}));
    EXPECT_EQ(backend->close_calls, 1U);
}

TEST(TcpSocksSessionTest, ClientToUpstreamHandlesPartialBackendWrites)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->write_result = 2;

    const std::uint8_t payload[] = {0xA1, 0xB2, 0xC3, 0xD4};
    boost::asio::write(pair.client, boost::asio::buffer(payload));
    pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 2U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0xA1, 0xB2, 0xC3, 0xD4}));
    EXPECT_EQ(backend->writes[1], std::vector<std::uint8_t>({0xC3, 0xD4}));
}

TEST(TcpSocksSessionTest, UpstreamToClientWritesDataThenStopsOnError)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->read_sequence.push_back({boost::system::error_code{}, {0xAA, 0xBB}});
    backend->read_sequence.push_back({boost::asio::error::eof, {}});

    mux::test::run_awaitable_void(io_context, session->upstream_to_client(backend));

    std::uint8_t buf[2] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(buf));
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[1], 0xBB);
}

TEST(TcpSocksSessionTest, RunReturnsNotAllowedWhenRouteBlocked)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_block_domain("blocked.test");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("blocked.test", 80));

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepNotAllowed);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, RunReturnsGeneralFailureWhenRouterMissing)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    mux::config::timeout_t const timeout_cfg{};
    auto session = std::make_shared<mux::tcp_socks_session>(std::move(pair.server), io_context, nullptr, nullptr, 1, timeout_cfg);

    mux::test::run_awaitable_void(io_context, session->run("example.test", 80));

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, RunReturnsHostUnreachWhenDirectConnectFails)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("non-existent.invalid", 80));

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartSpawnsRunAndReturnsErrorCodeForBlockedRoute)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_block_domain("blocked.test");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    session->start("blocked.test", 80);
    io_context.run();
    io_context.restart();

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepNotAllowed);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartSpawnsRunAndReturnsHostUnreachForProxyWithoutTunnel)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    session->start("203.0.113.1", 443);
    io_context.run();
    io_context.restart();

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, CloseClientSocketHandlesOpenAndClosedSockets)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    EXPECT_TRUE(session->socket_.is_open());
    session->close_client_socket();
    EXPECT_FALSE(session->socket_.is_open());

    session->close_client_socket();
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, CloseClientSocketHandlesNotConnectedSocket)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    boost::system::error_code ec;
    session->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ASSERT_FALSE(ec);

    session->close_client_socket();
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, CloseClientSocketHandlesUnexpectedShutdownAndCloseErrors)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    fail_next_shutdown(EIO);
    fail_next_close(EIO);
    session->close_client_socket();

    boost::system::error_code ec;
    if (session->socket_.is_open())
    {
        session->socket_.close(ec);
    }
}

TEST(TcpSocksSessionTest, CloseClientSocketIgnoresBadDescriptorCloseError)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    fail_next_close(EBADF);
    session->close_client_socket();

    boost::system::error_code ec;
    if (session->socket_.is_open())
    {
        session->socket_.close(ec);
    }
}

TEST(TcpSocksSessionTest, ReplyErrorWritesSocksErrorResponse)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    mux::test::run_awaitable_void(io_context, session->reply_error(socks::kRepConnRefused));

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepConnRefused);
}

TEST(TcpSocksSessionTest, IdleWatchdogClosesBackendAndSocketWhenTimedOut)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    session->last_activity_time_ms_.store(0, std::memory_order_release);
    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));

    EXPECT_EQ(backend->close_calls, 1U);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, IdleWatchdogBreaksWhenTimerCanceled)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    boost::asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait([session](const boost::system::error_code&) { session->idle_timer_.cancel(); });

    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));

    EXPECT_EQ(backend->close_calls, 0U);
    EXPECT_TRUE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartIdleWatchdogSpawnsAndHandlesCancel)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    boost::asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait(
        [session](const boost::system::error_code&)
        {
            session->idle_timer_.cancel();
            session->socket_.close();
        });

    session->start_idle_watchdog(backend);
    io_context.run();
    io_context.restart();

    EXPECT_EQ(backend->close_calls, 0U);
}

TEST(TcpSocksSessionTest, StartIdleWatchdogSpawnsAndClosesIdleSession)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    session->last_activity_time_ms_.store(0, std::memory_order_release);
    session->start_idle_watchdog(backend);
    io_context.run_for(std::chrono::milliseconds(1100));
    io_context.restart();

    EXPECT_EQ(backend->close_calls, 1U);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, IdleWatchdogReturnsImmediatelyWhenSocketClosed)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    session->socket_.close();

    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));
    EXPECT_EQ(backend->close_calls, 0U);
}

TEST(TcpSocksSessionTest, IdleWatchdogDisabledWhenIdleTimeoutZero)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.idle = 0;
    auto session = std::make_shared<mux::tcp_socks_session>(std::move(pair.server), io_context, nullptr, std::move(router), 88, timeout_cfg);
    auto backend = std::make_shared<fake_upstream>();

    session->last_activity_time_ms_.store(0, std::memory_order_release);
    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));
    EXPECT_EQ(backend->close_calls, 0U);
    EXPECT_TRUE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, UpstreamToClientStopsWhenClientWriteFails)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->read_sequence.push_back({boost::system::error_code{}, {0xAA}});
    session->socket_.close();

    mux::test::run_awaitable_void(io_context, session->upstream_to_client(backend));
}

TEST(TcpSocksSessionTest, RunDirectPathRepliesSuccessAndForwardsPayload)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_direct_cidr("127.0.0.1/32");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    boost::asio::ip::tcp::acceptor backend_acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(backend_acceptor));
    const std::uint16_t backend_port = backend_acceptor.local_endpoint().port();
    boost::asio::co_spawn(
        io_context,
        [&backend_acceptor]() -> boost::asio::awaitable<void>
        {
            auto backend_socket = co_await backend_acceptor.async_accept(boost::asio::use_awaitable);
            std::array<std::uint8_t, 4> buf = {0};
            boost::system::error_code read_ec;
            const std::size_t n =
                co_await backend_socket.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, read_ec));
            if (!read_ec && n > 0)
            {
                (void)co_await boost::asio::async_write(
                    backend_socket, boost::asio::buffer(buf.data(), n), boost::asio::as_tuple(boost::asio::use_awaitable));
            }
            boost::system::error_code ignore;
            backend_socket.close(ignore);
            co_return;
        },
        boost::asio::detached);

    const std::array<std::uint8_t, 4> payload = {0x11, 0x22, 0x33, 0x44};
    boost::asio::write(pair.client, boost::asio::buffer(payload));
    pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->run("127.0.0.1", backend_port));

    std::uint8_t rep[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);

    std::array<std::uint8_t, 4> echoed = {0};
    boost::asio::read(pair.client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);
}

TEST(TcpSocksSessionTest, RunStopsWhenReplySuccessWriteFails)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_direct_cidr("127.0.0.1/32");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);
    session->socket_.close();

    boost::asio::ip::tcp::acceptor backend_acceptor(io_context);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(backend_acceptor));
    const std::uint16_t backend_port = backend_acceptor.local_endpoint().port();
    boost::asio::co_spawn(
        io_context,
        [&backend_acceptor]() -> boost::asio::awaitable<void>
        {
            auto backend_socket = co_await backend_acceptor.async_accept(boost::asio::use_awaitable);
            boost::system::error_code ignore;
            backend_socket.close(ignore);
            co_return;
        },
        boost::asio::detached);

    mux::test::run_awaitable_void(io_context, session->run("127.0.0.1", backend_port));
}

TEST(TcpSocksSessionTest, RunReturnsHostUnreachWhenProxyTunnelUnavailable)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("198.51.100.2", 443));

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, RunProxyPathRepliesSuccessWhenAckAccepted)
{
    boost::asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto tunnel = make_test_tunnel(io_context, 91);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(io_context);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(::testing::Return(91));
    ON_CALL(*mock_conn, mock_send_async(_, _, _)).WillByDefault(::testing::Return(boost::system::error_code{}));

    std::vector<std::uint8_t> dat_payload;
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdSyn, _)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(_, _))
        .WillOnce(
            [&io_context](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> stream_iface) -> bool
            {
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(stream_iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }

                mux::ack_payload ack{};
                ack.socks_rep = socks::kRepSuccess;
                std::vector<std::uint8_t> ack_data;
                mux::mux_codec::encode_ack(ack, ack_data);
                boost::asio::post(io_context, [stream, ack_data]() { stream->on_data(ack_data); });

                boost::asio::post(io_context, [stream]() { stream->on_data(std::vector<std::uint8_t>{0xBE, 0xEF}); });
                boost::asio::post(io_context, [stream]() { stream->on_close(); });
                return true;
            });
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdDat, _))
        .WillOnce(
            [&dat_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                dat_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    const auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router, tunnel);
    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33};
    boost::asio::write(pair.client, boost::asio::buffer(payload));
    pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->run("203.0.113.7", 443));

    std::uint8_t rep[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);

    std::uint8_t echoed[2] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(echoed));
    EXPECT_EQ(echoed[0], 0xBE);
    EXPECT_EQ(echoed[1], 0xEF);
    EXPECT_EQ(dat_payload, payload);
}

}    // namespace
// NOLINTEND(bugprone-unused-return-value, misc-include-cleaner)
// NOLINTEND(misc-non-private-member-variables-in-classes, modernize-use-ranges, performance-unnecessary-value-param,
// readability-function-cognitive-complexity)
