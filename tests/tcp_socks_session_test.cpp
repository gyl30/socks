#include <memory>
#include <string>
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
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/as_tuple.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>

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
    std::vector<std::pair<std::error_code, std::vector<std::uint8_t>>> read_sequence;

    asio::awaitable<bool> connect(const std::string& host, std::uint16_t port) override
    {
        (void)host;
        (void)port;
        co_return connect_result;
    }

    asio::awaitable<std::pair<std::error_code, std::size_t>> read(std::vector<std::uint8_t>& buf) override
    {
        if (read_sequence.empty())
        {
            co_return std::make_pair(asio::error::eof, 0U);
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

    asio::awaitable<std::size_t> write(const std::vector<std::uint8_t>& data) override
    {
        writes.push_back(data);
        co_return write_result;
    }

    asio::awaitable<void> close() override
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

    void add_block_domain(const std::string& domain)
    {
        block_domain_matcher()->add(domain);
    }

    void add_direct_cidr(const std::string& cidr)
    {
        direct_ip_matcher()->add_rule(cidr);
    }

    void add_proxy_domain(const std::string& domain)
    {
        proxy_domain_matcher()->add(domain);
    }
};

struct tcp_socket_pair
{
    asio::ip::tcp::socket client;
    asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(asio::io_context& io_context)
{
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket client(io_context);
    asio::ip::tcp::socket server(io_context);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(server);
    return tcp_socket_pair{std::move(client), std::move(server)};
}

std::shared_ptr<mux::tcp_socks_session> make_tcp_session(asio::io_context& io_context,
                                                         asio::ip::tcp::socket socket,
                                                         std::shared_ptr<mux::mux_tunnel_impl<asio::ip::tcp::socket>> tunnel = nullptr)
{
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.idle = 1;
    return std::make_shared<mux::tcp_socks_session>(
        std::move(socket), io_context, std::move(tunnel), std::move(router), 1, timeout_cfg);
}

std::shared_ptr<mux::tcp_socks_session> make_tcp_session_with_router(asio::io_context& io_context,
                                                                     asio::ip::tcp::socket socket,
                                                                     std::shared_ptr<mux::router> router,
                                                                     std::shared_ptr<mux::mux_tunnel_impl<asio::ip::tcp::socket>> tunnel = nullptr,
                                                                     const std::uint32_t sid = 1,
                                                                     const std::uint16_t idle_timeout_sec = 1)
{
    mux::config::timeout_t timeout_cfg{};
    timeout_cfg.idle = idle_timeout_sec;
    return std::make_shared<mux::tcp_socks_session>(
        std::move(socket), io_context, std::move(tunnel), std::move(router), sid, timeout_cfg);
}

std::shared_ptr<mux::mux_tunnel_impl<asio::ip::tcp::socket>> make_test_tunnel(asio::io_context& io_context,
                                                                                const std::uint32_t conn_id = 9)
{
    return std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

TEST(TcpSocksSessionTest, CreateBackendReturnsNullForBlockRoute)
{
    asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};

    auto session = std::make_shared<mux::tcp_socks_session>(
        asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    EXPECT_EQ(session->create_backend(mux::route_type::kBlock), nullptr);
}

extern "C" int __real_shutdown(int fd, int how);
extern "C" int __real_close(int fd);

extern "C" int __wrap_shutdown(int fd, int how)
{
    if (g_fail_shutdown_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_shutdown_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_shutdown(fd, how);
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

TEST(TcpSocksSessionTest, CreateBackendReturnsDirectAndProxy)
{
    asio::io_context io_context;
    auto router = std::make_shared<mux::router>();
    mux::config::timeout_t timeout_cfg{};

    auto session = std::make_shared<mux::tcp_socks_session>(
        asio::ip::tcp::socket(io_context), io_context, nullptr, std::move(router), 1, timeout_cfg);

    EXPECT_NE(session->create_backend(mux::route_type::kDirect), nullptr);
    EXPECT_NE(session->create_backend(mux::route_type::kProxy), nullptr);
}

TEST(TcpSocksSessionTest, ReplySuccessWritesSocksResponse)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    EXPECT_TRUE(mux::test::run_awaitable(io_context, session->reply_success()));

    std::uint8_t res[10] = {0};
    asio::read(pair.client, asio::buffer(res));
    EXPECT_EQ(res[0], socks::kVer);
    EXPECT_EQ(res[1], socks::kRepSuccess);
}

TEST(TcpSocksSessionTest, ReplySuccessFailsWhenServerSocketClosed)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    session->socket_.close();

    EXPECT_FALSE(mux::test::run_awaitable(io_context, session->reply_success()));
}

TEST(TcpSocksSessionTest, ConnectBackendSuccessAndFailure)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    auto backend_ok = std::make_shared<fake_upstream>();
    backend_ok->connect_result = true;
    EXPECT_TRUE(mux::test::run_awaitable(
        io_context, session->connect_backend(backend_ok, "example.com", 443, mux::route_type::kDirect)));

    auto backend_fail = std::make_shared<fake_upstream>();
    backend_fail->connect_result = false;
    EXPECT_FALSE(mux::test::run_awaitable(
        io_context, session->connect_backend(backend_fail, "example.com", 443, mux::route_type::kProxy)));

    std::uint8_t res[10] = {0};
    asio::read(pair.client, asio::buffer(res));
    EXPECT_EQ(res[0], socks::kVer);
    EXPECT_EQ(res[1], socks::kRepHostUnreach);
}

TEST(TcpSocksSessionTest, CloseBackendOnceIsIdempotentAndHandlesNull)
{
    asio::io_context io_context;
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
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->write_result = 3;

    const std::uint8_t payload[] = {0x10, 0x20, 0x30};
    asio::write(pair.client, asio::buffer(payload));
    pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x10, 0x20, 0x30}));
}

TEST(TcpSocksSessionTest, ClientToUpstreamStopsWhenBackendWriteFails)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->write_result = 0;

    const std::uint8_t payload[] = {0x01, 0x02};
    asio::write(pair.client, asio::buffer(payload));

    mux::test::run_awaitable_void(io_context, session->client_to_upstream(backend));
    ASSERT_EQ(backend->writes.size(), 1U);
    EXPECT_EQ(backend->writes[0], std::vector<std::uint8_t>({0x01, 0x02}));
}

TEST(TcpSocksSessionTest, UpstreamToClientWritesDataThenStopsOnError)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->read_sequence.push_back({std::error_code{}, {0xAA, 0xBB}});
    backend->read_sequence.push_back({asio::error::eof, {}});

    mux::test::run_awaitable_void(io_context, session->upstream_to_client(backend));

    std::uint8_t buf[2] = {0};
    asio::read(pair.client, asio::buffer(buf));
    EXPECT_EQ(buf[0], 0xAA);
    EXPECT_EQ(buf[1], 0xBB);
}

TEST(TcpSocksSessionTest, RunReturnsNotAllowedWhenRouteBlocked)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_block_domain("blocked.test");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("blocked.test", 80));

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepNotAllowed);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, RunReturnsHostUnreachWhenDirectConnectFails)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("non-existent.invalid", 80));

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartSpawnsRunAndReturnsErrorCodeForBlockedRoute)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_block_domain("blocked.test");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    session->start("blocked.test", 80);
    io_context.run();
    io_context.restart();

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepNotAllowed);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartSpawnsRunAndReturnsHostUnreachForProxyWithoutTunnel)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    session->start("203.0.113.1", 443);
    io_context.run();
    io_context.restart();

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, CloseClientSocketHandlesOpenAndClosedSockets)
{
    asio::io_context io_context;
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
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    std::error_code ec;
    session->socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    ASSERT_FALSE(ec);

    session->close_client_socket();
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, CloseClientSocketHandlesUnexpectedShutdownAndCloseErrors)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    fail_next_shutdown(EIO);
    fail_next_close(EIO);
    session->close_client_socket();

    std::error_code ec;
    if (session->socket_.is_open())
    {
        session->socket_.close(ec);
    }
}

TEST(TcpSocksSessionTest, CloseClientSocketIgnoresBadDescriptorCloseError)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    fail_next_close(EBADF);
    session->close_client_socket();

    std::error_code ec;
    if (session->socket_.is_open())
    {
        session->socket_.close(ec);
    }
}

TEST(TcpSocksSessionTest, ReplyErrorWritesSocksErrorResponse)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));

    mux::test::run_awaitable_void(io_context, session->reply_error(socks::kRepConnRefused));

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepConnRefused);
}

TEST(TcpSocksSessionTest, IdleWatchdogClosesBackendAndSocketWhenTimedOut)
{
    asio::io_context io_context;
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
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait([session](const std::error_code&)
                            {
                                session->idle_timer_.cancel();
                            });

    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));

    EXPECT_EQ(backend->close_calls, 0U);
    EXPECT_TRUE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, StartIdleWatchdogSpawnsAndHandlesCancel)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();

    asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait([session](const std::error_code&)
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
    asio::io_context io_context;
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
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    session->socket_.close();

    mux::test::run_awaitable_void(io_context, session->idle_watchdog(backend));
    EXPECT_EQ(backend->close_calls, 0U);
}

TEST(TcpSocksSessionTest, UpstreamToClientStopsWhenClientWriteFails)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto session = make_tcp_session(io_context, std::move(pair.server));
    auto backend = std::make_shared<fake_upstream>();
    backend->read_sequence.push_back({std::error_code{}, {0xAA}});
    session->socket_.close();

    mux::test::run_awaitable_void(io_context, session->upstream_to_client(backend));
}

TEST(TcpSocksSessionTest, RunDirectPathRepliesSuccessAndForwardsPayload)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_direct_cidr("127.0.0.1/32");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    asio::ip::tcp::acceptor backend_acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const std::uint16_t backend_port = backend_acceptor.local_endpoint().port();
    asio::co_spawn(
        io_context,
        [&backend_acceptor]() -> asio::awaitable<void>
        {
            auto backend_socket = co_await backend_acceptor.async_accept(asio::use_awaitable);
            std::array<std::uint8_t, 4> buf = {0};
            std::error_code read_ec;
            const std::size_t n =
                co_await backend_socket.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, read_ec));
            if (!read_ec && n > 0)
            {
                (void)co_await asio::async_write(backend_socket, asio::buffer(buf.data(), n), asio::as_tuple(asio::use_awaitable));
            }
            std::error_code ignore;
            backend_socket.close(ignore);
            co_return;
        },
        asio::detached);

    const std::array<std::uint8_t, 4> payload = {0x11, 0x22, 0x33, 0x44};
    asio::write(pair.client, asio::buffer(payload));
    pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->run("127.0.0.1", backend_port));

    std::uint8_t rep[10] = {0};
    asio::read(pair.client, asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);

    std::array<std::uint8_t, 4> echoed = {0};
    asio::read(pair.client, asio::buffer(echoed));
    EXPECT_EQ(echoed, payload);
}

TEST(TcpSocksSessionTest, RunStopsWhenReplySuccessWriteFails)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    router->add_direct_cidr("127.0.0.1/32");
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);
    session->socket_.close();

    asio::ip::tcp::acceptor backend_acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const std::uint16_t backend_port = backend_acceptor.local_endpoint().port();
    asio::co_spawn(
        io_context,
        [&backend_acceptor]() -> asio::awaitable<void>
        {
            auto backend_socket = co_await backend_acceptor.async_accept(asio::use_awaitable);
            std::error_code ignore;
            backend_socket.close(ignore);
            co_return;
        },
        asio::detached);

    mux::test::run_awaitable_void(io_context, session->run("127.0.0.1", backend_port));
}

TEST(TcpSocksSessionTest, RunReturnsHostUnreachWhenProxyTunnelUnavailable)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router);

    mux::test::run_awaitable_void(io_context, session->run("198.51.100.2", 443));

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
    EXPECT_FALSE(session->socket_.is_open());
}

TEST(TcpSocksSessionTest, RunProxyPathRepliesSuccessWhenAckAccepted)
{
    asio::io_context io_context;
    auto pair = make_tcp_socket_pair(io_context);
    auto router = std::make_shared<configured_router>();
    auto tunnel = make_test_tunnel(io_context, 91);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(io_context);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(::testing::Return(91));
    ON_CALL(*mock_conn, mock_send_async(_, _, _)).WillByDefault(::testing::Return(std::error_code{}));

    std::vector<std::uint8_t> dat_payload;
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdSyn, _)).WillOnce(::testing::Return(std::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(_, _))
        .WillOnce([&io_context](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> stream_iface) -> bool
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
                      asio::post(io_context, [stream, ack_data]() { stream->on_data(ack_data); });

                      asio::post(io_context, [stream]() { stream->on_data(std::vector<std::uint8_t>{0xBE, 0xEF}); });
                      asio::post(io_context, [stream]() { stream->on_close(); });
                      return true;
                  });
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdDat, _))
        .WillOnce([&dat_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
                  {
                      dat_payload = payload;
                      return std::error_code{};
                  });
    EXPECT_CALL(*mock_conn, mock_send_async(_, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));

    const auto session = make_tcp_session_with_router(io_context, std::move(pair.server), router, tunnel);
    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33};
    asio::write(pair.client, asio::buffer(payload));
    pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);

    mux::test::run_awaitable_void(io_context, session->run("203.0.113.7", 443));

    std::uint8_t rep[10] = {0};
    asio::read(pair.client, asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);

    std::uint8_t echoed[2] = {0};
    asio::read(pair.client, asio::buffer(echoed));
    EXPECT_EQ(echoed[0], 0xBE);
    EXPECT_EQ(echoed[1], 0xEF);
    EXPECT_EQ(dat_payload, payload);
}

}    // namespace
