#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <system_error>
#include <future>
#include <atomic>
#include <cerrno>

#include <gtest/gtest.h>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/tcp.hpp>

#include <sys/socket.h>
#include <netinet/tcp.h>

#include "context_pool.h"
#define private public
#include "socks_client.h"
#undef private

using mux::io_context_pool;

namespace
{

std::atomic<bool> g_fail_socket_once{false};
std::atomic<int> g_fail_socket_errno{EMFILE};
std::atomic<bool> g_fail_reuse_setsockopt_once{false};
std::atomic<int> g_fail_reuse_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_tcp_nodelay_setsockopt_once{false};
std::atomic<int> g_fail_tcp_nodelay_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_accept_once{false};
std::atomic<int> g_fail_accept_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

void fail_next_socket(const int err)
{
    g_fail_socket_errno.store(err, std::memory_order_release);
    g_fail_socket_once.store(true, std::memory_order_release);
}

void fail_next_reuse_setsockopt(const int err)
{
    g_fail_reuse_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_reuse_setsockopt_once.store(true, std::memory_order_release);
}

void fail_next_tcp_nodelay_setsockopt(const int err)
{
    g_fail_tcp_nodelay_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_tcp_nodelay_setsockopt_once.store(true, std::memory_order_release);
}

void fail_next_accept(const int err)
{
    g_fail_accept_errno.store(err, std::memory_order_release);
    g_fail_accept_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
extern "C" int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
extern "C" int __real_close(int fd);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_REUSEADDR && g_fail_reuse_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_reuse_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY && g_fail_tcp_nodelay_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_tcp_nodelay_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept(sockfd, addr, addrlen);
}

extern "C" int __wrap_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept4(sockfd, addr, addrlen, flags);
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

class failing_router final : public mux::router
{
   public:
    bool load() override { return false; }
};

bool wait_for_listen_port(const std::shared_ptr<mux::socks_client>& client)
{
    for (int i = 0; i < 40; ++i)
    {
        if (client->listen_port() != 0)
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

template <typename Func>
auto run_on_io_context(asio::io_context& io_context, Func&& fn) -> decltype(fn())
{
    using result_type = decltype(fn());
    std::promise<result_type> promise;
    auto future = promise.get_future();
    asio::post(io_context,
               [func = std::forward<Func>(fn), promise = std::move(promise)]() mutable
               {
                   promise.set_value(func());
               });
    return future.get();
}

std::size_t session_count(asio::io_context& io_context, const std::shared_ptr<mux::socks_client>& client)
{
    return run_on_io_context(
        io_context,
        [client]()
        {
            auto snapshot = std::atomic_load_explicit(&client->sessions_, std::memory_order_acquire);
            if (snapshot == nullptr)
            {
                return std::size_t{0};
            }
            return snapshot->size();
        });
}

bool acceptor_is_open(asio::io_context& io_context, const std::shared_ptr<mux::socks_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->acceptor_.is_open(); });
}

std::future<void> spawn_accept_local_loop(asio::io_context& io_context, const std::shared_ptr<mux::socks_client>& client)
{
    auto done = std::make_shared<std::promise<void>>();
    auto future = done->get_future();
    asio::co_spawn(
        io_context,
        [client, done]() -> asio::awaitable<void>
        {
            co_await client->accept_local_loop();
            done->set_value();
            co_return;
        },
        asio::detached);
    return future;
}

}    // namespace

TEST(LocalClientTest, BasicStartStop)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10081;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    client->stop();
}

TEST(LocalClientTest, InvalidHexConfig)
{
    io_context_pool pool(1);
    const std::string bad_hex_odd = "ABC";
    const std::string bad_hex_chars = "GG";
    const std::string server_pub_key(64, 'a');

    mux::config cfg1;
    cfg1.outbound.host = "127.0.0.1";
    cfg1.outbound.port = 12345;
    cfg1.socks.port = 10083;
    cfg1.reality.public_key = server_pub_key;
    cfg1.reality.sni = "example.com";
    cfg1.reality.short_id = bad_hex_odd;
    auto client1 = std::make_shared<mux::socks_client>(pool, cfg1);

    mux::config cfg2;
    cfg2.outbound.host = "127.0.0.1";
    cfg2.outbound.port = 12345;
    cfg2.socks.port = 10084;
    cfg2.reality.public_key = server_pub_key;
    cfg2.reality.sni = "example.com";
    cfg2.reality.short_id = bad_hex_chars;
    auto client2 = std::make_shared<mux::socks_client>(pool, cfg2);

    mux::config cfg3;
    cfg3.outbound.host = "127.0.0.1";
    cfg3.outbound.port = 12345;
    cfg3.socks.port = 10085;
    cfg3.reality.public_key = server_pub_key;
    cfg3.reality.sni = "example.com";
    cfg3.reality.short_id = "0102";
    auto client3 = std::make_shared<mux::socks_client>(pool, cfg3);
}

TEST(LocalClientTest, InvalidMaxConnectionsFallback)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10089;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    cfg.limits.max_connections = 0;
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
}

TEST(LocalClientTest, InvalidAuthConfigAborts)
{
    io_context_pool pool(1);
    const std::string bad_hex_odd = "abc";
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 1080;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    cfg.reality.short_id = bad_hex_odd;
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    client->stop();
}

TEST(LocalClientTest, Getters)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10082;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    EXPECT_EQ(client->listen_port(), 10082);
}

TEST(LocalClientTest, StopWhenNotStarted)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10086;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->stop();
}

TEST(LocalClientTest, StopLogsAcceptorCloseFailureBranch)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread runner([&pool]() { pool.run(); });

    client->start();
    ASSERT_TRUE(wait_for_listen_port(client));

    fail_next_close(EIO);
    client->stop();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(LocalClientTest, StopRunsInlineWhenIoContextStopped)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10089;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    std::error_code ec;
    client->acceptor_.open(asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->acceptor_.is_open());

    pool.stop();
    client->stop();
    EXPECT_FALSE(client->acceptor_.is_open());
}

TEST(LocalClientTest, StopRunsWhenIoQueueBlocked)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10096;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    std::error_code ec;
    client->acceptor_.open(asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->acceptor_.is_open());

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    asio::post(
        pool.get_io_context(),
        [&blocker_started, &release_blocker]()
        {
            blocker_started.store(true, std::memory_order_release);
            while (!release_blocker.load(std::memory_order_acquire))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 100 && !blocker_started.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(blocker_started.load(std::memory_order_acquire));

    client->stop();
    EXPECT_FALSE(client->acceptor_.is_open());

    release_blocker.store(true, std::memory_order_release);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(LocalClientTest, StopRunsWhenIoContextNotRunning)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10095;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    std::error_code ec;
    client->acceptor_.open(asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->acceptor_.is_open());

    client->stop();
    EXPECT_FALSE(client->acceptor_.is_open());
    pool.stop();
}

TEST(LocalClientTest, DoubleStop)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10087;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
    client->stop();
}

TEST(LocalClientTest, StartWhileRunningIsIgnored)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10098;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    EXPECT_TRUE(client->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(client->acceptor_.is_open());

    const auto first_port = client->listen_port();
    client->start();
    EXPECT_TRUE(client->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->stop_.load(std::memory_order_acquire));
    EXPECT_TRUE(client->acceptor_.is_open());
    EXPECT_EQ(client->listen_port(), first_port);

    client->stop();
}

TEST(LocalClientTest, StartAfterStopResetsStopFlag)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10097;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    client->stop();
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));

    client->start();
    EXPECT_FALSE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(LocalClientTest, HandshakeFailInvalidServerPubKey)
{
    io_context_pool pool(1);
    const std::string bad_pub(31, 'a');
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10090;
    cfg.reality.public_key = bad_pub;
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}

TEST(LocalClientTest, ConnectFailureLoop)
{
    io_context_pool pool(1);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.port = 10088;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}

TEST(LocalClientTest, DisabledSocksStopsImmediately)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 0;
    cfg.socks.enabled = false;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(LocalClientTest, InvalidListenHostAbortsAcceptLoop)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "not-an-ip";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

TEST(LocalClientTest, ListenPortConflictTriggersSetupFailure)
{
    io_context_pool pool(1);

    asio::io_context blocker_ctx;
    asio::ip::tcp::acceptor blocker(blocker_ctx, {asio::ip::make_address("127.0.0.1"), 0});
    const auto blocked_port = blocker.local_endpoint().port();

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = blocked_port;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(acceptor_is_open(pool.get_io_context(), client));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

TEST(LocalClientTest, NoTunnelSelectionAndSessionPrunePath)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    ASSERT_TRUE(wait_for_listen_port(client));

    asio::io_context connect_ctx;
    asio::ip::tcp::socket first(connect_ctx);
    asio::ip::tcp::socket second(connect_ctx);
    std::error_code ec;
    const asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), client->listen_port());
    first.connect(ep, ec);
    ASSERT_FALSE(ec);
    second.connect(ep, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(2800));
    EXPECT_GT(session_count(pool.get_io_context(), client), 0U);

    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

TEST(LocalClientTest, RouterLoadFailureStopsEarly)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->router_ = std::make_shared<failing_router>();
    client->start();
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(LocalClientTest, AcceptLoopSetupHandlesSocketOpenFailure)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);

    fail_next_socket(EMFILE);
    auto done = spawn_accept_local_loop(pool.get_io_context(), client);
    std::thread runner([&pool]() { pool.run(); });
    EXPECT_EQ(done.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_FALSE(acceptor_is_open(pool.get_io_context(), client));

    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(LocalClientTest, AcceptLoopSetupHandlesReuseAddressFailure)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);

    fail_next_reuse_setsockopt(EPERM);
    auto done = spawn_accept_local_loop(pool.get_io_context(), client);
    std::thread runner([&pool]() { pool.run(); });
    EXPECT_EQ(done.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_FALSE(acceptor_is_open(pool.get_io_context(), client));

    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(LocalClientTest, AcceptLoopLogsRetryOnAcceptError)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);

    auto done = spawn_accept_local_loop(pool.get_io_context(), client);
    std::thread runner([&pool]() { pool.run(); });
    ASSERT_TRUE(wait_for_listen_port(client));

    fail_next_accept(EIO);

    asio::io_context connect_ctx;
    asio::ip::tcp::socket connector(connect_ctx);
    std::error_code ec;
    connector.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), client->listen_port()), ec);
    ASSERT_FALSE(ec);
    connector.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    connector.close(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    client->stop();
    EXPECT_EQ(done.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(LocalClientTest, AcceptLoopHandlesNoDelaySetOptionFailure)
{
    io_context_pool pool(1);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);

    auto done = spawn_accept_local_loop(pool.get_io_context(), client);
    std::thread runner([&pool]() { pool.run(); });
    ASSERT_TRUE(wait_for_listen_port(client));

    fail_next_tcp_nodelay_setsockopt(EPERM);

    asio::io_context connect_ctx;
    asio::ip::tcp::socket connector(connect_ctx);
    std::error_code ec;
    connector.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), client->listen_port()), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    connector.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    connector.close(ec);

    client->stop();
    EXPECT_EQ(done.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}
