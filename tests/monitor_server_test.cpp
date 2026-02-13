#include <array>
#include <chrono>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <sys/socket.h>
#include <unistd.h>

#include <asio.hpp>
#include <gtest/gtest.h>

#include "monitor_server.h"
#include "statistics.h"

namespace
{

enum class monitor_fail_mode
{
    kNone = 0,
    kSocket,
    kSocketAlways,
    kReuseAddr,
    kReuseAddrAlways,
    kListen,
    kListenAlways,
};

std::atomic<int> g_monitor_fail_mode{static_cast<int>(monitor_fail_mode::kNone)};
std::atomic<bool> g_fail_accept_once{false};
std::atomic<int> g_fail_accept_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

class monitor_fail_guard
{
   public:
    explicit monitor_fail_guard(const monitor_fail_mode mode)
    {
        g_monitor_fail_mode.store(static_cast<int>(mode), std::memory_order_release);
    }

    ~monitor_fail_guard() { g_monitor_fail_mode.store(static_cast<int>(monitor_fail_mode::kNone), std::memory_order_release); }
};

bool should_fail_monitor_mode(const monitor_fail_mode once_mode, const monitor_fail_mode always_mode)
{
    const auto current = static_cast<monitor_fail_mode>(g_monitor_fail_mode.load(std::memory_order_acquire));
    if (current == always_mode)
    {
        return true;
    }
    if (current == once_mode)
    {
        g_monitor_fail_mode.store(static_cast<int>(monitor_fail_mode::kNone), std::memory_order_release);
        return true;
    }
    return false;
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

std::uint16_t pick_free_port()
{
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor(ioc, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return acceptor.local_endpoint().port();
}

std::string read_response(std::uint16_t port, const std::string& request)
{
    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec)
    {
        return {};
    }

    asio::write(socket, asio::buffer(request), ec);
    if (ec)
    {
        return {};
    }

    std::string out;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(asio::buffer(buffer), ec);
        if (n > 0)
        {
            out.append(buffer.data(), n);
        }
        if (ec == asio::error::eof)
        {
            break;
        }
        if (ec)
        {
            return out;
        }
    }
    return out;
}

std::string request_with_retry(std::uint16_t port, const std::string& request)
{
    for (int i = 0; i < 30; ++i)
    {
        const auto resp = read_response(port, request);
        if (!resp.empty())
        {
            return resp;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return read_response(port, request);
}

void connect_and_close_without_payload(const std::uint16_t port)
{
    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec)
    {
        return;
    }
    socket.close(ec);
}

class monitor_server_env
{
   public:
    template <typename... Args>
    explicit monitor_server_env(Args&&... args) : server_(std::make_shared<mux::monitor_server>(ioc_, std::forward<Args>(args)...))
    {
        server_->start();
        thread_ = std::thread([this]() { ioc_.run(); });
    }

    ~monitor_server_env()
    {
        if (server_ != nullptr)
        {
            server_->stop();
        }
        ioc_.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

   private:
    asio::io_context ioc_;
    std::shared_ptr<mux::monitor_server> server_;
    std::thread thread_;
};

}    // namespace

extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_listen(int sockfd, int backlog);
extern "C" int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
extern "C" int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
extern "C" int __real_close(int fd);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (should_fail_monitor_mode(monitor_fail_mode::kSocket, monitor_fail_mode::kSocketAlways))
    {
        errno = EMFILE;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_REUSEADDR
        && should_fail_monitor_mode(monitor_fail_mode::kReuseAddr, monitor_fail_mode::kReuseAddrAlways))
    {
        errno = EPERM;
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_listen(int sockfd, int backlog)
{
    if (should_fail_monitor_mode(monitor_fail_mode::kListen, monitor_fail_mode::kListenAlways))
    {
        errno = EACCES;
        return -1;
    }
    return __real_listen(sockfd, backlog);
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

namespace mux
{

TEST(MonitorServerTest, EmptyTokenReturnsMetrics)
{
    statistics::instance().inc_total_connections();

    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());

    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
    EXPECT_NE(resp.find("socks_total_connections "), std::string::npos);
    EXPECT_NE(resp.find("socks_auth_failures_total "), std::string::npos);
}

TEST(MonitorServerTest, TokenRequiredAndRateLimit)
{
    const auto port = pick_free_port();
    monitor_server_env env(port, std::string("secret"), 500);

    const auto unauth = read_response(port, "no token\n");
    EXPECT_TRUE(unauth.empty());

    const auto authed = request_with_retry(port, "token=secret\n");
    EXPECT_NE(authed.find("socks_total_connections "), std::string::npos);

    const auto limited = read_response(port, "token=secret\n");
    EXPECT_TRUE(limited.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(550));
    const auto after_window = read_response(port, "token=secret\n");
    EXPECT_NE(after_window.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, EscapesPrometheusLabels)
{
    auto& stats = statistics::instance();
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "line1\"x\\y\nline2");

    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());
    const auto resp = request_with_retry(port, "metrics\n");

    EXPECT_NE(resp.find("reason=\"short_id\""), std::string::npos);
    EXPECT_NE(resp.find("sni=\"line1\\\"x\\\\y\\nline2\""), std::string::npos);
}

TEST(MonitorServerTest, ConstructWhenPortAlreadyInUse)
{
    const auto port = pick_free_port();

    asio::io_context guard_ioc;
    asio::ip::tcp::acceptor guard(guard_ioc);
    asio::error_code ec;
    guard.open(asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    guard.set_option(asio::socket_base::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    guard.bind(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    ASSERT_FALSE(ec);
    guard.listen(asio::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec);

    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
}

TEST(MonitorServerTest, ConstructorHandlesInvalidBindHost)
{
    const auto port = pick_free_port();
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port, std::string("token"), 10);
    auto bad_server = std::make_shared<monitor_server>(ioc, std::string("bad host"), port, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(bad_server, nullptr);
    bad_server->start();
    ioc.poll();
}

TEST(MonitorServerTest, ConstructorHandlesOpenFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kSocketAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
}

TEST(MonitorServerTest, ConstructorHandlesReuseAddressFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kReuseAddrAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
}

TEST(MonitorServerTest, ConstructorHandlesListenFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kListenAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
}

TEST(MonitorServerTest, StopClosesAcceptorAndRejectsNewConnections)
{
    const auto port = pick_free_port();
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();

    std::thread runner([&ioc]() { ioc.run(); });

    const auto before_stop = request_with_retry(port, "metrics\n");
    EXPECT_NE(before_stop.find("socks_uptime_seconds "), std::string::npos);

    server->stop();

    bool rejected = false;
    for (int i = 0; i < 30; ++i)
    {
        if (read_response(port, "metrics\n").empty())
        {
            rejected = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(rejected);

    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, StopLogsAcceptorCloseFailureBranch)
{
    const auto port = pick_free_port();
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();

    std::thread runner([&ioc]() { ioc.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    fail_next_close(EIO);
    server->stop();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, AcceptFailureRetriesAndServesRequest)
{
    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());

    fail_next_accept(EIO);
    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, SessionReadErrorPathStillAcceptsNextClient)
{
    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());

    connect_and_close_without_payload(port);
    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

}    // namespace mux
