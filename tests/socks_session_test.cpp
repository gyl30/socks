
#include <array>
#include <atomic>
#include <cerrno>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <unistd.h>
#include <sys/socket.h>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "protocol.h"
#include "statistics.h"

#define private public
#include "socks_session.h"

#undef private
#include "test_util.h"

std::atomic<bool> g_fail_shutdown_once{false};
std::atomic<int> g_fail_shutdown_errno{EPERM};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

void reset_failure_injections()
{
    g_fail_shutdown_once.store(false, std::memory_order_release);
    g_fail_shutdown_errno.store(EPERM, std::memory_order_release);
    g_fail_close_once.store(false, std::memory_order_release);
    g_fail_close_errno.store(EIO, std::memory_order_release);
}

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

// NOLINTBEGIN(bugprone-reserved-identifier)
// GNU ld --wrap requires __real_ / __wrap_ symbol names.
extern "C" int __real_shutdown(int sockfd, int how);
extern "C" int __real_close(int fd);

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
        const int injected_errno = g_fail_close_errno.load(std::memory_order_acquire);
        // Keep fd lifecycle realistic while still surfacing close failure to caller.
        (void)__real_close(fd);
        errno = injected_errno;
        return -1;
    }
    return __real_close(fd);
}
// NOLINTEND(bugprone-reserved-identifier)

namespace mux
{

class socks_session_tester
{
   public:
    static boost::asio::awaitable<bool> handshake(socks_session& session) { return session.handshake(); }
    static boost::asio::awaitable<socks_session::request_info> read_request(socks_session& session) { return session.read_request(); }
    static bool verify_credentials(socks_session& session, const std::string& username, const std::string& password)
    {
        return session.verify_credentials(username, password);
    }
};

}    // namespace mux

namespace
{

using namespace mux;

struct tcp_socket_pair
{
    boost::asio::ip::tcp::socket client;
    boost::asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(boost::asio::io_context& io_context)
{
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    if (!mux::test::open_ephemeral_tcp_acceptor(acceptor))
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    boost::asio::ip::tcp::socket client(io_context);
    boost::asio::ip::tcp::socket server(io_context);
    boost::system::error_code ec;
    client.connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    acceptor.accept(server, ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    return tcp_socket_pair{.client = std::move(client), .server = std::move(server)};
}

class socks_session_test_fixture : public ::testing::Test
{
   protected:
    void SetUp() override { reset_failure_injections(); }
    void TearDown() override { reset_failure_injections(); }
    boost::asio::io_context& io_ctx() { return io_ctx_; }

   private:
    boost::asio::io_context io_ctx_;
};

TEST_F(socks_session_test_fixture, ActiveConnectionGuardOutlivesSessionObject)
{
    auto& stats = mux::statistics::instance();
    const auto active_before = stats.active_connections();

    std::shared_ptr<void> guard;
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 999);
        EXPECT_EQ(stats.active_connections(), active_before + 1);

        guard = std::move(session->active_connection_guard_);
        session.reset();

        ASSERT_NE(guard, nullptr);
        EXPECT_EQ(stats.active_connections(), active_before + 1);
    }

    guard.reset();
    EXPECT_EQ(stats.active_connections(), active_before);
}

TEST_F(socks_session_test_fixture, HandshakeNoAuthSuccess)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = false;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x00};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);
    EXPECT_TRUE(handshake_future.get());

    std::uint8_t res[2];
    boost::asio::read(client_sock, boost::asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0x00);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakeGreetingReadTimesOutWhenIncomplete)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 1;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1001, config::socks_t{}, timeout_cfg);

    const std::uint8_t partial_greeting = socks::kVer;
    boost::asio::write(client_sock, boost::asio::buffer(&partial_greeting, 1));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    const auto start = std::chrono::steady_clock::now();
    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);
    EXPECT_FALSE(handshake_future.get());
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 4);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakeGreetingReadWithoutTimeoutKeepsWaiting)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 0;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1002, config::socks_t{}, timeout_cfg);

    const std::uint8_t partial_greeting = socks::kVer;
    boost::asio::write(client_sock, boost::asio::buffer(&partial_greeting, 1));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);
    EXPECT_EQ(handshake_future.wait_for(std::chrono::milliseconds(300)), std::future_status::timeout);

    boost::system::error_code close_ec;
    client_sock.close(close_ec);
    EXPECT_FALSE(handshake_future.get());

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakePasswordAuthSuccess)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);

    std::uint8_t res[2];
    boost::asio::read(client_sock, boost::asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0x02);

    std::uint8_t auth_req[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'};
    boost::asio::write(client_sock, boost::asio::buffer(auth_req));

    EXPECT_TRUE(handshake_future.get());

    std::uint8_t auth_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(auth_res));
    EXPECT_EQ(auth_res[0], 0x01);
    EXPECT_EQ(auth_res[1], 0x00);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, VerifyCredentialsRejectsLengthDifferenceBeyondEightBits)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = std::string(257, '\0');
    cfg.username[0] = 'u';
    cfg.password = "pass";

    socks_session session(std::move(pair.server), io_ctx(), nullptr, nullptr, 9001, cfg);
    EXPECT_FALSE(socks_session_tester::verify_credentials(session, "u", "pass"));
}

TEST_F(socks_session_test_fixture, ReadConnectRequestDomain)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x03, 0x0a, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);

    auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.host, "google.com");
    EXPECT_EQ(info.port, 443);
    EXPECT_EQ(info.cmd, 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakeNoAcceptableMethod)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    config::socks_t cfg;
    cfg.auth = false;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);
    EXPECT_FALSE(handshake_future.get());

    std::uint8_t res[2];
    boost::asio::read(client_sock, boost::asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0xFF);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakePasswordAuthWrongPassword)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);

    std::uint8_t method_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(method_res));
    EXPECT_EQ(method_res[0], 0x05);
    EXPECT_EQ(method_res[1], 0x02);

    std::uint8_t auth_req[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x05, 'w', 'r', 'o', 'n', 'g'};
    boost::asio::write(client_sock, boost::asio::buffer(auth_req));

    EXPECT_FALSE(handshake_future.get());

    std::uint8_t auth_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(auth_res));
    EXPECT_EQ(auth_res[0], 0x01);
    EXPECT_EQ(auth_res[1], 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakePasswordAuthRejectsEmptyUsername)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 2, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);

    std::uint8_t method_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(method_res));
    EXPECT_EQ(method_res[0], 0x05);
    EXPECT_EQ(method_res[1], 0x02);

    std::uint8_t auth_req[] = {0x01, 0x00, 0x04, 'p', 'a', 's', 's'};
    boost::asio::write(client_sock, boost::asio::buffer(auth_req));

    EXPECT_FALSE(handshake_future.get());

    std::uint8_t auth_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(auth_res));
    EXPECT_EQ(auth_res[0], 0x01);
    EXPECT_EQ(auth_res[1], 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HandshakePasswordAuthInvalidVersion)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), boost::asio::use_future);

    std::uint8_t method_res[2];
    boost::asio::read(client_sock, boost::asio::buffer(method_res));
    EXPECT_EQ(method_res[1], 0x02);

    std::uint8_t invalid_auth_ver[] = {0x02};
    boost::asio::write(client_sock, boost::asio::buffer(invalid_auth_ver));
    EXPECT_FALSE(handshake_future.get());

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, ReadRequestInvalidHeaderRejected)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x04, 0x01, 0x00, 0x01};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);

    std::uint8_t err_res[10];
    boost::asio::read(client_sock, boost::asio::buffer(err_res));
    EXPECT_EQ(err_res[0], socks::kVer);
    EXPECT_EQ(err_res[1], socks::kRepGenFail);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, ReadRequestUnsupportedCmdRejected)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x05, 0x02, 0x00, 0x01};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);
    EXPECT_EQ(info.cmd, 0x02);

    std::uint8_t err_res[10];
    boost::asio::read(client_sock, boost::asio::buffer(err_res));
    EXPECT_EQ(err_res[1], socks::kRepCmdNotSupported);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, ReadRequestUnsupportedAtypRejected)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x02};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);
    EXPECT_EQ(info.cmd, 0x01);

    std::uint8_t err_res[10];
    boost::asio::read(client_sock, boost::asio::buffer(err_res));
    EXPECT_EQ(err_res[1], socks::kRepAddrTypeNotSupported);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, ReadConnectRequestIPv4)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());
    boost::asio::ip::tcp::socket client_sock(std::move(pair.client));
    boost::asio::ip::tcp::socket server_sock(std::move(pair.server));

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x88};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);

    const auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.host, "1.2.3.4");
    EXPECT_EQ(info.port, 5000);
    EXPECT_EQ(info.cmd, 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, ReadConnectRequestIPv6)
{
    boost::asio::ip::tcp::socket client_sock(io_ctx());
    boost::asio::ip::tcp::socket server_sock(io_ctx());
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    const std::vector<std::uint8_t> req = {0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb};
    boost::asio::write(client_sock, boost::asio::buffer(req));

    auto work = boost::asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = boost::asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), boost::asio::use_future);

    const auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.port, 443);
    EXPECT_EQ(info.cmd, 0x01);
    EXPECT_EQ(boost::asio::ip::make_address(info.host), boost::asio::ip::make_address("2001:db8::1"));

    work.reset();
    t.join();
}

TEST_F(socks_session_test_fixture, HelperBranchesSelectMethodAndVerifyCredential)
{
    config::socks_t auth_cfg;
    auth_cfg.auth = true;
    auth_cfg.username = "user";
    auth_cfg.password = "pass";
    socks_session const auth_session(boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), nullptr, nullptr, 1, auth_cfg);
    EXPECT_EQ(auth_session.select_auth_method({socks::kMethodNoAuth, socks::kMethodPassword}), socks::kMethodPassword);
    EXPECT_EQ(auth_session.select_auth_method({socks::kMethodNoAuth}), socks::kMethodNoAcceptable);
    EXPECT_TRUE(auth_session.verify_credentials("user", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user2", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user", "pass2"));
    EXPECT_FALSE(auth_session.verify_credentials("uSer", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user", "paSs"));

    config::socks_t no_auth_cfg;
    no_auth_cfg.auth = false;
    socks_session const no_auth_session(boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), nullptr, nullptr, 2, no_auth_cfg);
    EXPECT_EQ(no_auth_session.select_auth_method({socks::kMethodNoAuth}), socks::kMethodNoAuth);
    EXPECT_EQ(no_auth_session.select_auth_method({socks::kMethodPassword}), socks::kMethodNoAcceptable);
    EXPECT_TRUE(socks_session::is_supported_cmd(socks::kCmdConnect));
    EXPECT_TRUE(socks_session::is_supported_cmd(socks::kCmdUdpAssociate));
    EXPECT_FALSE(socks_session::is_supported_cmd(0x09));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdConnect, socks::kAtypIpv4));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdConnect, socks::kAtypDomain));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdConnect, socks::kAtypIpv6));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdUdpAssociate, socks::kAtypIpv4));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdUdpAssociate, socks::kAtypIpv6));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kCmdUdpAssociate, socks::kAtypDomain));
    EXPECT_FALSE(socks_session::is_supported_atyp(socks::kCmdConnect, 0x09));
}

TEST_F(socks_session_test_fixture, ReadGreetingAndMethodsCoversSuccessAndFailures)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);

        const std::uint8_t hello[] = {socks::kVer, 0x02};
        boost::asio::write(pair.client, boost::asio::buffer(hello));
        std::uint8_t method_count = 0;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_socks_greeting(method_count)));
        EXPECT_EQ(method_count, 0x02);

        const std::uint8_t methods[] = {socks::kMethodNoAuth, socks::kMethodPassword};
        boost::asio::write(pair.client, boost::asio::buffer(methods));
        std::vector<std::uint8_t> out_methods;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_auth_methods(method_count, out_methods)));
        ASSERT_EQ(out_methods.size(), 2U);
        EXPECT_EQ(out_methods[0], socks::kMethodNoAuth);
        EXPECT_EQ(out_methods[1], socks::kMethodPassword);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);

        const std::uint8_t bad_hello[] = {0x04, 0x01};
        boost::asio::write(pair.client, boost::asio::buffer(bad_hello));
        std::uint8_t method_count = 0;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_socks_greeting(method_count)));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);

        pair.client.close();
        std::uint8_t method_count = 0;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_socks_greeting(method_count)));
        std::vector<std::uint8_t> methods;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_methods(1, methods)));
    }
}

TEST_F(socks_session_test_fixture, AuthVersionFieldAndResultBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        const std::uint8_t ver = 0x01;
        boost::asio::write(pair.client, boost::asio::buffer(&ver, 1));
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_auth_version()));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);
        const std::uint8_t bad_ver = 0x02;
        boost::asio::write(pair.client, boost::asio::buffer(&bad_ver, 1));
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_version()));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);
        pair.client.close();
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_version()));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);
        const std::uint8_t field[] = {0x04, 't', 'e', 's', 't'};
        boost::asio::write(pair.client, boost::asio::buffer(field));
        std::string out;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "username")));
        EXPECT_EQ(out, "test");
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 10);
        const std::uint8_t zero_len = 0x00;
        boost::asio::write(pair.client, boost::asio::buffer(&zero_len, 1));
        std::string out;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "username")));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 5);
        pair.client.close();
        std::string out;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "username")));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 6);
        const std::uint8_t len = 0x04;
        boost::asio::write(pair.client, boost::asio::buffer(&len, 1));
        pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
        std::string out;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "password")));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 7);
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->write_auth_result(true)));
        std::uint8_t ok_res[2] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(ok_res));
        EXPECT_EQ(ok_res[0], 0x01);
        EXPECT_EQ(ok_res[1], 0x00);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 8);
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->write_auth_result(false)));
        std::uint8_t fail_res[2] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(fail_res));
        EXPECT_EQ(fail_res[0], 0x01);
        EXPECT_EQ(fail_res[1], 0x01);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 9);
        session->socket_.close();
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->write_auth_result(true)));
    }
}

TEST_F(socks_session_test_fixture, ReadTargetHostPortAndValidationBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        const std::uint8_t ip_port[] = {127, 0, 0, 1, 0x1f, 0x90};
        boost::asio::write(pair.client, boost::asio::buffer(ip_port));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypIpv4));
        EXPECT_TRUE(req.ok);
        EXPECT_EQ(req.host, "127.0.0.1");
        EXPECT_EQ(req.port, 8080);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);
        const std::uint8_t domain[] = {0x04, 't', 'e', 's', 't', 0x00, 0x50};
        boost::asio::write(pair.client, boost::asio::buffer(domain));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdUdpAssociate, socks::kAtypDomain));
        EXPECT_TRUE(req.ok);
        EXPECT_EQ(req.host, "test");
        EXPECT_EQ(req.port, 80);
        EXPECT_EQ(req.cmd, socks::kCmdUdpAssociate);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 32);
        const std::uint8_t empty_domain_len = 0x00;
        boost::asio::write(pair.client, boost::asio::buffer(&empty_domain_len, 1));
        std::string host;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_request_domain(host)));
        EXPECT_TRUE(host.empty());
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 33);
        const std::uint8_t domain_with_nul[] = {0x04, 't', 'e', '\0', 't', 0x00, 0x50};
        boost::asio::write(pair.client, boost::asio::buffer(domain_with_nul));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypDomain));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);
        const std::uint8_t empty_domain[] = {0x00, 0x00, 0x50};
        boost::asio::write(pair.client, boost::asio::buffer(empty_domain));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypDomain));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 31);
        const std::uint8_t empty_domain[] = {0x00, 0x00, 0x35};
        boost::asio::write(pair.client, boost::asio::buffer(empty_domain));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdUdpAssociate, socks::kAtypDomain));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdUdpAssociate);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);
        const std::uint8_t zero_port_domain[] = {0x04, 't', 'e', 's', 't', 0x00, 0x00};
        boost::asio::write(pair.client, boost::asio::buffer(zero_port_domain));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypDomain));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 5);
        const std::uint8_t ipv6_port[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x35};
        boost::asio::write(pair.client, boost::asio::buffer(ipv6_port));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypIpv6));
        EXPECT_TRUE(req.ok);
        EXPECT_EQ(boost::asio::ip::make_address(req.host), boost::asio::ip::make_address("2001:db8::1"));
        EXPECT_EQ(req.port, 53);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 6);
        const std::uint8_t only_ipv4[] = {1, 2, 3, 4};
        boost::asio::write(pair.client, boost::asio::buffer(only_ipv4));
        pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypIpv4));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 7);
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, 0x09));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepAddrTypeNotSupported);
    }
}

TEST_F(socks_session_test_fixture, RequestHeaderValidationAndRejectRequestBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        std::array<std::uint8_t, 4> const head = {socks::kVer, socks::kCmdConnect, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        EXPECT_FALSE(result.has_value());
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);
        std::array<std::uint8_t, 4> const head = {0x04, socks::kCmdConnect, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, 0);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);
        std::array<std::uint8_t, 4> const head = {socks::kVer, 0x09, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, 0x09);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepCmdNotSupported);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);
        std::array<std::uint8_t, 4> const head = {socks::kVer, socks::kCmdConnect, 0, 0x09};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepAddrTypeNotSupported);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 41);
        std::array<std::uint8_t, 4> const head = {socks::kVer, socks::kCmdUdpAssociate, 0, socks::kAtypDomain};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        EXPECT_FALSE(result.has_value());
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 5);
        pair.client.close();
        std::array<std::uint8_t, 4> head = {0};
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_request_header(head)));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 6);
        const std::array<std::uint8_t, 4> head = {socks::kVer, socks::kCmdConnect, 0, socks::kAtypIpv4};
        boost::asio::write(pair.client, boost::asio::buffer(head));
        std::array<std::uint8_t, 4> read_head = {0};
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_request_header(read_head)));
        EXPECT_EQ(read_head, head);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 7);
        const std::uint8_t port_bytes[] = {0x13, 0x88};
        boost::asio::write(pair.client, boost::asio::buffer(port_bytes));
        std::uint16_t port = 0;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_request_port(port)));
        EXPECT_EQ(port, 5000);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 8);
        pair.client.close();
        std::uint16_t port = 0;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_request_port(port)));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 9);
        auto req = mux::test::run_awaitable(io_ctx(), session->reject_request(0x03, socks::kRepHostUnreach));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, 0x03);
        std::uint8_t err[10] = {0};
        boost::asio::read(pair.client, boost::asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepHostUnreach);
    }

    {
        const auto invalid_default = socks_session::make_invalid_request();
        EXPECT_FALSE(invalid_default.ok);
        EXPECT_EQ(invalid_default.port, 0);
        EXPECT_EQ(invalid_default.cmd, 0);
        const auto invalid_cmd = socks_session::make_invalid_request(0x7f);
        EXPECT_FALSE(invalid_cmd.ok);
        EXPECT_EQ(invalid_cmd.cmd, 0x7f);
    }
}

TEST_F(socks_session_test_fixture, StartAndStopLifecycleWithInvalidGreeting)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);

    const std::uint8_t bad_hello[] = {0x04, 0x01};
    boost::asio::write(pair.client, boost::asio::buffer(bad_hello));

    session->start();
    io_ctx().run();
    io_ctx().restart();

    EXPECT_FALSE(session->socket_.is_open());
    session->stop();
    EXPECT_FALSE(session->socket_.is_open());

    session->stop();
    EXPECT_FALSE(session->socket_.is_open());
}

TEST_F(socks_session_test_fixture, StartLifecycleWithUnsupportedCommand)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);

    const std::vector<std::uint8_t> req = {
        0x05,
        0x01,
        0x00,    // greeting
        0x05,
        0x09,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        0x00,
        0x50    // unsupported cmd
    };
    boost::asio::write(pair.client, boost::asio::buffer(req));

    session->start();
    io_ctx().run();
    io_ctx().restart();

    std::uint8_t method_res[2] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(method_res));
    EXPECT_EQ(method_res[0], socks::kVer);
    EXPECT_EQ(method_res[1], socks::kMethodNoAuth);

    std::uint8_t err_res[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err_res));
    EXPECT_EQ(err_res[0], socks::kVer);
    EXPECT_EQ(err_res[1], socks::kRepCmdNotSupported);
    EXPECT_FALSE(session->socket_.is_open());

    session->stop();
}

TEST_F(socks_session_test_fixture, StopHandlesUnexpectedShutdownAndCloseErrors)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);

    fail_next_shutdown(EPERM);
    fail_next_close(EIO);
    session->stop();

    session->stop();
    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

TEST_F(socks_session_test_fixture, StopIgnoresExpectedShutdownAndCloseErrors)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);

    fail_next_shutdown(ENOTCONN);
    fail_next_close(EBADF);
    session->stop();

    EXPECT_FALSE(session->socket_.is_open());
    pair.client.close();
}

}    // namespace
