#include <atomic>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <array>
#include <cstdint>
#include <utility>
#include <system_error>
#include <cerrno>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/use_future.hpp>
#include <asio/executor_work_guard.hpp>
#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"
#define private public
#include "socks_session.h"
#undef private
#include "test_util.h"

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
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);
}

namespace mux
{

class socks_session_tester
{
   public:
    static asio::awaitable<bool> handshake(socks_session& session) { return session.handshake(); }
    static asio::awaitable<socks_session::request_info> read_request(socks_session& session) { return session.read_request(); }
};

}    // namespace mux

namespace
{

using namespace mux;

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

class socks_session_test : public ::testing::Test
{
   protected:
    asio::io_context& io_ctx() { return io_ctx_; }

   private:
    asio::io_context io_ctx_;
};

TEST_F(socks_session_test, HandshakeNoAuthSuccess)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = false;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x00};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), asio::use_future);
    EXPECT_TRUE(handshake_future.get());

    std::uint8_t res[2];
    asio::read(client_sock, asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0x00);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, HandshakePasswordAuthSuccess)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), asio::use_future);

    std::uint8_t res[2];
    asio::read(client_sock, asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0x02);

    std::uint8_t auth_req[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'};
    asio::write(client_sock, asio::buffer(auth_req));

    EXPECT_TRUE(handshake_future.get());

    std::uint8_t auth_res[2];
    asio::read(client_sock, asio::buffer(auth_res));
    EXPECT_EQ(auth_res[0], 0x01);
    EXPECT_EQ(auth_res[1], 0x00);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadConnectRequestDomain)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x03, 0x0a, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);

    auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.host, "google.com");
    EXPECT_EQ(info.port, 443);
    EXPECT_EQ(info.cmd, 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, HandshakeNoAcceptableMethod)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = false;
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), asio::use_future);
    EXPECT_FALSE(handshake_future.get());

    std::uint8_t res[2];
    asio::read(client_sock, asio::buffer(res));
    EXPECT_EQ(res[0], 0x05);
    EXPECT_EQ(res[1], 0xFF);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, HandshakePasswordAuthWrongPassword)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), asio::use_future);

    std::uint8_t method_res[2];
    asio::read(client_sock, asio::buffer(method_res));
    EXPECT_EQ(method_res[0], 0x05);
    EXPECT_EQ(method_res[1], 0x02);

    std::uint8_t auth_req[] = {0x01, 0x04, 'u', 's', 'e', 'r', 0x05, 'w', 'r', 'o', 'n', 'g'};
    asio::write(client_sock, asio::buffer(auth_req));

    EXPECT_FALSE(handshake_future.get());

    std::uint8_t auth_res[2];
    asio::read(client_sock, asio::buffer(auth_res));
    EXPECT_EQ(auth_res[0], 0x01);
    EXPECT_EQ(auth_res[1], 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, HandshakePasswordAuthInvalidVersion)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    config::socks_t cfg;
    cfg.auth = true;
    cfg.username = "user";
    cfg.password = "pass";
    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1, cfg);

    std::uint8_t req[] = {0x05, 0x01, 0x02};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto handshake_future = asio::co_spawn(io_ctx(), socks_session_tester::handshake(*session), asio::use_future);

    std::uint8_t method_res[2];
    asio::read(client_sock, asio::buffer(method_res));
    EXPECT_EQ(method_res[1], 0x02);

    std::uint8_t invalid_auth_ver[] = {0x02};
    asio::write(client_sock, asio::buffer(invalid_auth_ver));
    EXPECT_FALSE(handshake_future.get());

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadRequestInvalidHeaderRejected)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x04, 0x01, 0x00, 0x01};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);

    std::uint8_t err_res[10];
    asio::read(client_sock, asio::buffer(err_res));
    EXPECT_EQ(err_res[0], socks::kVer);
    EXPECT_EQ(err_res[1], socks::kRepGenFail);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadRequestUnsupportedCmdRejected)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x05, 0x02, 0x00, 0x01};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);
    EXPECT_EQ(info.cmd, 0x02);

    std::uint8_t err_res[10];
    asio::read(client_sock, asio::buffer(err_res));
    EXPECT_EQ(err_res[1], socks::kRepCmdNotSupported);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadRequestUnsupportedAtypRejected)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);
    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x02};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);
    const auto info = req_future.get();
    EXPECT_FALSE(info.ok);
    EXPECT_EQ(info.cmd, 0x01);

    std::uint8_t err_res[10];
    asio::read(client_sock, asio::buffer(err_res));
    EXPECT_EQ(err_res[1], socks::kRepAddrTypeNotSupported);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadConnectRequestIPv4)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    std::uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x13, 0x88};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);

    const auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.host, "1.2.3.4");
    EXPECT_EQ(info.port, 5000);
    EXPECT_EQ(info.cmd, 0x01);

    work.reset();
    t.join();
}

TEST_F(socks_session_test, ReadConnectRequestIPv6)
{
    asio::ip::tcp::socket client_sock(io_ctx());
    asio::ip::tcp::socket server_sock(io_ctx());
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    client_sock.connect(acceptor.local_endpoint());
    acceptor.accept(server_sock);

    auto session = std::make_shared<socks_session>(std::move(server_sock), io_ctx(), nullptr, nullptr, 1);

    const std::vector<std::uint8_t> req = {0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb};
    asio::write(client_sock, asio::buffer(req));

    auto work = asio::make_work_guard(io_ctx());
    std::thread t([&io_ctx = this->io_ctx()] { io_ctx.run(); });

    auto req_future = asio::co_spawn(io_ctx(), socks_session_tester::read_request(*session), asio::use_future);

    const auto info = req_future.get();
    EXPECT_TRUE(info.ok);
    EXPECT_EQ(info.port, 443);
    EXPECT_EQ(info.cmd, 0x01);
    EXPECT_EQ(asio::ip::make_address(info.host), asio::ip::make_address("2001:db8::1"));

    work.reset();
    t.join();
}

TEST_F(socks_session_test, HelperBranchesSelectMethodAndVerifyCredential)
{
    config::socks_t auth_cfg;
    auth_cfg.auth = true;
    auth_cfg.username = "user";
    auth_cfg.password = "pass";
    socks_session auth_session(asio::ip::tcp::socket(io_ctx()), io_ctx(), nullptr, nullptr, 1, auth_cfg);
    EXPECT_EQ(auth_session.select_auth_method({socks::kMethodNoAuth, socks::kMethodPassword}), socks::kMethodPassword);
    EXPECT_EQ(auth_session.select_auth_method({socks::kMethodNoAuth}), socks::kMethodNoAcceptable);
    EXPECT_TRUE(auth_session.verify_credentials("user", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user2", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user", "pass2"));
    EXPECT_FALSE(auth_session.verify_credentials("uSer", "pass"));
    EXPECT_FALSE(auth_session.verify_credentials("user", "paSs"));

    config::socks_t no_auth_cfg;
    no_auth_cfg.auth = false;
    socks_session no_auth_session(asio::ip::tcp::socket(io_ctx()), io_ctx(), nullptr, nullptr, 2, no_auth_cfg);
    EXPECT_EQ(no_auth_session.select_auth_method({socks::kMethodNoAuth}), socks::kMethodNoAuth);
    EXPECT_EQ(no_auth_session.select_auth_method({socks::kMethodPassword}), socks::kMethodNoAcceptable);
    EXPECT_TRUE(socks_session::is_supported_cmd(socks::kCmdConnect));
    EXPECT_TRUE(socks_session::is_supported_cmd(socks::kCmdUdpAssociate));
    EXPECT_FALSE(socks_session::is_supported_cmd(0x09));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kAtypIpv4));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kAtypDomain));
    EXPECT_TRUE(socks_session::is_supported_atyp(socks::kAtypIpv6));
    EXPECT_FALSE(socks_session::is_supported_atyp(0x09));
}

TEST_F(socks_session_test, ReadGreetingAndMethodsCoversSuccessAndFailures)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);

        const std::uint8_t hello[] = {socks::kVer, 0x02};
        asio::write(pair.client, asio::buffer(hello));
        std::uint8_t method_count = 0;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_socks_greeting(method_count)));
        EXPECT_EQ(method_count, 0x02);

        const std::uint8_t methods[] = {socks::kMethodNoAuth, socks::kMethodPassword};
        asio::write(pair.client, asio::buffer(methods));
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
        asio::write(pair.client, asio::buffer(bad_hello));
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

TEST_F(socks_session_test, AuthVersionFieldAndResultBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        const std::uint8_t ver = 0x01;
        asio::write(pair.client, asio::buffer(&ver, 1));
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_auth_version()));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);
        const std::uint8_t bad_ver = 0x02;
        asio::write(pair.client, asio::buffer(&bad_ver, 1));
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
        asio::write(pair.client, asio::buffer(field));
        std::string out;
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "username")));
        EXPECT_EQ(out, "test");
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
        asio::write(pair.client, asio::buffer(&len, 1));
        pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);
        std::string out;
        EXPECT_FALSE(mux::test::run_awaitable(io_ctx(), session->read_auth_field(out, "password")));
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 7);
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->write_auth_result(true)));
        std::uint8_t ok_res[2] = {0};
        asio::read(pair.client, asio::buffer(ok_res));
        EXPECT_EQ(ok_res[0], 0x01);
        EXPECT_EQ(ok_res[1], 0x00);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 8);
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->write_auth_result(false)));
        std::uint8_t fail_res[2] = {0};
        asio::read(pair.client, asio::buffer(fail_res));
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

TEST_F(socks_session_test, ReadTargetHostPortAndValidationBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        const std::uint8_t ip_port[] = {127, 0, 0, 1, 0x1f, 0x90};
        asio::write(pair.client, asio::buffer(ip_port));
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
        asio::write(pair.client, asio::buffer(domain));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdUdpAssociate, socks::kAtypDomain));
        EXPECT_TRUE(req.ok);
        EXPECT_EQ(req.host, "test");
        EXPECT_EQ(req.port, 80);
        EXPECT_EQ(req.cmd, socks::kCmdUdpAssociate);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);
        const std::uint8_t ipv6_port[] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x35};
        asio::write(pair.client, asio::buffer(ipv6_port));
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypIpv6));
        EXPECT_TRUE(req.ok);
        EXPECT_EQ(asio::ip::make_address(req.host), asio::ip::make_address("2001:db8::1"));
        EXPECT_EQ(req.port, 53);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);
        const std::uint8_t only_ipv4[] = {1, 2, 3, 4};
        asio::write(pair.client, asio::buffer(only_ipv4));
        pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, socks::kAtypIpv4));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        asio::read(pair.client, asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 5);
        auto req = mux::test::run_awaitable(io_ctx(), session->read_request_target(socks::kCmdConnect, 0x09));
        EXPECT_FALSE(req.ok);
        EXPECT_EQ(req.cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        asio::read(pair.client, asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepAddrTypeNotSupported);
    }
}

TEST_F(socks_session_test, RequestHeaderValidationAndRejectRequestBranches)
{
    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);
        std::array<std::uint8_t, 4> head = {socks::kVer, socks::kCmdConnect, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        EXPECT_FALSE(result.has_value());
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);
        std::array<std::uint8_t, 4> head = {0x04, socks::kCmdConnect, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, 0);
        std::uint8_t err[10] = {0};
        asio::read(pair.client, asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepGenFail);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 3);
        std::array<std::uint8_t, 4> head = {socks::kVer, 0x09, 0, socks::kAtypIpv4};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, 0x09);
        std::uint8_t err[10] = {0};
        asio::read(pair.client, asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepCmdNotSupported);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 4);
        std::array<std::uint8_t, 4> head = {socks::kVer, socks::kCmdConnect, 0, 0x09};
        auto result = mux::test::run_awaitable(io_ctx(), session->validate_request_head(head));
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(result->ok);
        EXPECT_EQ(result->cmd, socks::kCmdConnect);
        std::uint8_t err[10] = {0};
        asio::read(pair.client, asio::buffer(err));
        EXPECT_EQ(err[1], socks::kRepAddrTypeNotSupported);
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
        asio::write(pair.client, asio::buffer(head));
        std::array<std::uint8_t, 4> read_head = {0};
        EXPECT_TRUE(mux::test::run_awaitable(io_ctx(), session->read_request_header(read_head)));
        EXPECT_EQ(read_head, head);
    }

    {
        auto pair = make_tcp_socket_pair(io_ctx());
        auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 7);
        const std::uint8_t port_bytes[] = {0x13, 0x88};
        asio::write(pair.client, asio::buffer(port_bytes));
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
        asio::read(pair.client, asio::buffer(err));
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

TEST_F(socks_session_test, StartAndStopLifecycleWithInvalidGreeting)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 1);

    const std::uint8_t bad_hello[] = {0x04, 0x01};
    asio::write(pair.client, asio::buffer(bad_hello));

    session->start();
    io_ctx().run();
    io_ctx().restart();

    EXPECT_TRUE(session->socket_.is_open());
    session->stop();
    EXPECT_FALSE(session->socket_.is_open());

    session->stop();
    EXPECT_FALSE(session->socket_.is_open());
}

TEST_F(socks_session_test, StartLifecycleWithUnsupportedCommand)
{
    auto pair = make_tcp_socket_pair(io_ctx());
    auto session = std::make_shared<socks_session>(std::move(pair.server), io_ctx(), nullptr, nullptr, 2);

    const std::vector<std::uint8_t> req = {
        0x05, 0x01, 0x00,    // greeting
        0x05, 0x09, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50    // unsupported cmd
    };
    asio::write(pair.client, asio::buffer(req));

    session->start();
    io_ctx().run();
    io_ctx().restart();

    std::uint8_t method_res[2] = {0};
    asio::read(pair.client, asio::buffer(method_res));
    EXPECT_EQ(method_res[0], socks::kVer);
    EXPECT_EQ(method_res[1], socks::kMethodNoAuth);

    std::uint8_t err_res[10] = {0};
    asio::read(pair.client, asio::buffer(err_res));
    EXPECT_EQ(err_res[0], socks::kVer);
    EXPECT_EQ(err_res[1], socks::kRepCmdNotSupported);

    session->stop();
}

TEST_F(socks_session_test, StopHandlesUnexpectedShutdownAndCloseErrors)
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

}    // namespace
