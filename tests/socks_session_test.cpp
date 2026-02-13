#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/co_spawn.hpp>
#include <asio/io_context.hpp>
#include <asio/use_future.hpp>
#include <asio/executor_work_guard.hpp>

#include "protocol.h"
#include "socks_session.h"

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

}    // namespace
