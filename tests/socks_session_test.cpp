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
    auto session = std::make_shared<socks_session>(std::move(server_sock), nullptr, nullptr, 1, cfg);

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
    auto session = std::make_shared<socks_session>(std::move(server_sock), nullptr, nullptr, 1, cfg);

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

    auto session = std::make_shared<socks_session>(std::move(server_sock), nullptr, nullptr, 1);

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

}    // namespace
