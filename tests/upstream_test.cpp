#include <memory>
#include <vector>
#include <thread>
#include <cstdint>
#include <system_error>

#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <gtest/gtest.h>

#include "upstream.h"
#include "test_util.h"
#include "log_context.h"

class UpstreamTest : public ::testing::Test
{
   protected:
    void TearDown() override { ctx_.stop(); }
    asio::io_context& ctx() { return ctx_; }

   private:
    asio::io_context ctx_;
};

class EchoServer
{
   public:
    EchoServer() : acceptor_(ctx_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0))
    {
        do_accept();
        thread_ = std::thread([this] { ctx_.run(); });
    }

    [[nodiscard]] uint16_t port() const { return acceptor_.local_endpoint().port(); }

    ~EchoServer() noexcept
    {
        try
        {
            stop();
            if (thread_.joinable())
            {
                thread_.join();
            }
        }
        catch (...)
        {
        }
    }

    void stop()
    {
        ctx_.stop();
        acceptor_.close();
    }

   private:
    void do_accept()
    {
        auto socket = std::make_shared<asio::ip::tcp::socket>(acceptor_.get_executor());
        acceptor_.async_accept(*socket,
                               [this, socket](std::error_code ec)
                               {
                                   if (!ec)
                                   {
                                       do_echo(socket);
                                   }
                                   if (acceptor_.is_open())
                                   {
                                       do_accept();
                                   }
                               });
    }

    void do_echo(const std::shared_ptr<asio::ip::tcp::socket>& socket)
    {
        auto buf = std::make_shared<std::vector<uint8_t>>(1024);
        socket->async_read_some(asio::buffer(*buf),
                                [this, socket, buf](std::error_code ec, size_t n)
                                {
                                    if (!ec)
                                    {
                                        asio::async_write(*socket,
                                                          asio::buffer(*buf, n),
                                                          [this, socket, buf](std::error_code ec, size_t)
                                                          {
                                                              if (!ec)
                                                              {
                                                                  do_echo(socket);
                                                              }
                                                          });
                                    }
                                });
    }

    asio::io_context ctx_;
    asio::ip::tcp::acceptor acceptor_;
    std::thread thread_;
};

TEST_F(UpstreamTest, DirectUpstreamConnectSuccess)
{
    EchoServer server;
    const uint16_t port = server.port();

    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});

    auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    const std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto write_n = mux::test::run_awaitable(ctx(), upstream.write(data));
    EXPECT_EQ(write_n, 3);

    std::vector<uint8_t> buf(1024);
    auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 3);
    EXPECT_EQ(buf[0], 0x01);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(UpstreamTest, DirectUpstreamConnectFail)
{
    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});

    auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", 1));
    EXPECT_FALSE(success);
}

TEST_F(UpstreamTest, DirectUpstreamResolveFail)
{
    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});
    auto success = mux::test::run_awaitable(ctx(), upstream.connect("invalid.host.name.local", 80));
    EXPECT_FALSE(success);
}
