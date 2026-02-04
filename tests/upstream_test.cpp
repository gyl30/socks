#include <memory>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>

#include "log.h"
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
        catch (const std::exception& e)
        {
            LOG_ERROR("echo server destructor exception {}", e.what());
        }
        catch (...)
        {
            LOG_ERROR("echo server destructor unknown exception");
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
                               [this, socket](const std::error_code ec)
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
                                [this, socket, buf](const std::error_code ec, const size_t n)
                                {
                                    if (!ec)
                                    {
                                        asio::async_write(*socket,
                                                          asio::buffer(*buf, n),
                                                          [this, socket, buf](const std::error_code ec_write, size_t)
                                                          {
                                                              if (!ec_write)
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

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    const std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    const auto write_n = mux::test::run_awaitable(ctx(), upstream.write(data));
    EXPECT_EQ(write_n, 3);

    std::vector<uint8_t> buf(1024);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 3);
    EXPECT_EQ(buf[0], 0x01);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(UpstreamTest, DirectUpstreamConnectFail)
{
    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", 1));
    EXPECT_FALSE(success);
}

TEST_F(UpstreamTest, DirectUpstreamWriteError)
{
    // Start a server that accepts and immediately closes
    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    uint16_t port = acceptor->local_endpoint().port();

    asio::co_spawn(
        ctx(),
        [acceptor]() -> asio::awaitable<void>
        {
            auto socket = co_await acceptor->async_accept(asio::use_awaitable);
            socket.close();
            co_return;
        },
        asio::detached);

    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    // Give server time to close its side
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Try to write multiple times to ensure we get an error
    size_t write_n = 1;
    for (int i = 0; i < 10 && write_n > 0; ++i)
    {
        write_n = mux::test::run_awaitable(ctx(), upstream.write({0x01, 0x02, 0x03}));
    }
    // Eventually it should fail and return 0
    EXPECT_EQ(write_n, 0);
}

#include "mux_tunnel.h"
#include "mock_mux_connection.h"

TEST_F(UpstreamTest, DirectUpstreamClose)
{
    mux::direct_upstream upstream(ctx().get_executor(), mux::connection_context{});
    // Closing uninitialized upstream should be safe and cover close error paths
    // (though on some OS it might not error, it still exercises the code).
    mux::test::run_awaitable_void(ctx(), upstream.close());
}
