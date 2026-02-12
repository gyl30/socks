#include <chrono>
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
#include "mux_tunnel.h"
#include "log_context.h"
#include "mock_mux_connection.h"

class upstream_test : public ::testing::Test
{
   protected:
    void TearDown() override { ctx_.stop(); }
    asio::io_context& ctx() { return ctx_; }

   private:
    asio::io_context ctx_;
};

class echo_server
{
   public:
    echo_server() : acceptor_(ctx_, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0))
    {
        do_accept();
        thread_ = std::thread([this] { ctx_.run(); });
    }

    [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

    ~echo_server() noexcept
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
        auto buf = std::make_shared<std::vector<std::uint8_t>>(1024);
        socket->async_read_some(asio::buffer(*buf),
                                [this, socket, buf](const std::error_code ec, const std::size_t n)
                                {
                                    if (!ec)
                                    {
                                        asio::async_write(*socket,
                                                          asio::buffer(*buf, n),
                                                          [this, socket, buf](const std::error_code ec_write, std::size_t)
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

TEST_F(upstream_test, DirectUpstreamConnectSuccess)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    const std::vector<std::uint8_t> data = {0x01, 0x02, 0x03};
    const auto write_n = mux::test::run_awaitable(ctx(), upstream.write(data));
    EXPECT_EQ(write_n, 3);

    std::vector<std::uint8_t> buf(1024);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, 3);
    EXPECT_EQ(buf[0], 0x01);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectFail)
{
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", 1));
    EXPECT_FALSE(success);
}

TEST_F(upstream_test, DirectUpstreamResolveFail)
{
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("non-existent.invalid", 80));
    EXPECT_FALSE(success);
}

TEST_F(upstream_test, DirectUpstreamReconnectSuccess)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    const std::vector<std::uint8_t> data = {0xAB, 0xCD};
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), data.size());

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, data.size());
    EXPECT_EQ(buf[0], 0xAB);
    EXPECT_EQ(buf[1], 0xCD);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamConnectWithSocketMark)
{
    echo_server server;
    const std::uint16_t port = server.port();

    mux::direct_upstream upstream(ctx(), mux::connection_context{}, 1);
    EXPECT_TRUE(mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port)));

    const std::vector<std::uint8_t> data = {0x11};
    EXPECT_EQ(mux::test::run_awaitable(ctx(), upstream.write(data)), data.size());

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_FALSE(read_ec);
    EXPECT_EQ(read_n, data.size());
    EXPECT_EQ(buf[0], 0x11);

    mux::test::run_awaitable_void(ctx(), upstream.close());
    server.stop();
}

TEST_F(upstream_test, DirectUpstreamWriteError)
{
    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    std::uint16_t port = acceptor->local_endpoint().port();

    asio::co_spawn(
        ctx(),
        [acceptor]() -> asio::awaitable<void>
        {
            auto socket = co_await acceptor->async_accept(asio::use_awaitable);
            socket.close();
            co_return;
        },
        asio::detached);

    mux::direct_upstream upstream(ctx(), mux::connection_context{});
    const auto success = mux::test::run_awaitable(ctx(), upstream.connect("127.0.0.1", port));
    EXPECT_TRUE(success);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::size_t write_n = 1;
    for (int i = 0; i < 10 && write_n > 0; ++i)
    {
        write_n = mux::test::run_awaitable(ctx(), upstream.write({0x01, 0x02, 0x03}));
    }

    EXPECT_EQ(write_n, 0);
}

TEST_F(upstream_test, DirectUpstreamClose)
{
    mux::direct_upstream upstream(ctx(), mux::connection_context{});

    mux::test::run_awaitable_void(ctx(), upstream.close());
}

TEST_F(upstream_test, ProxyUpstreamReadWriteWithoutConnect)
{
    mux::proxy_upstream upstream(nullptr, mux::connection_context{});

    std::vector<std::uint8_t> buf(16);
    const auto [read_ec, read_n] = mux::test::run_awaitable(ctx(), upstream.read(buf));
    EXPECT_EQ(read_ec, asio::error::operation_aborted);
    EXPECT_EQ(read_n, 0);

    const auto write_n = mux::test::run_awaitable(ctx(), upstream.write({0x01, 0x02, 0x03}));
    EXPECT_EQ(write_n, 0);

    mux::test::run_awaitable_void(ctx(), upstream.close());
}
