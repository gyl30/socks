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
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>

#include "mux_codec.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "mux_stream_interface.h"

namespace
{

using namespace mux;

class simple_mock_stream : public mux_stream_interface
{
   public:
    [[nodiscard]] const std::vector<uint8_t>& received_data() const { return received_data_; }
    [[nodiscard]] bool closed() const { return closed_; }
    [[nodiscard]] bool reset() const { return reset_; }

    void on_data(std::vector<uint8_t> data) override { received_data_.insert(received_data_.end(), data.begin(), data.end()); }
    void on_close() override { closed_ = true; }
    void on_reset() override { reset_ = true; }

   private:
    std::vector<uint8_t> received_data_;
    bool closed_ = false;
    bool reset_ = false;
};

class mux_connection_integration_test : public ::testing::Test

{
   protected:
    asio::io_context& io_ctx() { return io_ctx_; }

   private:
    asio::io_context io_ctx_;
};

TEST_F(mux_connection_integration_test, StreamDataExchange)

{
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    auto socket_server = std::make_shared<asio::ip::tcp::socket>(io_ctx());

    auto socket_client = std::make_shared<asio::ip::tcp::socket>(io_ctx());

    std::atomic<bool> accepted{false};

    acceptor.async_accept(*socket_server, [&](std::error_code ec) { accepted = true; });

    socket_client->connect(acceptor.local_endpoint());

    while (!accepted)
    {
        io_ctx().poll();
    }

    reality_engine engine_c{{}, {}, {}, {}, EVP_aes_128_gcm()};

    reality_engine engine_s{{}, {}, {}, {}, EVP_aes_128_gcm()};

    auto conn_c = std::make_shared<mux_connection>(std::move(*socket_client), io_ctx(), std::move(engine_c), true, 1);

    auto conn_s = std::make_shared<mux_connection>(std::move(*socket_server), io_ctx(), std::move(engine_s), false, 1);

    auto stream_s = std::make_shared<simple_mock_stream>();
    conn_s->register_stream(100, stream_s);

    asio::co_spawn(io_ctx(), [conn_c]() -> asio::awaitable<void> { co_await conn_c->start(); }, asio::detached);
    asio::co_spawn(io_ctx(), [conn_s]() -> asio::awaitable<void> { co_await conn_s->start(); }, asio::detached);

    std::vector<uint8_t> test_data = {'h', 'e', 'l', 'l', 'o'};

    asio::co_spawn(
        io_ctx(),
        [&]() -> asio::awaitable<void>
        {
            co_await conn_c->send_async(100, kCmdDat, test_data);

            asio::steady_timer timer(io_ctx());
            for (int i = 0; i < 10; ++i)
            {
                if (stream_s->received_data().size() == test_data.size())
                {
                    break;
                }
                timer.expires_after(std::chrono::milliseconds(50));
                co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
            }

            EXPECT_EQ(stream_s->received_data(), test_data);

            co_await conn_c->send_async(100, kCmdFin, {});
            for (int i = 0; i < 10; ++i)
            {
                if (stream_s->closed())
                {
                    break;
                }
                timer.expires_after(std::chrono::milliseconds(50));
                co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
            }
            EXPECT_TRUE(stream_s->closed());

            conn_c->stop();
            conn_s->stop();
        },
        asio::detached);

    io_ctx().run();
}

TEST_F(mux_connection_integration_test, ReadTimeoutHandling)
{
    asio::ip::tcp::acceptor acceptor(io_ctx(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    auto socket_server = std::make_shared<asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 1;
    timeout_cfg.write = 100;

    auto conn_s =
        std::make_shared<mux_connection>(
            std::move(*socket_server), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 1, "test", timeout_cfg);

    asio::co_spawn(io_ctx(), [conn_s]() -> asio::awaitable<void> { co_await conn_s->start(); }, asio::detached);

    auto start_time = std::chrono::steady_clock::now();
    while (conn_s->is_open() && (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)))
    {
        io_ctx().poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_FALSE(conn_s->is_open());
}

TEST_F(mux_connection_integration_test, WriteTimeoutHandling) {}

TEST_F(mux_connection_integration_test, TryRegisterStreamRejectsDuplicateId)
{
    asio::ip::tcp::socket socket(io_ctx());
    reality_engine engine{{}, {}, {}, {}, EVP_aes_128_gcm()};
    auto conn = std::make_shared<mux_connection>(std::move(socket), io_ctx(), std::move(engine), true, 1);

    auto stream_a = std::make_shared<simple_mock_stream>();
    auto stream_b = std::make_shared<simple_mock_stream>();

    EXPECT_TRUE(conn->try_register_stream(100, stream_a));
    EXPECT_FALSE(conn->try_register_stream(100, stream_b));
    EXPECT_TRUE(conn->has_stream(100));
}

}    // namespace
