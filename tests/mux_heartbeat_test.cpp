#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>
#include <spdlog/spdlog.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <spdlog/sinks/base_sink.h>
#include <asio/executor_work_guard.hpp>

#include "mux_protocol.h"
#include "mux_connection.h"

namespace
{

template <typename Mutex>
class HeartbeatLogSink : public spdlog::sinks::base_sink<Mutex>
{
   public:
    std::atomic<bool> found{false};

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        if (std::string_view(msg.payload.data(), msg.payload.size()).find("heartbeat received") != std::string_view::npos)
        {
            found = true;
        }
    }

    void flush_() override {}
};

using custom_sink_t = HeartbeatLogSink<std::mutex>;

TEST(HeartbeatTest, HeartbeatSendReceive)
{
    asio::io_context io_ctx;
    auto work = asio::make_work_guard(io_ctx);

    asio::ip::tcp::acceptor acceptor(io_ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    auto socket_server = std::make_shared<asio::ip::tcp::socket>(io_ctx);
    auto socket_client = std::make_shared<asio::ip::tcp::socket>(io_ctx);

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    auto sink = std::make_shared<custom_sink_t>();
    auto logger = std::make_shared<spdlog::logger>("test", sink);
    logger->set_level(spdlog::level::debug);
    spdlog::set_default_logger(logger);

    mux::config::heartbeat_t hb_c;
    hb_c.enabled = true;
    hb_c.idle_timeout = 0;
    hb_c.min_interval = 1;
    hb_c.max_interval = 1;
    hb_c.min_padding = 0;
    hb_c.max_padding = 0;

    mux::config::heartbeat_t hb_s;
    hb_s.enabled = false;

    std::vector<std::uint8_t> key(16, 0);
    std::vector<std::uint8_t> iv(12, 0);

    auto conn_c = std::make_shared<mux::mux_connection>(std::move(*socket_client),
                                                        mux::reality_engine{key, iv, key, iv, EVP_aes_128_gcm()},
                                                        true,
                                                        1,
                                                        "c",
                                                        mux::config::timeout_t{},
                                                        mux::config::limits_t{},
                                                        hb_c);
    auto conn_s = std::make_shared<mux::mux_connection>(std::move(*socket_server),
                                                        mux::reality_engine{key, iv, key, iv, EVP_aes_128_gcm()},
                                                        false,
                                                        1,
                                                        "s",
                                                        mux::config::timeout_t{},
                                                        mux::config::limits_t{},
                                                        hb_s);

    asio::co_spawn(io_ctx, [conn_c]() -> asio::awaitable<void> { co_await conn_c->start(); }, asio::detached);
    asio::co_spawn(io_ctx, [conn_s]() -> asio::awaitable<void> { co_await conn_s->start(); }, asio::detached);

    std::thread t([&io_ctx] { io_ctx.run(); });

    auto start_time = std::chrono::steady_clock::now();
    while (!sink->found && (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    EXPECT_TRUE(sink->found);

    conn_c->stop();
    conn_s->stop();
    work.reset();
    t.join();
}

}    // namespace
