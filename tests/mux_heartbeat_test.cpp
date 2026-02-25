
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <spdlog/sinks/base_sink.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/executor_work_guard.hpp>

#include "mux_protocol.h"
#include "mux_connection.h"

namespace
{

template <typename Mutex>
class heartbeat_log_sink : public spdlog::sinks::base_sink<Mutex>
{
   public:
    [[nodiscard]] bool found() const { return found_.load(std::memory_order_acquire); }

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        if (std::string_view(msg.payload.data(), msg.payload.size()).find("heartbeat received") != std::string_view::npos)
        {
            found_.store(true, std::memory_order_release);
        }
    }

    void flush_() override {}

   private:
    std::atomic<bool> found_{false};
};

using custom_sink_t = heartbeat_log_sink<std::mutex>;

TEST(HeartbeatTest, HeartbeatSendReceive)
{
    boost::asio::io_context io_ctx;
    auto work = boost::asio::make_work_guard(io_ctx);

    boost::asio::ip::tcp::acceptor acceptor(io_ctx);
    boost::system::error_code ec;
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec);
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx);
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx);

    const auto listen_ep = acceptor.local_endpoint(ec);
    ASSERT_FALSE(ec);
    socket_client->connect(listen_ep, ec);
    ASSERT_FALSE(ec);
    acceptor.accept(*socket_server, ec);
    ASSERT_FALSE(ec);

    auto sink = std::make_shared<custom_sink_t>();
    auto logger = std::make_shared<spdlog::logger>("test", sink);
    logger->set_level(spdlog::level::debug);
    auto previous_logger = spdlog::default_logger();
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

    std::vector<std::uint8_t> const key(16, 0);
    std::vector<std::uint8_t> const iv(12, 0);

    auto conn_c = std::make_shared<mux::mux_connection>(std::move(*socket_client),
                                                        io_ctx,
                                                        mux::reality_engine{key, iv, key, iv, EVP_aes_128_gcm()},
                                                        true,
                                                        1,
                                                        "c",
                                                        mux::config::timeout_t{},
                                                        mux::config::limits_t{},
                                                        hb_c);
    auto conn_s = std::make_shared<mux::mux_connection>(std::move(*socket_server),
                                                        io_ctx,
                                                        mux::reality_engine{key, iv, key, iv, EVP_aes_128_gcm()},
                                                        false,
                                                        1,
                                                        "s",
                                                        mux::config::timeout_t{},
                                                        mux::config::limits_t{},
                                                        hb_s);

    boost::asio::co_spawn(io_ctx, [conn_c]() -> boost::asio::awaitable<void> { co_await conn_c->start(); }, boost::asio::detached);
    boost::asio::co_spawn(io_ctx, [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    std::thread t([&io_ctx] { io_ctx.run(); });

    auto start_time = std::chrono::steady_clock::now();
    while (!sink->found() && (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    EXPECT_TRUE(sink->found());

    conn_c->stop();
    conn_s->stop();
    spdlog::set_default_logger(previous_logger);
    work.reset();
    t.join();
}

}    // namespace
