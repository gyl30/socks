#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "mux_codec.h"
#include "mux_connection.h"
#include "mux_protocol.h"
#include "reality_engine.h"
#include "task_group.h"

namespace
{

constexpr std::uint64_t kTestMaxBuffer = 32;

[[nodiscard]] mux::reality_engine make_test_engine()
{
    std::vector<std::uint8_t> key(16, 0);
    std::vector<std::uint8_t> iv(12, 0);
    return mux::reality_engine(std::move(key), std::move(iv), std::vector<std::uint8_t>(16, 0), std::vector<std::uint8_t>(12, 0), EVP_aes_128_gcm());
}

struct fixture
{
    boost::asio::io_context io;
    task_group group;
    mux::config cfg;
    std::shared_ptr<mux::mux_connection> conn;

    fixture()
        : io(),
          group(io),
          cfg(),
          conn()
    {
        cfg.limits.max_buffer = kTestMaxBuffer;
        cfg.heartbeat.enabled = false;
        cfg.timeout.read = 1;
        cfg.timeout.write = 1;
        cfg.timeout.idle = 1;

        boost::asio::ip::tcp::socket socket(io);
        auto engine = make_test_engine();
        conn = std::make_shared<mux::mux_connection>(std::move(socket), io, std::move(engine), cfg, group, 1, "mux-backpressure-test");
    }

    [[nodiscard]] std::uint64_t stream_budget() const
    {
        return std::max<std::uint64_t>(1ULL, cfg.limits.max_buffer / 4ULL);
    }
};

[[noreturn]] void fail(const std::string& message)
{
    throw std::runtime_error(message);
}

void require(const bool condition, const std::string& message)
{
    if (!condition)
    {
        fail(message);
    }
}

void require_ok(const boost::system::error_code& ec, const std::string& message)
{
    if (ec)
    {
        fail(message + ": " + ec.message());
    }
}

void require_error(const boost::system::error_code& ec, const boost::system::error_code& expected, const std::string& message)
{
    if (ec != expected)
    {
        fail(message + ": expected " + expected.message() + ", got " + ec.message());
    }
}

[[nodiscard]] mux::mux_frame make_dat_frame(const std::uint32_t stream_id, const std::size_t payload_len)
{
    mux::mux_frame frame;
    frame.h.stream_id = stream_id;
    frame.h.command = mux::kCmdDat;
    frame.payload.assign(payload_len, 0x42);
    return frame;
}

[[nodiscard]] mux::mux_frame make_ack_frame(const std::uint32_t stream_id)
{
    mux::ack_payload ack{.socks_rep = 0, .bnd_addr = "127.0.0.1", .bnd_port = 1080};
    std::vector<std::uint8_t> payload;
    if (!mux::mux_codec::encode_ack(ack, payload))
    {
        fail("failed to encode ACK payload");
    }

    mux::mux_frame frame;
    frame.h.stream_id = stream_id;
    frame.h.command = mux::kCmdAck;
    frame.payload = std::move(payload);
    return frame;
}

[[nodiscard]] mux::mux_frame make_heartbeat_frame(const std::size_t payload_len)
{
    return make_dat_frame(mux::kStreamIdHeartbeat, payload_len);
}

boost::asio::awaitable<boost::system::error_code> send_frame(const std::shared_ptr<mux::mux_connection>& conn, mux::mux_frame frame)
{
    boost::system::error_code ec;
    co_await conn->send_async(std::move(frame), ec);
    co_return ec;
}

boost::asio::awaitable<void> stream_fairness_scenario(const std::shared_ptr<mux::mux_connection>& conn, const std::uint64_t stream_budget)
{
    for (std::uint64_t i = 0; i < stream_budget; ++i)
    {
        const auto ec = co_await send_frame(conn, make_dat_frame(1, 1));
        require_ok(ec, "stream 1 should stay within its per-stream budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_dat_frame(1, 1));
        require_error(ec, boost::asio::error::no_buffer_space, "stream 1 should hit the per-stream cap first");
    }

    for (std::uint64_t i = 0; i < stream_budget; ++i)
    {
        const auto ec = co_await send_frame(conn, make_dat_frame(2, 1));
        require_ok(ec, "stream 2 should keep its own write budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_dat_frame(2, 1));
        require_error(ec, boost::asio::error::no_buffer_space, "stream 2 should also stop at its own cap");
    }

    co_return;
}

boost::asio::awaitable<void> exemption_and_cleanup_scenario(const std::shared_ptr<mux::mux_connection>& conn, const std::uint64_t stream_budget)
{
    for (std::uint64_t i = 0; i < stream_budget; ++i)
    {
        const auto ec = co_await send_frame(conn, make_dat_frame(1, 1));
        require_ok(ec, "stream 1 should fill to its per-stream budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_ack_frame(1));
        require_ok(ec, "ACK frames must bypass the per-stream budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_dat_frame(1, 0));
        require_ok(ec, "zero-length DAT frames must not consume per-stream budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_heartbeat_frame(1));
        require_ok(ec, "heartbeat frames must bypass the per-stream budget");
    }

    conn->stop();

    {
        const auto ec = co_await send_frame(conn, make_dat_frame(1, 1));
        require(static_cast<bool>(ec), "post-stop DAT send should fail");
        require(ec != boost::asio::error::no_buffer_space, "stop() should clear stale per-stream quota instead of reporting no_buffer_space");
    }

    co_return;
}

boost::asio::awaitable<void> connection_budget_scenario(const std::shared_ptr<mux::mux_connection>& conn, const std::uint64_t stream_budget)
{
    for (std::uint32_t stream_id = 1; stream_id <= 4; ++stream_id)
    {
        const auto ec = co_await send_frame(conn, make_dat_frame(stream_id, stream_budget));
        require_ok(ec, "each stream should be able to consume its own share of the connection budget");
    }

    {
        const auto ec = co_await send_frame(conn, make_dat_frame(5, 1));
        require_error(ec, boost::asio::error::no_buffer_space, "connection should reject once the global write budget is exhausted");
    }

    co_return;
}

void run_scenario(const std::string& name, const std::function<boost::asio::awaitable<void>(const std::shared_ptr<mux::mux_connection>&, std::uint64_t)>& scenario)
{
    fixture fx;
    auto future = boost::asio::co_spawn(fx.io, scenario(fx.conn, fx.stream_budget()), boost::asio::use_future);
    fx.io.run();
    future.get();
    std::cout << "[PASS] " << name << '\n';
}

}    // namespace

int main()
{
    try
    {
        run_scenario("single-stream-fairness", stream_fairness_scenario);
        run_scenario("exemptions-and-cleanup", exemption_and_cleanup_scenario);
        run_scenario("connection-budget", connection_budget_scenario);
    }
    catch (const std::exception& e)
    {
        std::cerr << "[FAIL] " << e.what() << '\n';
        return 1;
    }

    return 0;
}
