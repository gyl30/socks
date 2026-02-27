#include <array>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <barrier>
#include <cstdint>
#include <utility>
#include <unistd.h>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "mux_codec.h"
#include "test_util.h"
#include "mux_protocol.h"
#include "reality_core.h"
#include "tls_record_layer.h"

#define private public
#include "mux_connection.h"

#undef private
#include "mux_stream_interface.h"
#include "mux_stream.h"

namespace
{
#ifdef __linux__
std::atomic<bool> g_force_rand_bytes_failure{false};
#endif
}

#ifdef __linux__
extern "C"
{
int __real_RAND_bytes(unsigned char* buf, int num);
}

extern "C"
{
int __wrap_RAND_bytes(unsigned char* buf, int num)
{
    if (g_force_rand_bytes_failure.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);
}
}
#endif

namespace
{

using namespace mux;

class simple_mock_stream : public mux_stream_interface
{
   public:
    [[nodiscard]] const std::vector<uint8_t>& received_data() const { return received_data_; }
    [[nodiscard]] std::size_t data_events() const { return data_events_; }
    [[nodiscard]] bool closed() const { return closed_; }
    [[nodiscard]] bool reset() const { return reset_; }

    void on_data(std::vector<uint8_t> data) override
    {
        data_events_++;
        received_data_.insert(received_data_.end(), data.begin(), data.end());
    }
    void on_close() override { closed_ = true; }
    void on_reset() override { reset_ = true; }

   private:
    std::vector<uint8_t> received_data_;
    std::size_t data_events_ = 0;
    bool closed_ = false;
    bool reset_ = false;
};

class ack_mock_stream : public simple_mock_stream
{
   public:
    [[nodiscard]] bool accept_ack() const override { return ack_pending_; }
    bool on_ack(std::vector<std::uint8_t> data) override
    {
        if (!ack_pending_)
        {
            return false;
        }
        ack_pending_ = false;
        on_data(std::move(data));
        return true;
    }

   private:
    bool ack_pending_ = true;
};

std::shared_ptr<mux_connection::stream_map_t> snapshot_streams_for_test(const std::shared_ptr<mux_connection>& conn)
{
    auto snapshot = std::atomic_load_explicit(&conn->streams_, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<mux_connection::stream_map_t>();
}

void insert_stream_for_test(const std::shared_ptr<mux_connection>& conn, const std::uint32_t id, const std::shared_ptr<mux_stream_interface>& stream)
{
    static const mux_connection::stream_map_t k_empty_streams{};
    for (;;)
    {
        auto current = std::atomic_load_explicit(&conn->streams_, std::memory_order_acquire);
        const auto* current_map = current.get();
        if (current_map == nullptr)
        {
            current_map = &k_empty_streams;
        }

        auto updated = std::make_shared<mux_connection::stream_map_t>(*current_map);
        (*updated)[id] = stream;

        auto expected = current;
        if (std::atomic_compare_exchange_weak_explicit(&conn->streams_, &expected, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

[[nodiscard]] bool has_stream_for_test(const std::shared_ptr<mux_connection>& conn, const std::uint32_t id)
{
    const auto snapshot = snapshot_streams_for_test(conn);
    return snapshot->find(id) != snapshot->end();
}

[[nodiscard]] std::size_t stream_count_for_test(const std::shared_ptr<mux_connection>& conn) { return snapshot_streams_for_test(conn)->size(); }

void drain_io_context(boost::asio::io_context& io_context, const int rounds = 16)
{
    io_context.restart();
    for (int i = 0; i < rounds; ++i)
    {
        if (io_context.poll() == 0)
        {
            break;
        }
    }
}

class mux_connection_integration_test_fixture : public ::testing::Test

{
   protected:
    boost::asio::io_context& io_ctx() { return io_ctx_; }

   private:
    boost::asio::io_context io_ctx_;
};

boost::system::error_code setup_loopback_acceptor_with_retry(boost::asio::ip::tcp::acceptor& acceptor, const int max_attempts = 128)
{
    boost::system::error_code last_ec = boost::asio::error::address_in_use;
    for (int attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (ec)
        {
            last_ec = ec;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }

        acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
        if (!ec)
        {
            acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
            if (!ec)
            {
                return {};
            }
        }

        boost::system::error_code ignored;
        acceptor.close(ignored);
        last_ec = ec;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return last_ec;
}

TEST_F(mux_connection_integration_test_fixture, StreamDataExchange)

{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();

    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    std::atomic<bool> accepted{false};

    acceptor.async_accept(*socket_server, [&](boost::system::error_code) { accepted = true; });

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

    boost::asio::co_spawn(io_ctx(), [conn_c]() -> boost::asio::awaitable<void> { co_await conn_c->start(); }, boost::asio::detached);
    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    std::vector<uint8_t> test_data = {'h', 'e', 'l', 'l', 'o'};

    boost::asio::co_spawn(
        io_ctx(),
        [&]() -> boost::asio::awaitable<void>
        {
            co_await conn_c->send_async(100, kCmdDat, test_data);

            boost::asio::steady_timer timer(io_ctx());
            for (int i = 0; i < 10; ++i)
            {
                if (stream_s->received_data().size() == test_data.size())
                {
                    break;
                }
                timer.expires_after(std::chrono::milliseconds(50));
                co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
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
                co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            }
            EXPECT_TRUE(stream_s->closed());

            conn_c->stop();
            conn_s->stop();
        },
        boost::asio::detached);

    io_ctx().run();
}

TEST_F(mux_connection_integration_test_fixture, ReadTimeoutHandling)
{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 1;
    timeout_cfg.write = 100;

    auto conn_s = std::make_shared<mux_connection>(
        std::move(*socket_server), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 1, "test", timeout_cfg);

    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    auto start_time = std::chrono::steady_clock::now();
    while (conn_s->is_open() && (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)))
    {
        io_ctx().poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_FALSE(conn_s->is_open());
}

TEST_F(mux_connection_integration_test_fixture, WriteTimeoutHandling)
{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 100;
    timeout_cfg.write = 1;

    auto conn_s = std::make_shared<mux_connection>(
        std::move(*socket_server), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 12, "write_timeout", timeout_cfg);

    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    auto start_time = std::chrono::steady_clock::now();
    while (conn_s->is_open() && (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(5)))
    {
        io_ctx().poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_FALSE(conn_s->is_open());
}

TEST_F(mux_connection_integration_test_fixture, ZeroReadTimeoutDoesNotCloseConnection)
{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 0;
    timeout_cfg.write = 100;

    auto conn_s = std::make_shared<mux_connection>(
        std::move(*socket_server), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 23, "zero_read_timeout", timeout_cfg);

    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2500);
    while (std::chrono::steady_clock::now() < deadline)
    {
        io_ctx().poll();
        if (!conn_s->is_open())
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_TRUE(conn_s->is_open());

    conn_s->stop();
    for (int i = 0; i < 20 && conn_s->is_open(); ++i)
    {
        io_ctx().poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

TEST_F(mux_connection_integration_test_fixture, ZeroWriteTimeoutDoesNotCloseConnection)
{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 100;
    timeout_cfg.write = 0;

    auto conn_s = std::make_shared<mux_connection>(
        std::move(*socket_server), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 24, "zero_write_timeout", timeout_cfg);

    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2500);
    while (std::chrono::steady_clock::now() < deadline)
    {
        io_ctx().poll();
        if (!conn_s->is_open())
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_TRUE(conn_s->is_open());

    conn_s->stop();
    for (int i = 0; i < 20 && conn_s->is_open(); ++i)
    {
        io_ctx().poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

#ifdef __linux__
TEST_F(mux_connection_integration_test_fixture, HeartbeatRandFailureStopsConnection)
{
    boost::asio::ip::tcp::acceptor acceptor(io_ctx());
    const auto setup_ec = setup_loopback_acceptor_with_retry(acceptor);
    ASSERT_FALSE(setup_ec) << setup_ec.message();
    auto socket_server = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());
    auto socket_client = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx());

    socket_client->connect(acceptor.local_endpoint());
    acceptor.accept(*socket_server);

    config::timeout_t timeout_cfg;
    timeout_cfg.read = 100;
    timeout_cfg.write = 100;

    config::heartbeat_t heartbeat_client;
    heartbeat_client.enabled = true;
    heartbeat_client.idle_timeout = 0;
    heartbeat_client.min_interval = 1;
    heartbeat_client.max_interval = 1;
    heartbeat_client.min_padding = 16;
    heartbeat_client.max_padding = 16;

    config::heartbeat_t heartbeat_server;
    heartbeat_server.enabled = false;

    auto conn_c = std::make_shared<mux_connection>(std::move(*socket_client),
                                                   io_ctx(),
                                                   reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                   true,
                                                   21,
                                                   "heartbeat_rand_fail_c",
                                                   timeout_cfg,
                                                   config::limits_t{},
                                                   heartbeat_client);
    auto conn_s = std::make_shared<mux_connection>(std::move(*socket_server),
                                                   io_ctx(),
                                                   reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                   false,
                                                   22,
                                                   "heartbeat_rand_fail_s",
                                                   timeout_cfg,
                                                   config::limits_t{},
                                                   heartbeat_server);

    g_force_rand_bytes_failure.store(true, std::memory_order_release);

    boost::asio::co_spawn(io_ctx(), [conn_c]() -> boost::asio::awaitable<void> { co_await conn_c->start(); }, boost::asio::detached);
    boost::asio::co_spawn(io_ctx(), [conn_s]() -> boost::asio::awaitable<void> { co_await conn_s->start(); }, boost::asio::detached);

    std::thread io_thread([this]() { io_ctx().run(); });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
    while (conn_c->is_open() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    EXPECT_FALSE(conn_c->is_open());

    g_force_rand_bytes_failure.store(false, std::memory_order_release);
    conn_c->stop();
    conn_s->stop();
    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}
#endif

TEST_F(mux_connection_integration_test_fixture, TryRegisterStreamRejectsDuplicateId)
{
    boost::asio::ip::tcp::socket socket(io_ctx());
    reality_engine engine{{}, {}, {}, {}, EVP_aes_128_gcm()};
    auto conn = std::make_shared<mux_connection>(std::move(socket), io_ctx(), std::move(engine), true, 1);

    auto stream_a = std::make_shared<simple_mock_stream>();
    auto stream_b = std::make_shared<simple_mock_stream>();

    EXPECT_TRUE(conn->try_register_stream(100, stream_a));
    EXPECT_FALSE(conn->try_register_stream(100, stream_b));
    EXPECT_TRUE(conn->has_stream(100));
}

TEST_F(mux_connection_integration_test_fixture, RegisterStreamRejectsDuplicateIdWithoutReplacingExistingStream)
{
    boost::asio::ip::tcp::socket socket(io_ctx());
    reality_engine engine{{}, {}, {}, {}, EVP_aes_128_gcm()};
    auto conn = std::make_shared<mux_connection>(std::move(socket), io_ctx(), std::move(engine), true, 101);

    auto stream_a = std::make_shared<simple_mock_stream>();
    auto stream_b = std::make_shared<simple_mock_stream>();

    EXPECT_TRUE(conn->register_stream(100, stream_a));
    EXPECT_FALSE(conn->register_stream(100, stream_b));
    EXPECT_EQ(stream_count_for_test(conn), 1U);

    const frame_header dat_header{
        .stream_id = 100,
        .length = 1,
        .command = kCmdDat,
    };
    conn->handle_stream_frame(dat_header, {0x7f});

    EXPECT_EQ(stream_a->data_events(), 1U);
    EXPECT_EQ(stream_b->data_events(), 0U);
}

TEST_F(mux_connection_integration_test_fixture, RegisterStreamAllowsTakeoverFromMuxPlaceholder)
{
    boost::asio::ip::tcp::socket socket(io_ctx());
    reality_engine engine{{}, {}, {}, {}, EVP_aes_128_gcm()};
    auto conn = std::make_shared<mux_connection>(std::move(socket), io_ctx(), std::move(engine), true, 102);

    auto placeholder = std::make_shared<mux_stream>(100, conn->id(), "takeover", conn, io_ctx());
    auto stream_handler = std::make_shared<simple_mock_stream>();

    EXPECT_TRUE(conn->register_stream(100, placeholder));
    EXPECT_TRUE(conn->register_stream(100, stream_handler));

    const frame_header dat_header{
        .stream_id = 100,
        .length = 1,
        .command = kCmdDat,
    };
    conn->handle_stream_frame(dat_header, {0x5a});

    EXPECT_EQ(stream_handler->data_events(), 1U);
}

TEST_F(mux_connection_integration_test_fixture, ClosedStateGuardsAndUnlimitedCheck)
{
    boost::asio::ip::tcp::socket socket(io_ctx());
    reality_engine engine{{}, {}, {}, {}, EVP_aes_128_gcm()};
    auto conn = std::make_shared<mux_connection>(std::move(socket), io_ctx(), std::move(engine), true, 2);
    auto stream = std::make_shared<simple_mock_stream>();

    conn->register_stream(1, nullptr);
    conn->connection_state_.store(mux_connection_state::kClosed, std::memory_order_release);
    conn->register_stream(2, stream);
    EXPECT_FALSE(conn->has_stream(2));
    EXPECT_FALSE(conn->try_register_stream(3, stream));
    EXPECT_FALSE(conn->can_accept_stream());

    config::limits_t limits_cfg;
    limits_cfg.max_streams = 0;
    auto unlimited = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                      io_ctx(),
                                                      reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                      true,
                                                      3,
                                                      "trace",
                                                      config::timeout_t{},
                                                      limits_cfg);
    unlimited->connection_state_.store(mux_connection_state::kClosed, std::memory_order_release);
    EXPECT_FALSE(unlimited->can_accept_stream());
}

TEST_F(mux_connection_integration_test_fixture, IsOpenTreatsDrainingAsOpen)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 10);

    conn->connection_state_.store(mux_connection_state::kDraining, std::memory_order_release);
    EXPECT_TRUE(conn->is_open());
    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_FALSE(conn->can_accept_stream());
    EXPECT_FALSE(conn->try_register_stream(501, stream));
    EXPECT_EQ(conn->create_stream("draining"), nullptr);

    conn->connection_state_.store(mux_connection_state::kClosing, std::memory_order_release);
    EXPECT_FALSE(conn->is_open());
}

TEST_F(mux_connection_integration_test_fixture, SendAsyncAllowedWhenDraining)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 13);

    conn->connection_state_.store(mux_connection_state::kDraining, std::memory_order_release);
    auto future = boost::asio::co_spawn(
        io_ctx(),
        [conn]() -> boost::asio::awaitable<boost::system::error_code> { co_return co_await conn->send_async(1, kCmdRst, {}); },
        boost::asio::use_future);

    io_ctx().run();
    EXPECT_EQ(future.get(), boost::system::error_code{});
}

TEST_F(mux_connection_integration_test_fixture, SendAsyncRejectsUnknownCommand)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 14);

    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    auto future = boost::asio::co_spawn(
        io_ctx(),
        [conn]() -> boost::asio::awaitable<boost::system::error_code> { co_return co_await conn->send_async(1, 0xFE, {}); },
        boost::asio::use_future);

    io_ctx().run();
    EXPECT_EQ(future.get(), boost::asio::error::invalid_argument);
}

TEST_F(mux_connection_integration_test_fixture, SendAsyncRejectsPayloadLargerThanSingleRecordLimit)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 15);

    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    std::vector<std::uint8_t> payload(reality::kMaxTlsPlaintextLen - mux::kHeaderSize + 1U, 0x7a);
    auto future = boost::asio::co_spawn(
        io_ctx(),
        [conn, payload = std::move(payload)]() mutable -> boost::asio::awaitable<boost::system::error_code>
        {
            co_return co_await conn->send_async(1, kCmdDat, std::move(payload));
        },
        boost::asio::use_future);

    io_ctx().run();
    EXPECT_EQ(future.get(), boost::asio::error::message_size);
}

TEST_F(mux_connection_integration_test_fixture, AcquireNextIdSkipsHeartbeatReservedIdAfterWrap)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, false, 16);

    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    conn->next_stream_id_.store(mux::kStreamIdHeartbeat, std::memory_order_release);

    EXPECT_EQ(conn->acquire_next_id(), 2U);
    EXPECT_EQ(conn->acquire_next_id(), 4U);

    auto stream = conn->create_stream("wrap-around");
    ASSERT_NE(stream, nullptr);
    EXPECT_FALSE(conn->has_stream(mux::kStreamIdHeartbeat));
}

TEST_F(mux_connection_integration_test_fixture, CreateStreamRetriesOnIdConflict)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 17);

    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    conn->next_stream_id_.store(1, std::memory_order_release);

    auto existing = std::make_shared<simple_mock_stream>();
    ASSERT_TRUE(conn->try_register_stream(1, existing));

    auto stream = conn->create_stream("id-conflict");
    ASSERT_NE(stream, nullptr);
    EXPECT_TRUE(conn->has_stream(1));
    EXPECT_TRUE(conn->has_stream(3));
}

TEST_F(mux_connection_integration_test_fixture, OffThreadRegisterAndQueryPaths)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 4);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::thread io_thread([&]() { io_ctx().run(); });

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->try_register_stream(42, stream));
    EXPECT_TRUE(conn->has_stream(42));
    EXPECT_FALSE(conn->has_stream(4042));
    EXPECT_TRUE(conn->can_accept_stream());

    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    io_ctx().restart();
}

TEST_F(mux_connection_integration_test_fixture, OffThreadCanAcceptStreamFalsePath)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 1;

    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 11,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::thread io_thread([&]() { io_ctx().run(); });

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->try_register_stream(1, stream));
    EXPECT_FALSE(conn->can_accept_stream());

    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    io_ctx().restart();
}

TEST_F(mux_connection_integration_test_fixture, OffThreadConcurrentCreateStreamRespectsLimit)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 1;

    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 12,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::atomic<bool> io_started{false};
    std::thread io_thread(
        [&]()
        {
            io_started.store(true, std::memory_order_release);
            io_ctx().run();
        });
    ASSERT_TRUE(mux::test::co_wait_until(
        [&io_started]() { return io_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    std::barrier gate(3);
    std::shared_ptr<mux_stream> stream_a;
    std::shared_ptr<mux_stream> stream_b;

    std::thread t1(
        [&]()
        {
            gate.arrive_and_wait();
            stream_a = conn->create_stream("race-a");
        });
    std::thread t2(
        [&]()
        {
            gate.arrive_and_wait();
            stream_b = conn->create_stream("race-b");
        });
    gate.arrive_and_wait();

    if (t1.joinable())
    {
        t1.join();
    }
    if (t2.joinable())
    {
        t2.join();
    }

    const auto success_count = static_cast<int>(stream_a != nullptr) + static_cast<int>(stream_b != nullptr);
    EXPECT_EQ(success_count, 1);
    EXPECT_EQ(stream_count_for_test(conn), 1U);

    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    io_ctx().restart();
}

TEST_F(mux_connection_integration_test_fixture, OffThreadSyncQueriesTimeoutWhenIoQueueBusyNoMutation)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 15);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::thread io_thread([&]() { io_ctx().run(); });

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });
    EXPECT_TRUE(mux::test::co_wait_until(
        [&blocker_started]() { return blocker_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    auto stream = std::make_shared<simple_mock_stream>();
    bool register_ok = true;
    bool try_register_ok = true;
    bool create_stream_is_null = false;
    std::atomic<bool> caller_done{false};
    std::thread caller(
        [&]()
        {
            register_ok = conn->register_stream(101, stream);
            try_register_ok = conn->try_register_stream(102, stream);
            create_stream_is_null = (conn->create_stream("busy-queue") == nullptr);
            caller_done.store(true, std::memory_order_release);
        });

    EXPECT_TRUE(
        mux::test::co_wait_until([&caller_done]() { return caller_done.load(std::memory_order_acquire); }, std::chrono::seconds(3)));
    release_blocker.store(true, std::memory_order_release);

    if (caller.joinable())
    {
        caller.join();
    }

    EXPECT_TRUE(register_ok);
    EXPECT_TRUE(try_register_ok);
    EXPECT_FALSE(create_stream_is_null);
    EXPECT_TRUE(has_stream_for_test(conn, 101));
    EXPECT_TRUE(has_stream_for_test(conn, 102));

    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    io_ctx().restart();
}

TEST_F(mux_connection_integration_test_fixture, OffThreadSyncQueryTimeoutDoesNotMutateBeforeStopAndRestart)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 18);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::thread io_thread([&]() { io_ctx().run(); });

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });
    EXPECT_TRUE(mux::test::co_wait_until(
        [&blocker_started]() { return blocker_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    auto stream = std::make_shared<simple_mock_stream>();
    bool register_ok = true;
    std::atomic<bool> caller_done{false};
    std::thread caller(
        [&]()
        {
            register_ok = conn->register_stream(201, stream);
            caller_done.store(true, std::memory_order_release);
        });

    EXPECT_TRUE(
        mux::test::co_wait_until([&caller_done]() { return caller_done.load(std::memory_order_acquire); }, std::chrono::seconds(1)));
    io_ctx().stop();
    release_blocker.store(true, std::memory_order_release);

    if (caller.joinable())
    {
        caller.join();
    }
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    EXPECT_TRUE(register_ok);
    EXPECT_TRUE(has_stream_for_test(conn, 201));

    io_ctx().restart();
    io_ctx().poll();
    EXPECT_TRUE(has_stream_for_test(conn, 201));
}

TEST_F(mux_connection_integration_test_fixture, OffThreadTryRegisterTimeoutDoesNotMutateBeforeStopAndRestart)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 19);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto guard = boost::asio::make_work_guard(io_ctx());
    std::thread io_thread([&]() { io_ctx().run(); });

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });
    EXPECT_TRUE(mux::test::co_wait_until(
        [&blocker_started]() { return blocker_started.load(std::memory_order_acquire); }, std::chrono::seconds(1)));

    auto stream = std::make_shared<simple_mock_stream>();
    bool try_register_ok = true;
    std::atomic<bool> caller_done{false};
    std::thread caller(
        [&]()
        {
            try_register_ok = conn->try_register_stream(202, stream);
            caller_done.store(true, std::memory_order_release);
        });

    EXPECT_TRUE(
        mux::test::co_wait_until([&caller_done]() { return caller_done.load(std::memory_order_acquire); }, std::chrono::seconds(1)));
    io_ctx().stop();
    release_blocker.store(true, std::memory_order_release);

    if (caller.joinable())
    {
        caller.join();
    }
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    EXPECT_TRUE(try_register_ok);
    EXPECT_TRUE(has_stream_for_test(conn, 202));

    io_ctx().restart();
    io_ctx().poll();
    EXPECT_TRUE(has_stream_for_test(conn, 202));
}

TEST_F(mux_connection_integration_test_fixture, MarkStartedForExternalCallsWithoutIoThreadCannotMutate)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 20);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    conn->mark_started_for_external_calls();

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->try_register_stream(303, stream));
    EXPECT_TRUE(has_stream_for_test(conn, 303));
}
TEST_F(mux_connection_integration_test_fixture, StoppedIoContextDefersQueryPathsUntilDrain)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 1;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 13,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    io_ctx().stop();

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->try_register_stream(42, stream));
    EXPECT_TRUE(conn->has_stream(42));
    EXPECT_FALSE(conn->can_accept_stream());
    conn->remove_stream(42);
    EXPECT_TRUE(conn->has_stream(42));
    EXPECT_FALSE(conn->can_accept_stream());
    drain_io_context(io_ctx());
    EXPECT_FALSE(conn->has_stream(42));
    EXPECT_TRUE(conn->can_accept_stream());
}

TEST_F(mux_connection_integration_test_fixture, StopRunsInlineWhenIoContextStopped)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 14);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    io_ctx().stop();
    conn->stop();

    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosing);
    drain_io_context(io_ctx());
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosed);
}

TEST_F(mux_connection_integration_test_fixture, StopRunsWhenIoContextNotRunning)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 16);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    conn->stop();
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosing);
    drain_io_context(io_ctx());
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosed);
}

TEST_F(mux_connection_integration_test_fixture, StopRunsWhenIoQueueBlocked)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 18);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto stream = std::make_shared<simple_mock_stream>();
    insert_stream_for_test(conn, 303, stream);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([this]() { io_ctx().run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        io_ctx().stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    conn->stop();
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosing);
    EXPECT_TRUE(has_stream_for_test(conn, 303));

    release_blocker.store(true, std::memory_order_release);
    EXPECT_TRUE(mux::test::co_wait_until(
        [conn]() { return conn->connection_state_.load(std::memory_order_acquire) == mux_connection_state::kClosed; }, std::chrono::seconds(2)));
    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    EXPECT_FALSE(has_stream_for_test(conn, 303));
    EXPECT_TRUE(stream->reset());
}

TEST_F(mux_connection_integration_test_fixture, RemoveStreamRunsWhenIoContextNotRunning)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 4;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 17,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    insert_stream_for_test(conn, 77, std::make_shared<simple_mock_stream>());
    ASSERT_TRUE(has_stream_for_test(conn, 77));

    conn->remove_stream(77);
    EXPECT_TRUE(has_stream_for_test(conn, 77));
    drain_io_context(io_ctx());
    EXPECT_FALSE(has_stream_for_test(conn, 77));
}

TEST_F(mux_connection_integration_test_fixture, RemoveStreamRunsInlineWhenIoContextStopped)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 4;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 18,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    insert_stream_for_test(conn, 78, std::make_shared<simple_mock_stream>());
    ASSERT_TRUE(has_stream_for_test(conn, 78));

    io_ctx().stop();
    conn->remove_stream(78);
    EXPECT_TRUE(has_stream_for_test(conn, 78));
    drain_io_context(io_ctx());
    EXPECT_FALSE(has_stream_for_test(conn, 78));
}

TEST_F(mux_connection_integration_test_fixture, RemoveStreamRunsWhenIoQueueBlocked)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 4;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 19,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    insert_stream_for_test(conn, 79, std::make_shared<simple_mock_stream>());
    ASSERT_TRUE(has_stream_for_test(conn, 79));

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([this]() { io_ctx().run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        io_ctx().stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    conn->remove_stream(79);
    EXPECT_TRUE(has_stream_for_test(conn, 79));

    release_blocker.store(true, std::memory_order_release);
    EXPECT_TRUE(mux::test::co_wait_until([conn]() { return !has_stream_for_test(conn, 79); }, std::chrono::seconds(2)));
    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST_F(mux_connection_integration_test_fixture, StopConcurrentRegisterAndTryRegisterWhenIoQueueBlocked)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 8;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 21,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto existing_stream = std::make_shared<simple_mock_stream>();
    insert_stream_for_test(conn, 701, existing_stream);
    ASSERT_TRUE(has_stream_for_test(conn, 701));

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([this]() { io_ctx().run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        io_ctx().stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    std::barrier sync_point(3);
    auto register_stream = std::make_shared<simple_mock_stream>();
    auto try_register_stream = std::make_shared<simple_mock_stream>();
    std::thread register_thread(
        [&]()
        {
            sync_point.arrive_and_wait();
            conn->register_stream(702, register_stream);
        });
    std::thread try_register_thread(
        [&]()
        {
            sync_point.arrive_and_wait();
            const bool try_register_result = conn->try_register_stream(703, try_register_stream);
            (void)try_register_result;
        });

    sync_point.arrive_and_wait();
    conn->stop();

    if (register_thread.joinable())
    {
        register_thread.join();
    }
    if (try_register_thread.joinable())
    {
        try_register_thread.join();
    }
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosing);

    release_blocker.store(true, std::memory_order_release);
    EXPECT_TRUE(mux::test::co_wait_until(
        [conn]() { return conn->connection_state_.load(std::memory_order_acquire) == mux_connection_state::kClosed; }, std::chrono::seconds(2)));
    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    EXPECT_FALSE(has_stream_for_test(conn, 701));
    EXPECT_FALSE(has_stream_for_test(conn, 702));
    EXPECT_FALSE(has_stream_for_test(conn, 703));
    EXPECT_EQ(stream_count_for_test(conn), 0U);
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosed);
    EXPECT_TRUE(existing_stream->reset());
}

TEST_F(mux_connection_integration_test_fixture, StopConcurrentRemoveWhenIoQueueBlocked)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 8;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 22,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);
    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);

    auto remove_target = std::make_shared<simple_mock_stream>();
    auto stop_target = std::make_shared<simple_mock_stream>();
    insert_stream_for_test(conn, 710, remove_target);
    insert_stream_for_test(conn, 711, stop_target);
    ASSERT_TRUE(has_stream_for_test(conn, 710));
    ASSERT_TRUE(has_stream_for_test(conn, 711));

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_ctx(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([this]() { io_ctx().run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        io_ctx().stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    std::barrier sync_point(2);
    std::thread remove_thread(
        [&]()
        {
            sync_point.arrive_and_wait();
            conn->remove_stream(710);
        });

    sync_point.arrive_and_wait();
    conn->stop();

    if (remove_thread.joinable())
    {
        remove_thread.join();
    }
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosing);

    release_blocker.store(true, std::memory_order_release);
    EXPECT_TRUE(mux::test::co_wait_until(
        [conn]() { return conn->connection_state_.load(std::memory_order_acquire) == mux_connection_state::kClosed; }, std::chrono::seconds(2)));
    io_ctx().stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    EXPECT_FALSE(has_stream_for_test(conn, 710));
    EXPECT_FALSE(has_stream_for_test(conn, 711));
    EXPECT_EQ(stream_count_for_test(conn), 0U);
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosed);
    EXPECT_TRUE(stop_target->reset());
}

TEST_F(mux_connection_integration_test_fixture, StopDrainingAndInternalErrorBranches)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 5);

    conn->connection_state_.store(mux_connection_state::kDraining, std::memory_order_release);
    conn->stop();
    io_ctx().poll();

    conn->connection_state_.store(mux_connection_state::kClosed, std::memory_order_release);
    conn->stop_impl();
    conn->close_socket_on_stop();

    EXPECT_TRUE(conn->should_stop_read(boost::asio::error::connection_reset, 0));

    std::array<std::uint8_t, 8> junk = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00};
    conn->mux_dispatcher_.set_max_buffer(1);
    conn->mux_dispatcher_.on_plaintext_data(std::span<const std::uint8_t>(junk.data(), junk.size()));
    EXPECT_TRUE(conn->has_dispatch_failure(std::make_error_code(std::errc::protocol_error)));
}

TEST_F(mux_connection_integration_test_fixture, HandleStreamAndUnknownStreamBranches)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 6);

    auto stream = std::make_shared<ack_mock_stream>();
    EXPECT_TRUE(conn->register_stream_local(100, stream));

    std::vector<std::uint8_t> const ack_payload = {1, 2, 3};
    const frame_header ack_header{
        .stream_id = 100,
        .length = static_cast<std::uint16_t>(ack_payload.size()),
        .command = kCmdAck,
    };
    conn->handle_stream_frame(ack_header, ack_payload);
    std::vector<std::uint8_t> dat_payload = {4, 5, 6};
    const frame_header dat_header{
        .stream_id = 100,
        .length = static_cast<std::uint16_t>(dat_payload.size()),
        .command = kCmdDat,
    };
    conn->handle_stream_frame(dat_header, dat_payload);

    std::vector<std::uint8_t> expected = ack_payload;
    expected.insert(expected.end(), dat_payload.begin(), dat_payload.end());
    EXPECT_EQ(stream->received_data(), expected);
    EXPECT_EQ(stream->data_events(), 2U);

    const frame_header unknown_header{
        .stream_id = 100,
        .length = 0,
        .command = 0xFF,
    };
    conn->handle_stream_frame(unknown_header, {});
    EXPECT_TRUE(stream->reset());
    EXPECT_TRUE(has_stream_for_test(conn, 100));
    drain_io_context(io_ctx());
    EXPECT_FALSE(has_stream_for_test(conn, 100));

    conn->handle_unknown_stream(1000, kCmdRst);
    conn->handle_unknown_stream(1001, kCmdDat);
    io_ctx().poll();
}

TEST_F(mux_connection_integration_test_fixture, UnexpectedAckResetsNonAckStream)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 26);

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->register_stream_local(101, stream));

    const frame_header ack_header{
        .stream_id = 101,
        .length = 1,
        .command = kCmdAck,
    };
    conn->handle_stream_frame(ack_header, {0x42});

    EXPECT_TRUE(stream->reset());
    EXPECT_TRUE(has_stream_for_test(conn, 101));
    drain_io_context(io_ctx());
    EXPECT_FALSE(has_stream_for_test(conn, 101));
    EXPECT_EQ(stream->data_events(), 0U);
    EXPECT_TRUE(stream->received_data().empty());
}

TEST_F(mux_connection_integration_test_fixture, EmptyDatIgnoredWithoutReset)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 28);

    auto stream = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->register_stream_local(103, stream));

    const frame_header empty_dat_header{
        .stream_id = 103,
        .length = 0,
        .command = kCmdDat,
    };
    conn->handle_stream_frame(empty_dat_header, {});

    EXPECT_FALSE(stream->reset());
    EXPECT_TRUE(has_stream_for_test(conn, 103));
    EXPECT_EQ(stream->data_events(), 0U);
    EXPECT_TRUE(stream->received_data().empty());
}

TEST_F(mux_connection_integration_test_fixture, UnexpectedRepeatedAckResetsAckStream)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 27);

    auto stream = std::make_shared<ack_mock_stream>();
    EXPECT_TRUE(conn->register_stream_local(102, stream));

    const frame_header first_ack_header{
        .stream_id = 102,
        .length = 1,
        .command = kCmdAck,
    };
    conn->handle_stream_frame(first_ack_header, {0x11});

    EXPECT_EQ(stream->data_events(), 1U);
    EXPECT_FALSE(stream->reset());
    EXPECT_TRUE(has_stream_for_test(conn, 102));

    const frame_header second_ack_header{
        .stream_id = 102,
        .length = 1,
        .command = kCmdAck,
    };
    conn->handle_stream_frame(second_ack_header, {0x22});

    EXPECT_TRUE(stream->reset());
    EXPECT_TRUE(has_stream_for_test(conn, 102));
    drain_io_context(io_ctx());
    EXPECT_FALSE(has_stream_for_test(conn, 102));
    EXPECT_EQ(stream->data_events(), 1U);
    EXPECT_EQ(stream->received_data(), std::vector<std::uint8_t>({0x11}));
}

TEST_F(mux_connection_integration_test_fixture, SynCallbackAndReadGuardBranches)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 7);

    const frame_header syn_header{
        .stream_id = 88,
        .length = 1,
        .command = kCmdSyn,
    };

    conn->on_mux_frame(syn_header, {7});
    const auto [no_cb_ec, no_cb_msg] =
        mux::test::run_awaitable(io_ctx(), conn->write_channel_->async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)));
    EXPECT_FALSE(no_cb_ec);
    EXPECT_EQ(no_cb_msg.stream_id, 88U);
    EXPECT_EQ(no_cb_msg.command, kCmdRst);
    EXPECT_TRUE(no_cb_msg.payload.empty());

    bool syn_called = false;
    std::uint32_t syn_stream_id = 0;
    std::vector<std::uint8_t> syn_payload;
    conn->set_syn_callback(
        [&](const std::uint32_t stream_id, std::vector<std::uint8_t> payload)
        {
            syn_called = true;
            syn_stream_id = stream_id;
            syn_payload = std::move(payload);
        });
    conn->on_mux_frame(syn_header, {9});

    EXPECT_TRUE(syn_called);
    EXPECT_EQ(syn_stream_id, 88);
    EXPECT_EQ(syn_payload, std::vector<std::uint8_t>({9}));

    EXPECT_FALSE(conn->should_stop_read(boost::system::error_code{}, 8));
    EXPECT_TRUE(conn->should_stop_read(boost::system::error_code{}, 0));
    EXPECT_TRUE(conn->should_stop_read(boost::asio::error::eof, 0));
    EXPECT_TRUE(conn->should_stop_read(boost::asio::error::operation_aborted, 0));
}

TEST_F(mux_connection_integration_test_fixture, RejectsNonDatHeartbeatCommand)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 19);

    const frame_header invalid_heartbeat{
        .stream_id = mux::kStreamIdHeartbeat,
        .length = 0,
        .command = kCmdSyn,
    };

    conn->on_mux_frame(invalid_heartbeat, {});
    EXPECT_FALSE(conn->is_open());
}

TEST_F(mux_connection_integration_test_fixture, ResetStreamsAndDispatchFailureBranches)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 8);

    auto reset_stream = std::make_shared<simple_mock_stream>();
    mux_connection::stream_map_t streams_to_clear;
    streams_to_clear.emplace(1, reset_stream);
    streams_to_clear.emplace(2, nullptr);
    conn->reset_streams_on_stop(streams_to_clear);

    EXPECT_TRUE(reset_stream->reset());
    EXPECT_EQ(streams_to_clear.size(), 2U);
    EXPECT_FALSE(conn->has_dispatch_failure(boost::system::error_code{}));
    EXPECT_TRUE(conn->has_dispatch_failure(std::make_error_code(std::errc::protocol_error)));
}

TEST_F(mux_connection_integration_test_fixture, ProcessDecryptedRecordsRejectsUnexpectedContentType)
{
    std::vector<std::uint8_t> read_key(16, 0x11);
    std::vector<std::uint8_t> read_iv(12, 0x22);
    std::vector<std::uint8_t> write_key(16, 0x33);
    std::vector<std::uint8_t> write_iv(12, 0x44);

    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine(read_key, read_iv, write_key, write_iv, EVP_aes_128_gcm()),
                                                 true,
                                                 29);

    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
    auto encrypted = reality::tls_record_layer::encrypt_record(
        EVP_aes_128_gcm(), read_key, read_iv, 0, payload, reality::kContentTypeHandshake);
    ASSERT_TRUE(encrypted.has_value());

    auto write_buf = conn->reality_engine_.read_buffer(encrypted->size());
    const auto copied = boost::asio::buffer_copy(write_buf, boost::asio::buffer(*encrypted));
    ASSERT_EQ(copied, encrypted->size());
    conn->reality_engine_.commit_read(copied);

    const auto process_res = conn->process_decrypted_records();
    ASSERT_FALSE(process_res.has_value());
    EXPECT_EQ(process_res.error(), boost::asio::error::invalid_argument);
}

TEST_F(mux_connection_integration_test_fixture, DispatchFailureOnOversizedFrameHeader)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 24);

    std::vector<std::uint8_t> oversized_header = {0x00, 0x00, 0x00, 0x2a, 0xff, 0xff, kCmdDat};
    conn->mux_dispatcher_.on_plaintext_data(std::span<const std::uint8_t>(oversized_header.data(), oversized_header.size()));

    EXPECT_TRUE(conn->mux_dispatcher_.has_fatal_error());
    EXPECT_EQ(conn->mux_dispatcher_.fatal_error_reason(), mux_dispatcher_fatal_reason::kOversizedFrame);
    EXPECT_TRUE(conn->has_dispatch_failure(boost::system::error_code{}));
}

TEST_F(mux_connection_integration_test_fixture, TryRegisterNullAndCloseSocketErrorBranches)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 9);

    EXPECT_FALSE(conn->try_register_stream(77, nullptr));

    boost::asio::ip::tcp::socket broken_socket(io_ctx());
    boost::system::error_code open_ec;
    broken_socket.open(boost::asio::ip::tcp::v4(), open_ec);
    ASSERT_FALSE(open_ec);

    const int native_fd = broken_socket.native_handle();
    ASSERT_GE(native_fd, 0);
    ASSERT_EQ(::close(native_fd), 0);

    conn->socket_ = std::move(broken_socket);
    conn->close_socket_on_stop();

    conn->write_channel_.reset();
    conn->finalize_stop_state();
    EXPECT_EQ(conn->connection_state_.load(std::memory_order_acquire), mux_connection_state::kClosed);
}

TEST_F(mux_connection_integration_test_fixture, StreamStorageNullFallbackPaths)
{
    auto conn = std::make_shared<mux_connection>(
        boost::asio::ip::tcp::socket(io_ctx()), io_ctx(), reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 23);

    conn->streams_.reset();
    const auto snapshot = conn->snapshot_streams();
    EXPECT_TRUE(snapshot->empty());

    conn->streams_.reset();
    const auto detached = conn->detach_streams();
    EXPECT_TRUE(detached->empty());
    EXPECT_NE(conn->streams_, nullptr);

    auto stream = std::make_shared<simple_mock_stream>();
    conn->streams_.reset();
    EXPECT_TRUE(conn->register_stream_local(501, stream));
    EXPECT_TRUE(conn->has_stream_local(501));
}

TEST_F(mux_connection_integration_test_fixture, TryRegisterLocalNullStorageAndLimitBranches)
{
    config::limits_t limits_cfg;
    limits_cfg.max_streams = 1;
    auto conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                 io_ctx(),
                                                 reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                 true,
                                                 24,
                                                 "trace",
                                                 config::timeout_t{},
                                                 limits_cfg);

    conn->streams_.reset();
    auto stream_a = std::make_shared<simple_mock_stream>();
    auto stream_b = std::make_shared<simple_mock_stream>();
    EXPECT_TRUE(conn->try_register_stream_local(601, stream_a));
    EXPECT_FALSE(conn->try_register_stream_local(602, stream_b));
    EXPECT_TRUE(conn->has_stream_local(601));
    EXPECT_FALSE(conn->has_stream_local(602));
}

TEST_F(mux_connection_integration_test_fixture, CanAcceptStreamLocalAndPublicLimitBranches)
{
    config::limits_t unlimited_limits;
    unlimited_limits.max_streams = 0;
    auto unlimited_conn = std::make_shared<mux_connection>(boost::asio::ip::tcp::socket(io_ctx()),
                                                           io_ctx(),
                                                           reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
                                                           true,
                                                           25,
                                                           "trace",
                                                           config::timeout_t{},
                                                           unlimited_limits);

    unlimited_conn->connection_state_.store(mux_connection_state::kConnected, std::memory_order_release);
    EXPECT_TRUE(unlimited_conn->can_accept_stream_local());
    EXPECT_TRUE(unlimited_conn->can_accept_stream());

    unlimited_conn->connection_state_.store(mux_connection_state::kClosing, std::memory_order_release);
    EXPECT_FALSE(unlimited_conn->can_accept_stream_local());
}

}
