
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <netdb.h>
#include <utility>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#define private public
#include "remote_udp_session.h"

#undef private

#include "protocol.h"
#include "mux_codec.h"
#include "test_util.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "mock_mux_connection.h"

namespace
{

using ::testing::_;

std::atomic<bool> g_delay_getaddrinfo_once{false};
std::atomic<int> g_delay_getaddrinfo_ms{0};

void delay_next_getaddrinfo(const int delay_ms)
{
    g_delay_getaddrinfo_ms.store(delay_ms, std::memory_order_release);
    g_delay_getaddrinfo_once.store(true, std::memory_order_release);
}

extern "C" int __real_getaddrinfo(const char* node,    
                                  const char* service,
                                  const struct addrinfo* hints,
                                  struct addrinfo** res);

extern "C" int __wrap_getaddrinfo(const char* node,    
                                  const char* service,
                                  const struct addrinfo* hints,
                                  struct addrinfo** res)
{
    if (g_delay_getaddrinfo_once.exchange(false, std::memory_order_acq_rel))
    {
        const auto delay_ms = g_delay_getaddrinfo_ms.load(std::memory_order_acquire);
        if (delay_ms > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
    }
    return __real_getaddrinfo(node, service, hints, res);    
}

class noop_stream : public mux::mux_stream_interface
{
   public:
    void on_data(std::vector<std::uint8_t>) override {}
    void on_close() override {}
    void on_reset() override {}
};

std::vector<std::uint8_t> make_mux_udp_packet(const std::string& host, const std::uint16_t port, const std::vector<std::uint8_t>& payload)
{
    socks_udp_header header{};
    header.addr = host;
    header.port = port;
    auto packet = socks_codec::encode_udp_header(header);
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

std::shared_ptr<mux::remote_udp_session> make_session(boost::asio::io_context& io_context,
                                                      const std::shared_ptr<mux::mock_mux_connection>& conn,
                                                      const std::uint32_t id = 1,
                                                      const mux::config::timeout_t& timeout_cfg = {})
{
    mux::connection_context const ctx;
    return std::make_shared<mux::remote_udp_session>(conn, id, io_context, ctx, timeout_cfg);
}

std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> make_manager(boost::asio::io_context& io_context, const std::uint32_t id = 99)
{
    return std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, id);
}

TEST(RemoteUdpSessionTest, StartReturnsWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 10);
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->start());
    SUCCEED();
}

TEST(RemoteUdpSessionTest, StartRemovesManagerStreamWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 110);
    auto manager = make_manager(io_context, 410);
    manager->connection()->register_stream(110, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(110));
    session->set_manager(manager);
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->start());

    EXPECT_FALSE(manager->connection()->has_stream(110));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(RemoteUdpSessionTest, SetupUdpSocketAlreadyOpenTriggersFailureAckAndReset)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 11);
    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdAck, _))
        .WillOnce(
            [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                ack_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    const bool ok = mux::test::run_awaitable(io_context, session->setup_udp_socket(conn));
    EXPECT_FALSE(ok);
    EXPECT_FALSE(session->udp_socket_.is_open());

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepGenFail);
}

TEST(RemoteUdpSessionTest, HandleStartFailureRemovesStreamWhenManagerExists)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 12);

    auto manager = make_manager(io_context, 300);
    manager->connection()->register_stream(12, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(12));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdAck, _)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->handle_start_failure(conn, "udp open", boost::asio::error::already_open));
    EXPECT_FALSE(manager->connection()->has_stream(12));
}

TEST(RemoteUdpSessionTest, SetupUdpSocketSuccessAndCloseSocket)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 13);

    const bool ok = mux::test::run_awaitable(io_context, session->setup_udp_socket(conn));
    ASSERT_TRUE(ok);
    ASSERT_TRUE(session->udp_socket_.is_open());

    session->close_socket();
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(RemoteUdpSessionTest, CloseSocketNoopWhenAlreadyClosed)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 131);

    EXPECT_FALSE(session->udp_socket_.is_open());
    session->close_socket();
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(RemoteUdpSessionTest, LogUdpLocalEndpointHandlesClosedSocket)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 132);

    session->log_udp_local_endpoint();
    SUCCEED();
}

TEST(RemoteUdpSessionTest, CleanupAfterStopWithoutManagerClosesSocket)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 133);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));
    ASSERT_TRUE(session->udp_socket_.is_open());

    EXPECT_CALL(*conn, mock_send_async(133, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(io_context, session->cleanup_after_stop());
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(RemoteUdpSessionTest, ForwardMuxPayloadRejectsInvalidPackets)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 14);
    auto& stats = mux::statistics::instance();
    const auto resolve_errors_before = stats.remote_udp_session_resolve_errors();
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(std::vector<std::uint8_t>{0x00, 0x01}));
    const auto no_payload_packet = make_mux_udp_packet("127.0.0.1", 53, {});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(no_payload_packet));
    const auto resolve_fail_packet = make_mux_udp_packet("non-existent.invalid", 5353, std::vector<std::uint8_t>{0x01});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(resolve_fail_packet));
    EXPECT_GE(stats.remote_udp_session_resolve_errors(), resolve_errors_before + 1);
}

TEST(RemoteUdpSessionTest, ForwardMuxPayloadDropsFragmentedPackets)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 141);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::ip::udp::socket receiver(io_context);
    boost::system::error_code ec;
    receiver.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);
    receiver.set_option(boost::asio::ip::v6_only(false), ec);
    ASSERT_FALSE(ec);
    receiver.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    ASSERT_FALSE(ec);
    receiver.non_blocking(true, ec);
    ASSERT_FALSE(ec);

    socks_udp_header header{};
    header.frag = 0x01;
    header.addr = "127.0.0.1";
    header.port = receiver.local_endpoint().port();
    auto packet = socks_codec::encode_udp_header(header);
    packet.push_back(0x5A);

    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(packet));

    std::array<std::uint8_t, 8> recv = {0};
    boost::asio::ip::udp::endpoint from_ep;
    const auto n = receiver.receive_from(boost::asio::buffer(recv), from_ep, 0, ec);
    EXPECT_EQ(n, 0U);
    EXPECT_TRUE(ec == boost::asio::error::would_block || ec == boost::asio::error::try_again);
}

TEST(RemoteUdpSessionTest, ForwardMuxPayloadSendsIpv4AndIpv6Payloads)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 15);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::ip::udp::socket receiver(io_context);
    boost::system::error_code ec;
    receiver.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);
    receiver.set_option(boost::asio::ip::v6_only(false), ec);
    ASSERT_FALSE(ec);
    receiver.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    ASSERT_FALSE(ec);
    receiver.non_blocking(true, ec);
    ASSERT_FALSE(ec);
    const auto port = receiver.local_endpoint().port();

    const auto v4_packet = make_mux_udp_packet("127.0.0.1", port, std::vector<std::uint8_t>{0x11, 0x22});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(v4_packet));
    std::array<std::uint8_t, 8> first_recv = {0};
    boost::asio::ip::udp::endpoint from_ep;
    std::size_t first_n = 0;
    for (int i = 0; i < 50; ++i)
    {
        first_n = receiver.receive_from(boost::asio::buffer(first_recv), from_ep, 0, ec);
        if (!ec)
        {
            break;
        }
        if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_FALSE(ec);
    ASSERT_EQ(first_n, 2U);
    EXPECT_EQ(first_recv[0], 0x11);
    EXPECT_EQ(first_recv[1], 0x22);

    const auto v6_packet = make_mux_udp_packet("::1", port, std::vector<std::uint8_t>{0x33, 0x44, 0x55});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(v6_packet));
}

TEST(RemoteUdpSessionTest, ForwardMuxPayloadStopsWhenSocketClosed)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 16);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));
    session->close_socket();

    const auto packet = make_mux_udp_packet("127.0.0.1", 53, std::vector<std::uint8_t>{0x99});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(packet));
}

TEST(RemoteUdpSessionTest, ForwardMuxPayloadResolveTimeoutDropsPayload)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::config::timeout_t timeout_cfg;
    timeout_cfg.read = 1;
    auto session = make_session(io_context, conn, 134, timeout_cfg);
    auto& stats = mux::statistics::instance();
    const auto resolve_timeouts_before = stats.remote_udp_session_resolve_timeouts();
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::ip::udp::socket receiver(io_context);
    boost::system::error_code ec;
    receiver.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);
    receiver.set_option(boost::asio::ip::v6_only(false), ec);
    ASSERT_FALSE(ec);
    receiver.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    ASSERT_FALSE(ec);
    receiver.non_blocking(true, ec);
    ASSERT_FALSE(ec);

    delay_next_getaddrinfo(1500);
    const auto packet = make_mux_udp_packet("localhost", receiver.local_endpoint().port(), std::vector<std::uint8_t>{0x42});
    mux::test::run_awaitable_void(io_context, session->forward_mux_payload(packet));

    std::array<std::uint8_t, 8> recv_buf = {0};
    boost::asio::ip::udp::endpoint from_ep;
    const auto recv_n = receiver.receive_from(boost::asio::buffer(recv_buf), from_ep, 0, ec);
    EXPECT_EQ(recv_n, 0U);
    EXPECT_TRUE(ec == boost::asio::error::would_block || ec == boost::asio::error::try_again);
    EXPECT_GE(stats.remote_udp_session_resolve_timeouts(), resolve_timeouts_before + 1);
}

TEST(RemoteUdpSessionTest, MuxToUdpProcessesUntilEmptyFrame)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 17);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::ip::udp::socket receiver(io_context);
    boost::system::error_code ec;
    receiver.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);
    receiver.set_option(boost::asio::ip::v6_only(false), ec);
    ASSERT_FALSE(ec);
    receiver.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    ASSERT_FALSE(ec);

    const auto payload_packet = make_mux_udp_packet("127.0.0.1", receiver.local_endpoint().port(), std::vector<std::uint8_t>{0x7A});
    session->recv_channel_.try_send(boost::system::error_code{}, payload_packet);
    session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{});
    mux::test::run_awaitable_void(io_context, session->mux_to_udp());

    std::array<std::uint8_t, 8> recv = {0};
    boost::asio::ip::udp::endpoint from_ep;
    const auto n = receiver.receive_from(boost::asio::buffer(recv), from_ep, 0, ec);
    ASSERT_FALSE(ec);
    ASSERT_EQ(n, 1U);
    EXPECT_EQ(recv[0], 0x7A);
}

TEST(RemoteUdpSessionTest, UdpToMuxForwardsAndStopsOnSendFailure)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 18);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::ip::udp::socket sender(io_context);
    boost::system::error_code ec;
    sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const std::vector<std::uint8_t> source_payload = {0xAA, 0xBB};
    const auto target_ep =
        boost::asio::ip::udp::endpoint(boost::asio::ip::make_address_v4("127.0.0.1"), session->udp_socket_.local_endpoint().port());
    sender.send_to(boost::asio::buffer(source_payload), target_ep, 0, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> dat_payload;
    EXPECT_CALL(*conn, mock_send_async(18, mux::kCmdDat, _))
        .WillOnce(
            [&dat_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                dat_payload = payload;
                return boost::asio::error::broken_pipe;
            });

    mux::test::run_awaitable_void(io_context, session->udp_to_mux());

    socks_udp_header decoded{};
    ASSERT_TRUE(socks_codec::decode_udp_header(dat_payload.data(), dat_payload.size(), decoded));
    ASSERT_LT(decoded.header_len, dat_payload.size());
    EXPECT_EQ(dat_payload[decoded.header_len], 0xAA);
    EXPECT_EQ(dat_payload[decoded.header_len + 1], 0xBB);
}

TEST(RemoteUdpSessionTest, UdpToMuxStopsWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 19);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));
    conn.reset();

    boost::asio::ip::udp::socket sender(io_context);
    boost::system::error_code ec;
    sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const auto target_ep =
        boost::asio::ip::udp::endpoint(boost::asio::ip::make_address_v4("127.0.0.1"), session->udp_socket_.local_endpoint().port());
    sender.send_to(boost::asio::buffer(std::vector<std::uint8_t>{0xEE}), target_ep, 0, ec);
    ASSERT_FALSE(ec);

    mux::test::run_awaitable_void(io_context, session->udp_to_mux());
}

TEST(RemoteUdpSessionTest, OnDataDispatchesPayload)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 20);

    session->on_data(std::vector<std::uint8_t>{0x10, 0x20});
    const auto [recv_ec, data] =
        mux::test::run_awaitable(io_context, session->recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)));
    EXPECT_FALSE(recv_ec);
    ASSERT_EQ(data.size(), 2U);
    EXPECT_EQ(data[0], 0x10);
    EXPECT_EQ(data[1], 0x20);
}

TEST(RemoteUdpSessionTest, OnDataRunsStopWhenIoContextStopped)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 215);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    session->recv_channel_.close();

    session->timer_.expires_after(std::chrono::seconds(30));
    session->timer_.async_wait([](const boost::system::error_code&) {});

    io_context.stop();
    session->on_data(std::vector<std::uint8_t>{0x10});

    EXPECT_EQ(session->timer_.cancel(), 0U);
    EXPECT_FALSE(session->udp_socket_.is_open());
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnDataRunsStopWhenIoContextNotRunning)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 216);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    session->recv_channel_.close();

    session->timer_.expires_after(std::chrono::seconds(30));
    session->timer_.async_wait([](const boost::system::error_code&) {});

    session->on_data(std::vector<std::uint8_t>{0x10});
    EXPECT_EQ(session->timer_.cancel(), 0U);
    EXPECT_FALSE(session->udp_socket_.is_open());
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnDataRunsStopWhenIoQueueBlocked)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 214);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    session->recv_channel_.close();

    std::promise<boost::system::error_code> timer_wait_done;
    auto timer_wait_future = timer_wait_done.get_future();
    session->timer_.expires_after(std::chrono::seconds(30));
    session->timer_.async_wait([done = std::move(timer_wait_done)](const boost::system::error_code& ec) mutable { done.set_value(ec); });

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_context,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { io_context.run(); });
    for (int i = 0; i < 100 && !blocker_started.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(blocker_started.load(std::memory_order_acquire));

    session->on_data(std::vector<std::uint8_t>{0x10});

    release_blocker.store(true, std::memory_order_release);
    const bool timer_cancelled = timer_wait_future.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready;
    if (!timer_cancelled)
    {
        session->request_stop();
    }

    io_context.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }

    ASSERT_TRUE(timer_cancelled);
    EXPECT_EQ(timer_wait_future.get(), boost::asio::error::operation_aborted);
    EXPECT_FALSE(session->udp_socket_.is_open());
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnCloseAndOnResetCloseReceiveChannel)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 21);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    session->on_close();
    io_context.run();
    io_context.restart();
    session->on_reset();
    io_context.run();
    io_context.restart();

    const auto [recv_ec, recv_data] =
        mux::test::run_awaitable(io_context, session->recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)));
    EXPECT_TRUE(recv_ec);
    EXPECT_TRUE(recv_data.empty());
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnCloseAndOnResetRemoveManagerStreamEvenBeforeStart)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto manager = make_manager(io_context, 411);

    auto session = make_session(io_context, conn, 210);
    manager->connection()->register_stream(210, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(210));
    session->set_manager(manager);

    session->on_close();
    io_context.run();
    io_context.restart();
    EXPECT_FALSE(manager->connection()->has_stream(210));

    auto reset_session = make_session(io_context, conn, 211);
    manager->connection()->register_stream(211, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(211));
    reset_session->set_manager(manager);
    reset_session->on_reset();
    io_context.run();
    io_context.restart();
    EXPECT_FALSE(manager->connection()->has_stream(211));
}

TEST(RemoteUdpSessionTest, OnCloseAndOnResetRunInlineWhenIoContextStopped)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 211);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    io_context.stop();
    session->on_close();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));
    EXPECT_FALSE(session->udp_socket_.is_open());

    session->on_reset();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x02}));
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnCloseAndOnResetRunWhenIoContextNotRunning)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 212);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    session->on_close();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));
    EXPECT_FALSE(session->udp_socket_.is_open());

    session->on_reset();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x02}));
    session->close_socket();
}

TEST(RemoteUdpSessionTest, OnCloseAndOnResetRunWhenIoQueueBlocked)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 213);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(io_context,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { io_context.run(); });
    for (int i = 0; i < 100 && !blocker_started.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(blocker_started.load(std::memory_order_acquire));

    session->on_close();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));
    EXPECT_FALSE(session->udp_socket_.is_open());

    session->on_reset();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x02}));

    release_blocker.store(true, std::memory_order_release);
    io_context.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
    session->close_socket();
}

TEST(RemoteUdpSessionTest, StartImplSendsAckAndCleansUpManager)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 22);
    auto manager = make_manager(io_context, 301);
    manager->connection()->register_stream(22, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(22));
    session->set_manager(manager);

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(22, mux::kCmdAck, _))
        .WillOnce(
            [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                ack_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(22, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    boost::asio::co_spawn(
        io_context,
        [session]() -> boost::asio::awaitable<void>
        {
            boost::asio::steady_timer stop_timer(co_await boost::asio::this_coro::executor);
            stop_timer.expires_after(std::chrono::milliseconds(10));
            co_await stop_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            session->on_close();
        },
        boost::asio::detached);

    mux::test::run_awaitable_void(io_context, session->start_impl(session));

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepSuccess);
    EXPECT_FALSE(ack.bnd_addr.empty());
    EXPECT_NE(ack.bnd_addr, "0.0.0.0");
    EXPECT_NE(ack.bnd_port, 0);
    EXPECT_FALSE(session->udp_socket_.is_open());
    EXPECT_FALSE(manager->connection()->has_stream(22));
}

TEST(RemoteUdpSessionTest, StartImplSkipsAckWhenStopRequestedBeforeStart)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 26);
    auto manager = make_manager(io_context, 303);
    manager->connection()->register_stream(26, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(26));
    session->set_manager(manager);

    session->on_close();

    EXPECT_CALL(*conn, mock_send_async(26, mux::kCmdAck, _)).Times(0);
    EXPECT_CALL(*conn, mock_send_async(26, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->start_impl(session));

    EXPECT_FALSE(session->udp_socket_.is_open());
    EXPECT_FALSE(manager->connection()->has_stream(26));
}

TEST(RemoteUdpSessionTest, StartImplAckFailureStopsSessionAndRemovesStream)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 25);
    auto manager = make_manager(io_context, 302);
    manager->connection()->register_stream(25, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(25));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(25, mux::kCmdAck, _)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
    EXPECT_CALL(*conn, mock_send_async(25, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->start_impl(session));

    EXPECT_FALSE(session->udp_socket_.is_open());
    EXPECT_FALSE(manager->connection()->has_stream(25));
}

TEST(RemoteUdpSessionTest, WatchdogStopsWhenCancelled)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 23);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));

    boost::asio::co_spawn(
        io_context,
        [session]() -> boost::asio::awaitable<void>
        {
            boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
            timer.expires_after(std::chrono::milliseconds(20));
            co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            session->request_stop();
        },
        boost::asio::detached);

    mux::test::run_awaitable_void(io_context, session->watchdog());
}

TEST(RemoteUdpSessionTest, TimeoutThresholdsUseConfigValues)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::config::timeout_t timeout_cfg;
    timeout_cfg.read = 12;
    timeout_cfg.write = 34;
    timeout_cfg.idle = 56;
    auto session = make_session(io_context, conn, 230, timeout_cfg);

    EXPECT_EQ(session->read_timeout_ms_, 12000ULL);
    EXPECT_EQ(session->write_timeout_ms_, 34000ULL);
    EXPECT_EQ(session->idle_timeout_ms_, 56000ULL);
}

TEST(RemoteUdpSessionTest, IdleWatchdogDisabledWhenIdleTimeoutZero)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::config::timeout_t timeout_cfg;
    timeout_cfg.idle = 0;
    auto session = make_session(io_context, conn, 231, timeout_cfg);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));
    session->last_activity_time_ms_.store(0, std::memory_order_release);

    mux::test::run_awaitable_void(io_context, session->idle_watchdog());
    EXPECT_TRUE(session->udp_socket_.is_open());
    session->close_socket();
}

TEST(RemoteUdpSessionTest, IdleWatchdogStopsWhenIdleTimedOut)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    auto session = make_session(io_context, conn, 24);
    ASSERT_TRUE(mux::test::run_awaitable(io_context, session->setup_udp_socket(conn)));
    session->last_activity_time_ms_.store(0, std::memory_order_release);

    mux::test::run_awaitable_void(io_context, session->idle_watchdog());
}

}    // namespace
