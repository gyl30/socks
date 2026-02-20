
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <gtest/gtest.h>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <asm-generic/socket.h>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <gmock/gmock-actions.h>
#include <gmock/gmock-matchers.h>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <gmock/gmock-spec-builders.h>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_stream_interface.h"

#define private public
#include "remote_session.h"

#undef private

#include "protocol.h"
#include "mux_codec.h"
#include "test_util.h"
#include "statistics.h"
#include "mock_mux_connection.h"

std::atomic<bool> g_fail_tcp_nodelay_setsockopt_once{false};
std::atomic<int> g_fail_tcp_nodelay_setsockopt_errno{EPERM};

void fail_next_tcp_nodelay_setsockopt(const int err)
{
    g_fail_tcp_nodelay_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_tcp_nodelay_setsockopt_once.store(true, std::memory_order_release);
}

extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == IPPROTO_TCP && optname == TCP_NODELAY && g_fail_tcp_nodelay_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_tcp_nodelay_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

namespace
{

using ::testing::_;

class noop_stream : public mux::mux_stream_interface
{
   public:
    void on_data(std::vector<std::uint8_t>) override {}
    void on_close() override {}
    void on_reset() override {}
};

struct tcp_socket_pair
{
    boost::asio::ip::tcp::socket client;
    boost::asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(boost::asio::io_context& io_context)
{
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    if (!mux::test::open_ephemeral_tcp_acceptor(acceptor))
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    boost::asio::ip::tcp::socket client(io_context);
    boost::asio::ip::tcp::socket server(io_context);
    boost::system::error_code ec;
    client.connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    acceptor.accept(server, ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(io_context), .server = boost::asio::ip::tcp::socket(io_context)};
    }
    return tcp_socket_pair{.client = std::move(client), .server = std::move(server)};
}

mux::syn_payload make_syn(const std::string& host, const std::uint16_t port)
{
    mux::syn_payload syn{};
    syn.socks_cmd = socks::kCmdConnect;
    syn.addr = host;
    syn.port = port;
    syn.trace_id = "trace-remote";
    return syn;
}

std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> make_manager(boost::asio::io_context& io_context,
                                                                                 const std::uint32_t conn_id = 301)
{
    return std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

TEST(RemoteSessionTest, StartReturnsWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 7, io_context, ctx);
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->start(make_syn("127.0.0.1", 80)));
    SUCCEED();
}

TEST(RemoteSessionTest, StartRemovesManagerStreamWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 8, io_context, ctx);

    auto manager = make_manager(io_context, 450);
    manager->connection()->register_stream(8, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(8));
    session->set_manager(manager);

    conn.reset();

    mux::test::run_awaitable_void(io_context, session->start(make_syn("127.0.0.1", 80)));
    EXPECT_FALSE(manager->connection()->has_stream(8));
}

TEST(RemoteSessionTest, RunResolveFailureSendsHostUnreachAckAndReset)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 9, io_context, ctx);
    auto& stats = mux::statistics::instance();
    const auto resolve_errors_before = stats.remote_session_resolve_errors();
    const auto resolve_timeouts_before = stats.remote_session_resolve_timeouts();

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(9, mux::kCmdAck, _))
        .WillOnce(
            [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                ack_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(9, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepHostUnreach);
    const bool resolve_failed_or_timed_out = stats.remote_session_resolve_errors() >= resolve_errors_before + 1 ||
                                             stats.remote_session_resolve_timeouts() >= resolve_timeouts_before + 1;
    EXPECT_TRUE(resolve_failed_or_timed_out);
}

TEST(RemoteSessionTest, RunResolveFailureRemovesManagerStream)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 10, io_context, ctx);

    auto manager = make_manager(io_context, 302);
    manager->connection()->register_stream(10, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(10));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(10, mux::kCmdAck, _)).WillOnce(::testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*conn, mock_send_async(10, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));
    EXPECT_FALSE(manager->connection()->has_stream(10));
}

TEST(RemoteSessionTest, RunResolveFailureAckSendErrorStillResetsAndRemovesManagerStream)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 12, io_context, ctx);

    auto manager = make_manager(io_context, 303);
    manager->connection()->register_stream(12, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(12));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdAck, _)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));
    EXPECT_FALSE(manager->connection()->has_stream(12));
}

TEST(RemoteSessionTest, RunConnectFailureSendsConnRefusedAckAndReset)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 11, io_context, ctx);
    auto& stats = mux::statistics::instance();
    const auto connect_errors_before = stats.remote_session_connect_errors();

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    const std::uint16_t closed_port = acceptor.local_endpoint().port();
    acceptor.close();

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdAck, _))
        .WillOnce(
            [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                ack_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", closed_port)));

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepConnRefused);
    EXPECT_GE(stats.remote_session_connect_errors(), connect_errors_before + 1);
}

TEST(RemoteSessionTest, RunConnectTimeoutSendsConnRefusedAckAndReset)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 35, io_context, ctx, 1);
    auto& stats = mux::statistics::instance();
    const auto connect_timeouts_before = stats.remote_session_connect_timeouts();

    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor saturated_acceptor(io_context);
    ec = saturated_acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.listen(1, ec);
    ASSERT_FALSE(ec);

    const auto target_port = saturated_acceptor.local_endpoint().port();
    boost::asio::ip::tcp::socket queued_client_a(io_context);
    queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(io_context);
    queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(35, mux::kCmdAck, _))
        .WillOnce(
            [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                ack_payload = payload;
                return boost::system::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(35, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));

    const auto start = std::chrono::steady_clock::now();
    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", target_port)));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepConnRefused);
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);
    EXPECT_GE(stats.remote_session_connect_timeouts(), connect_timeouts_before + 1);

    boost::system::error_code close_ec;
    queued_client_a.close(close_ec);
    queued_client_b.close(close_ec);
    saturated_acceptor.close(close_ec);
}

TEST(RemoteSessionTest, RunAckSendFailureReturnsWithoutReset)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 13, io_context, ctx);

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    EXPECT_CALL(*conn, mock_send_async(13, mux::kCmdAck, _)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
    EXPECT_CALL(*conn, mock_send_async(13, mux::kCmdRst, _)).Times(0);

    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", acceptor.local_endpoint().port())));
    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, RunSkipsHandshakeWhenResetAlreadyRequested)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 34, io_context, ctx);

    session->on_reset();

    EXPECT_CALL(*conn, mock_send_async(_, _, _)).Times(0);
    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));
}

TEST(RemoteSessionTest, RunSuccessWhenSetNoDelayFailsStillSendsAckAndFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 29, io_context, ctx);
    session->recv_channel_.close();

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    const std::uint16_t port = acceptor.local_endpoint().port();
    std::thread accept_thread(
        [&io_context, &acceptor]()
        {
            boost::asio::ip::tcp::socket accepted(io_context);
            boost::system::error_code ec;
            acceptor.accept(accepted, ec);
            if (!ec)
            {
                accepted.close(ec);
            }
        });

    std::vector<std::uint8_t> ack_payload;
    {
        ::testing::InSequence const seq;
        EXPECT_CALL(*conn, mock_send_async(29, mux::kCmdAck, _))
            .WillOnce(
                [&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
                {
                    ack_payload = payload;
                    return boost::system::error_code{};
                });
        EXPECT_CALL(*conn, mock_send_async(29, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    }
    fail_next_tcp_nodelay_setsockopt(EPERM);

    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", port)));

    if (accept_thread.joinable())
    {
        accept_thread.join();
    }

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepSuccess);
}

TEST(RemoteSessionTest, UpstreamWritesPayloadAndStopsOnEmptyFrame)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 15, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x11, 0x22});
    session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{});

    mux::test::run_awaitable_void(io_context, session->upstream());

    std::uint8_t recv_buf[2] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(recv_buf));
    EXPECT_EQ(recv_buf[0], 0x11);
    EXPECT_EQ(recv_buf[1], 0x22);
}

TEST(RemoteSessionTest, UpstreamStopsWhenChannelClosed)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 16, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    session->recv_channel_.close();

    mux::test::run_awaitable_void(io_context, session->upstream());
}

TEST(RemoteSessionTest, UpstreamStopsWhenWriteToTargetFails)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 26, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    boost::system::error_code ec;
    session->target_socket_.close(ec);
    ASSERT_FALSE(ec);

    session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x33});
    mux::test::run_awaitable_void(io_context, session->upstream());
}

TEST(RemoteSessionTest, DownstreamSendsDataAndFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 17, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    const std::vector<std::uint8_t> payload = {0xA1, 0xB2, 0xC3};
    boost::asio::write(pair.client, boost::asio::buffer(payload));
    pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send);

    {
        ::testing::InSequence const seq;
        EXPECT_CALL(*conn, mock_send_async(17, mux::kCmdDat, payload)).WillOnce(::testing::Return(boost::system::error_code{}));
        EXPECT_CALL(*conn, mock_send_async(17, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    }

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenMuxSendFailsStillFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 18, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    const std::vector<std::uint8_t> payload = {0xCA, 0xFE};
    boost::asio::write(pair.client, boost::asio::buffer(payload));

    {
        ::testing::InSequence const seq;
        EXPECT_CALL(*conn, mock_send_async(18, mux::kCmdDat, payload)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
        EXPECT_CALL(*conn, mock_send_async(18, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    }

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamMuxSendFailureUnblocksUpstreamLoop)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 38, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    const std::vector<std::uint8_t> payload = {0xDE, 0xAD};
    boost::asio::write(pair.client, boost::asio::buffer(payload));

    {
        ::testing::InSequence const seq;
        EXPECT_CALL(*conn, mock_send_async(38, mux::kCmdDat, payload)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));
        EXPECT_CALL(*conn, mock_send_async(38, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    }

    auto future = std::async(std::launch::async,
                             [&io_context, session]()
                             {
                                 mux::test::run_awaitable_void(io_context,
                                                               [session]() -> boost::asio::awaitable<void>
                                                               {
                                                                   using boost::asio::experimental::awaitable_operators::operator&&;
                                                                   co_await (session->upstream() && session->downstream());
                                                               }());
                             });

    const bool completed = future.wait_for(std::chrono::milliseconds(500)) == std::future_status::ready;
    if (!completed)
    {
        session->recv_channel_.close();
        boost::system::error_code close_ec;
        session->target_socket_.close(close_ec);
        pair.client.close(close_ec);
    }

    future.wait();
    EXPECT_TRUE(completed);
}

TEST(RemoteSessionTest, DownstreamStopsWhenConnectionExpired)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 19, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    boost::asio::write(pair.client, boost::asio::buffer(std::vector<std::uint8_t>{0x01, 0x02}));
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadFailsStillSendsFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 27, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    boost::system::error_code ec;
    session->target_socket_.close(ec);
    ASSERT_FALSE(ec);

    EXPECT_CALL(*conn, mock_send_async(27, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadOperationAbortedStillSendsFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 28, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    boost::asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait(
        [session](const boost::system::error_code&)
        {
            boost::system::error_code ec;
            session->target_socket_.cancel(ec);
        });

    EXPECT_CALL(*conn, mock_send_async(28, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadConnectionResetStillSendsFin)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 30, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    linger linger_opt{};
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    ASSERT_EQ(::setsockopt(pair.client.native_handle(), SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)), 0);

    boost::system::error_code ec;
    pair.client.close(ec);
    ASSERT_FALSE(ec);

    EXPECT_CALL(*conn, mock_send_async(30, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(boost::system::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamSkipsFinWhenResetRequested)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 36, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    session->on_reset();
    EXPECT_FALSE(session->target_socket_.is_open());

    EXPECT_CALL(*conn, mock_send_async(36, mux::kCmdFin, std::vector<std::uint8_t>{})).Times(0);
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, OnDataDispatchEnqueuesFrame)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 20, io_context, ctx);

    session->on_data({0x55});
    const auto [ec, data] =
        mux::test::run_awaitable(io_context, session->recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)));
    EXPECT_FALSE(ec);
    ASSERT_EQ(data.size(), 1U);
    EXPECT_EQ(data[0], 0x55);
}

TEST(RemoteSessionTest, OnDataRunsCleanupWhenIoContextStopped)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 32, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    session->recv_channel_.close();
    io_context.stop();

    session->on_data({0x55});
    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, OnDataRunsCleanupWhenIoContextNotRunning)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 33, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    session->recv_channel_.close();
    session->on_data({0x55});
    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, OnDataRunsCleanupWhenIoQueueBlocked)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 31, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    session->recv_channel_.close();

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

    session->on_data({0x55});
    EXPECT_FALSE(session->target_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    io_context.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(RemoteSessionTest, OnCloseAndOnResetDispatchCleanup)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 21, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    session->on_close();
    io_context.run();
    io_context.restart();

    session->on_reset();
    io_context.run();
    io_context.restart();

    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, OnResetRemovesManagerStreamEvenBeforeRun)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 39, io_context, ctx);

    auto manager = make_manager(io_context, 451);
    manager->connection()->register_stream(39, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(39));
    session->set_manager(manager);

    session->on_reset();
    io_context.run();
    io_context.restart();

    EXPECT_FALSE(manager->connection()->has_stream(39));
}

TEST(RemoteSessionTest, OnCloseAndOnResetRunInlineWhenIoContextStopped)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 22, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    io_context.stop();
    session->on_close();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));

    session->on_reset();
    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, OnCloseAndOnResetRunWhenIoContextNotRunning)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 23, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

    session->on_close();
    EXPECT_FALSE(session->recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));

    session->on_reset();
    EXPECT_FALSE(session->target_socket_.is_open());
}

TEST(RemoteSessionTest, OnCloseAndOnResetRunWhenIoQueueBlocked)
{
    boost::asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context const ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 24, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    ASSERT_TRUE(session->target_socket_.is_open());

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

    session->on_reset();
    EXPECT_FALSE(session->target_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    io_context.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

}    // namespace
