#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <utility>
#include <thread>
#include <system_error>
#include <cerrno>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>
#include <sys/socket.h>
#include <netinet/tcp.h>

extern "C"
{
#include <openssl/evp.h>
}

#define private public
#include "remote_session.h"
#undef private

#include "mux_codec.h"
#include "protocol.h"
#include "test_util.h"
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
    if (level == IPPROTO_TCP && optname == TCP_NODELAY &&
        g_fail_tcp_nodelay_setsockopt_once.exchange(false, std::memory_order_acq_rel))
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
    asio::ip::tcp::socket client;
    asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(asio::io_context& io_context)
{
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket client(io_context);
    asio::ip::tcp::socket server(io_context);
    client.connect(acceptor.local_endpoint());
    acceptor.accept(server);
    return tcp_socket_pair{std::move(client), std::move(server)};
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

std::shared_ptr<mux::mux_tunnel_impl<asio::ip::tcp::socket>> make_manager(asio::io_context& io_context,
                                                                            const std::uint32_t conn_id = 301)
{
    return std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

TEST(RemoteSessionTest, StartReturnsWhenConnectionExpired)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 7, io_context, ctx);
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->start(make_syn("127.0.0.1", 80)));
    SUCCEED();
}

TEST(RemoteSessionTest, RunResolveFailureSendsHostUnreachAckAndReset)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 9, io_context, ctx);

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(9, mux::kCmdAck, _))
        .WillOnce([&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
                  {
                      ack_payload = payload;
                      return std::error_code{};
                  });
    EXPECT_CALL(*conn, mock_send_async(9, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepHostUnreach);
}

TEST(RemoteSessionTest, RunResolveFailureRemovesManagerStream)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 10, io_context, ctx);

    auto manager = make_manager(io_context, 302);
    manager->connection()->register_stream(10, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(10));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(10, mux::kCmdAck, _)).WillOnce(::testing::Return(std::error_code{}));
    EXPECT_CALL(*conn, mock_send_async(10, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));
    EXPECT_FALSE(manager->connection()->has_stream(10));
}

TEST(RemoteSessionTest, RunResolveFailureAckSendErrorStillResetsAndRemovesManagerStream)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 12, io_context, ctx);

    auto manager = make_manager(io_context, 303);
    manager->connection()->register_stream(12, std::make_shared<noop_stream>());
    ASSERT_TRUE(manager->connection()->has_stream(12));
    session->set_manager(manager);

    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdAck, _)).WillOnce(::testing::Return(asio::error::broken_pipe));
    EXPECT_CALL(*conn, mock_send_async(12, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("non-existent.invalid", 443)));
    EXPECT_FALSE(manager->connection()->has_stream(12));
}

TEST(RemoteSessionTest, RunConnectFailureSendsConnRefusedAckAndReset)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 11, io_context, ctx);

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const std::uint16_t closed_port = acceptor.local_endpoint().port();
    acceptor.close();

    std::vector<std::uint8_t> ack_payload;
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdAck, _))
        .WillOnce([&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
                  {
                      ack_payload = payload;
                      return std::error_code{};
                  });
    EXPECT_CALL(*conn, mock_send_async(11, mux::kCmdRst, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));

    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", closed_port)));

    mux::ack_payload ack{};
    ASSERT_TRUE(mux::mux_codec::decode_ack(ack_payload.data(), ack_payload.size(), ack));
    EXPECT_EQ(ack.socks_rep, socks::kRepConnRefused);
}

TEST(RemoteSessionTest, RunAckSendFailureReturnsWithoutReset)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 13, io_context, ctx);

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    EXPECT_CALL(*conn, mock_send_async(13, mux::kCmdAck, _)).WillOnce(::testing::Return(asio::error::broken_pipe));
    EXPECT_CALL(*conn, mock_send_async(13, mux::kCmdRst, _)).Times(0);

    mux::test::run_awaitable_void(io_context, session->run(make_syn("127.0.0.1", acceptor.local_endpoint().port())));
}

TEST(RemoteSessionTest, RunSuccessWhenSetNoDelayFailsStillSendsAckAndFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 29, io_context, ctx);
    session->recv_channel_.close();

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const std::uint16_t port = acceptor.local_endpoint().port();
    std::thread accept_thread(
        [&io_context, &acceptor]()
        {
            asio::ip::tcp::socket accepted(io_context);
            std::error_code ec;
            acceptor.accept(accepted, ec);
            if (!ec)
            {
                accepted.close(ec);
            }
        });

    std::vector<std::uint8_t> ack_payload;
    {
        ::testing::InSequence seq;
        EXPECT_CALL(*conn, mock_send_async(29, mux::kCmdAck, _))
            .WillOnce([&ack_payload](const std::uint32_t, const std::uint8_t, const std::vector<std::uint8_t>& payload)
                      {
                          ack_payload = payload;
                          return std::error_code{};
                      });
        EXPECT_CALL(*conn, mock_send_async(29, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
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
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 15, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    session->recv_channel_.try_send(std::error_code{}, std::vector<std::uint8_t>{0x11, 0x22});
    session->recv_channel_.try_send(std::error_code{}, std::vector<std::uint8_t>{});

    mux::test::run_awaitable_void(io_context, session->upstream());

    std::uint8_t recv_buf[2] = {0};
    asio::read(pair.client, asio::buffer(recv_buf));
    EXPECT_EQ(recv_buf[0], 0x11);
    EXPECT_EQ(recv_buf[1], 0x22);
}

TEST(RemoteSessionTest, UpstreamStopsWhenChannelClosed)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 16, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    session->recv_channel_.close();

    mux::test::run_awaitable_void(io_context, session->upstream());
}

TEST(RemoteSessionTest, UpstreamStopsWhenWriteToTargetFails)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 26, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    std::error_code ec;
    session->target_socket_.close(ec);
    ASSERT_FALSE(ec);

    session->recv_channel_.try_send(std::error_code{}, std::vector<std::uint8_t>{0x33});
    mux::test::run_awaitable_void(io_context, session->upstream());
}

TEST(RemoteSessionTest, DownstreamSendsDataAndFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 17, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    const std::vector<std::uint8_t> payload = {0xA1, 0xB2, 0xC3};
    asio::write(pair.client, asio::buffer(payload));
    pair.client.shutdown(asio::ip::tcp::socket::shutdown_send);

    {
        ::testing::InSequence seq;
        EXPECT_CALL(*conn, mock_send_async(17, mux::kCmdDat, payload)).WillOnce(::testing::Return(std::error_code{}));
        EXPECT_CALL(*conn, mock_send_async(17, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
    }

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenMuxSendFailsStillFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 18, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    const std::vector<std::uint8_t> payload = {0xCA, 0xFE};
    asio::write(pair.client, asio::buffer(payload));

    {
        ::testing::InSequence seq;
        EXPECT_CALL(*conn, mock_send_async(18, mux::kCmdDat, payload)).WillOnce(::testing::Return(asio::error::broken_pipe));
        EXPECT_CALL(*conn, mock_send_async(18, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
    }

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenConnectionExpired)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 19, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    asio::write(pair.client, asio::buffer(std::vector<std::uint8_t>{0x01, 0x02}));
    conn.reset();

    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadFailsStillSendsFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 27, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);
    std::error_code ec;
    session->target_socket_.close(ec);
    ASSERT_FALSE(ec);

    EXPECT_CALL(*conn, mock_send_async(27, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadOperationAbortedStillSendsFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 28, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    asio::steady_timer cancel_timer(io_context);
    cancel_timer.expires_after(std::chrono::milliseconds(10));
    cancel_timer.async_wait([session](const std::error_code&)
                            {
                                std::error_code ec;
                                session->target_socket_.cancel(ec);
                            });

    EXPECT_CALL(*conn, mock_send_async(28, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, DownstreamStopsWhenTargetReadConnectionResetStillSendsFin)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 30, io_context, ctx);

    auto pair = make_tcp_socket_pair(io_context);
    session->target_socket_ = std::move(pair.server);

    linger linger_opt{};
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    ASSERT_EQ(::setsockopt(pair.client.native_handle(), SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt)), 0);

    std::error_code ec;
    pair.client.close(ec);
    ASSERT_FALSE(ec);

    EXPECT_CALL(*conn, mock_send_async(30, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(::testing::Return(std::error_code{}));
    mux::test::run_awaitable_void(io_context, session->downstream());
}

TEST(RemoteSessionTest, OnDataDispatchEnqueuesFrame)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
    auto session = std::make_shared<mux::remote_session>(conn, 20, io_context, ctx);

    session->on_data({0x55});
    const auto [ec, data] = mux::test::run_awaitable(io_context, session->recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable)));
    EXPECT_FALSE(ec);
    ASSERT_EQ(data.size(), 1U);
    EXPECT_EQ(data[0], 0x55);
}

TEST(RemoteSessionTest, OnCloseAndOnResetDispatchCleanup)
{
    asio::io_context io_context;
    auto conn = std::make_shared<mux::mock_mux_connection>(io_context);
    mux::connection_context ctx;
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

}    // namespace
