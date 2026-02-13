#include <thread>
#include <chrono>
#include <memory>
#include <vector>
#include <array>
#include <cstdint>
#include <system_error>
#include <atomic>
#include <cerrno>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include "protocol.h"
#include "mux_stream.h"
#include "mux_codec.h"
#include "mux_protocol.h"
#include "test_util.h"
#define private public
#include "mux_connection.h"
#include "mux_tunnel.h"
#include "udp_socks_session.h"
#undef private
#include "mock_mux_connection.h"

extern "C"
{
#include <openssl/evp.h>
}

namespace
{

std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};
std::atomic<bool> g_fail_bind_once{false};
std::atomic<int> g_fail_bind_errno{EADDRINUSE};

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

void fail_next_bind(const int err)
{
    g_fail_bind_errno.store(err, std::memory_order_release);
    g_fail_bind_once.store(true, std::memory_order_release);
}

extern "C" int __real_close(int fd);
extern "C" int __real_bind(int sockfd, const sockaddr* addr, socklen_t addrlen);

extern "C" int __wrap_close(int fd)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);
}

extern "C" int __wrap_bind(int sockfd, const sockaddr* addr, socklen_t addrlen)
{
    if (g_fail_bind_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_bind_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_bind(sockfd, addr, addrlen);
}

struct tcp_socket_pair
{
    asio::ip::tcp::socket client;
    asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(asio::io_context& ctx)
{
    asio::ip::tcp::acceptor acceptor(ctx, {asio::ip::tcp::v4(), 0});
    asio::ip::tcp::socket client(ctx);
    asio::ip::tcp::socket server(ctx);

    std::error_code ec;
    client.connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        return tcp_socket_pair{asio::ip::tcp::socket(ctx), asio::ip::tcp::socket(ctx)};
    }
    acceptor.accept(server, ec);
    if (ec)
    {
        return tcp_socket_pair{asio::ip::tcp::socket(ctx), asio::ip::tcp::socket(ctx)};
    }
    return tcp_socket_pair{std::move(client), std::move(server)};
}

std::shared_ptr<mux::mux_tunnel_impl<asio::ip::tcp::socket>> make_test_tunnel(asio::io_context& io_context,
                                                                                const std::uint32_t conn_id = 100)
{
    return std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

}    // namespace

TEST(UdpSocksSessionTest, PrepareUdpAssociateFailureBranches)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;

    auto session_with_closed_tcp =
        std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 1, timeout_cfg);

    bool done = false;
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::address local_addr;
            std::uint16_t udp_bind_port = 0;
            const auto stream = co_await session_with_closed_tcp->prepare_udp_associate(local_addr, udp_bind_port);
            EXPECT_EQ(stream, nullptr);
            done = true;
            co_return;
        },
        asio::detached);
    ctx.run();
    EXPECT_TRUE(done);

    ctx.restart();
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.server.is_open());

    auto session_without_tunnel =
        std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 2, timeout_cfg);

    done = false;
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::address local_addr;
            std::uint16_t udp_bind_port = 0;
            const auto stream = co_await session_without_tunnel->prepare_udp_associate(local_addr, udp_bind_port);
            EXPECT_EQ(stream, nullptr);
            done = true;
            co_return;
        },
        asio::detached);
    ctx.run();
    EXPECT_TRUE(done);
}

TEST(UdpSocksSessionTest, ShouldStopStreamToUdpCoversExpectedAndUnexpectedErrors)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 30, timeout_cfg);

    EXPECT_FALSE(session->should_stop_stream_to_udp(std::error_code{}, std::vector<std::uint8_t>{0x01}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(asio::experimental::error::channel_closed, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(asio::experimental::error::channel_cancelled, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(asio::error::operation_aborted, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(asio::error::connection_reset, {}));
}

TEST(UdpSocksSessionTest, ForwardAndReceiveStopBranches)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 3, timeout_cfg);

    EXPECT_TRUE(session->should_stop_stream_to_udp(asio::error::connection_reset, {}));

    bool returned = false;
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            co_await session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x01, 0x02});
            returned = true;
            co_return;
        },
        asio::detached);
    ctx.run();
    EXPECT_TRUE(returned);
}

TEST(UdpSocksSessionTest, StreamToUdpSockForwardsDataToTrackedEndpoint)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 31, timeout_cfg);

    std::error_code ec;
    session->udp_socket_.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    asio::ip::udp::socket recv_socket(ctx);
    recv_socket.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    recv_socket.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    recv_socket.non_blocking(true, ec);
    ASSERT_FALSE(ec);

    session->has_client_ep_ = true;
    session->client_ep_ = recv_socket.local_endpoint(ec);
    ASSERT_FALSE(ec);
    ASSERT_NE(session->client_ep_.port(), 0);

    session->on_data({0x51, 0x52, 0x53});
    asio::steady_timer stop_timer(ctx);
    stop_timer.expires_after(std::chrono::milliseconds(30));
    stop_timer.async_wait([session](const std::error_code&) { session->on_close(); });

    mux::test::run_awaitable_void(ctx, session->stream_to_udp_sock(nullptr));

    std::array<std::uint8_t, 8> recv_buf = {0};
    asio::ip::udp::endpoint sender;
    const auto recv_n = recv_socket.receive_from(asio::buffer(recv_buf), sender, 0, ec);
    EXPECT_FALSE(ec);
    ASSERT_EQ(recv_n, 3U);
    EXPECT_EQ(recv_buf[0], 0x51);
    EXPECT_EQ(recv_buf[1], 0x52);
    EXPECT_EQ(recv_buf[2], 0x53);
}

TEST(UdpSocksSessionTest, ForwardStreamDataToClientHandlesZeroPortAndSendError)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 32, timeout_cfg);

    session->has_client_ep_ = true;
    session->client_ep_ = {asio::ip::make_address("127.0.0.1"), 0};
    mux::test::run_awaitable_void(ctx, session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x01}));

    session->client_ep_ = {asio::ip::make_address("127.0.0.1"), 5353};
    mux::test::run_awaitable_void(ctx, session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x02}));
}

TEST(UdpSocksSessionTest, UdpSockToStreamValidationBranches)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 4, timeout_cfg);

    std::error_code ec;
    session->udp_socket_.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    const auto recv_ep = session->udp_socket_.local_endpoint(ec);
    ASSERT_FALSE(ec);

    auto conn = std::make_shared<mux::mock_mux_connection>(ctx);
    EXPECT_CALL(*conn, mock_send_async(1, mux::kCmdDat, testing::_))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(testing::Return(std::error_code{}));

    auto stream = std::make_shared<mux::mux_stream>(1, 1, "trace", conn, ctx);
    asio::co_spawn(
        ctx,
        [session, stream]() -> asio::awaitable<void>
        {
            co_await session->udp_sock_to_stream(stream);
            co_return;
        },
        asio::detached);

    std::thread runner([&ctx]() { ctx.run(); });

    asio::io_context send_ctx;
    asio::ip::udp::socket sender1(send_ctx);
    asio::ip::udp::socket sender2(send_ctx);
    sender1.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender2.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender1.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    sender2.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    auto send_packet = [&](asio::ip::udp::socket& sender, const std::vector<std::uint8_t>& data)
    {
        sender.send_to(asio::buffer(data), recv_ep, 0, ec);
        ASSERT_FALSE(ec);
    };

    send_packet(sender1, {0x00, 0x01});

    socks_udp_header frag_header;
    frag_header.frag = 0x01;
    frag_header.addr = "1.1.1.1";
    frag_header.port = 53;
    auto frag_packet = socks_codec::encode_udp_header(frag_header);
    frag_packet.push_back(0x11);
    send_packet(sender1, frag_packet);

    socks_udp_header huge_header;
    huge_header.frag = 0x00;
    huge_header.addr = "1.1.1.1";
    huge_header.port = 53;
    auto huge_packet = socks_codec::encode_udp_header(huge_header);
    huge_packet.resize(mux::kMaxPayload + 1, 0x22);
    send_packet(sender1, huge_packet);

    socks_udp_header valid_header;
    valid_header.frag = 0x00;
    valid_header.addr = "1.1.1.1";
    valid_header.port = 53;
    auto valid_packet = socks_codec::encode_udp_header(valid_header);
    valid_packet.push_back(0x33);
    send_packet(sender1, valid_packet);
    send_packet(sender1, valid_packet);
    send_packet(sender2, valid_packet);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    session->on_close();

    if (runner.joinable())
    {
        runner.join();
    }

    EXPECT_TRUE(session->has_client_ep_);
    EXPECT_NE(session->client_ep_.port(), 0);
}

TEST(UdpSocksSessionTest, KeepTcpAliveCoversExpectedErrorCodes)
{
    mux::config::timeout_t timeout_cfg;

    {
        asio::io_context ctx;
        auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 33, timeout_cfg);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());

        std::error_code ec;
        session->socket_.open(asio::ip::tcp::v4(), ec);
        ASSERT_FALSE(ec);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }

    {
        asio::io_context ctx;
        auto pair = make_tcp_socket_pair(ctx);
        ASSERT_TRUE(pair.client.is_open());
        ASSERT_TRUE(pair.server.is_open());
        auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 34, timeout_cfg);

        std::error_code ec;
        pair.client.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        ASSERT_FALSE(ec);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }

    {
        asio::io_context ctx;
        auto pair = make_tcp_socket_pair(ctx);
        ASSERT_TRUE(pair.server.is_open());
        auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 35, timeout_cfg);
        asio::steady_timer timer(ctx);
        timer.expires_after(std::chrono::milliseconds(10));
        timer.async_wait([session](const std::error_code&)
                         {
                             std::error_code close_ec;
                             session->socket_.close(close_ec);
                         });
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateIPv6PathBranches)
{
    const auto rep = mux::detail::build_udp_associate_reply(asio::ip::make_address("::1"), 5353);
    ASSERT_GE(rep.size(), 4U + 16U + 2U);
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);
    EXPECT_EQ(rep[3], socks::kAtypIpv6);
    EXPECT_EQ(rep[rep.size() - 2], static_cast<std::uint8_t>((5353 >> 8) & 0xFF));
    EXPECT_EQ(rep[rep.size() - 1], static_cast<std::uint8_t>(5353 & 0xFF));
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesBindFailureAndStartPath)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 36, timeout_cfg);
    fail_next_bind(EADDRINUSE);

    asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, StartSpawnsRunAndWritesHostUnreachWhenTunnelUnavailable)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 37, timeout_cfg);
    session->start("ignored.example", 1234);
    ctx.run();

    std::uint8_t err[10] = {0};
    asio::read(pair.client, asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
}

TEST(UdpSocksSessionTest, PrepareAndFinalizeUdpAssociateSuccess)
{
    mux::config::timeout_t timeout_cfg;
    asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 201);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(201));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(std::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).WillOnce(testing::Return(std::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillOnce([&ctx](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> iface)
                  {
                      auto stream = std::dynamic_pointer_cast<mux::mux_stream>(iface);
                      ASSERT_NE(stream, nullptr);
                      mux::ack_payload ack{};
                      ack.socks_rep = socks::kRepSuccess;
                      std::vector<std::uint8_t> ack_data;
                      mux::mux_codec::encode_ack(ack, ack_data);
                      asio::post(ctx, [stream, ack_data]() { stream->on_data(ack_data); });
                  });
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{}))
        .WillOnce(testing::Return(std::error_code{}));

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 38, timeout_cfg);
    asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    ASSERT_NE(stream, nullptr);
    EXPECT_NE(udp_bind_port, 0);
    mux::test::run_awaitable_void(ctx, session->finalize_udp_associate(stream));

    std::uint8_t rep[10] = {0};
    asio::read(pair.client, asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);
}

TEST(UdpSocksSessionTest, CloseImplLogsCloseFailureBranch)
{
    asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(asio::ip::tcp::socket(ctx), ctx, nullptr, 5, timeout_cfg);

    std::error_code ec;
    session->udp_socket_.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    fail_next_close(EIO);
    session->close_impl();

    session->close_impl();
}
