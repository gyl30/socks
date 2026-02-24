
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "protocol.h"
#include "mux_codec.h"
#include "test_util.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "reality_core.h"

#define private public
#include "mux_tunnel.h"
#include "mux_connection.h"
#include "udp_socks_session.h"

#undef private
extern "C"
{
#include <openssl/evp.h>
}

#include "mock_mux_connection.h"

namespace
{

std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};
std::atomic<bool> g_fail_bind_once{false};
std::atomic<int> g_fail_bind_errno{EADDRINUSE};
std::atomic<bool> g_fail_setsockopt_once{false};
std::atomic<int> g_fail_setsockopt_level{-1};
std::atomic<int> g_fail_setsockopt_optname{-1};
std::atomic<int> g_fail_setsockopt_errno{EPERM};
std::atomic<bool> g_mock_getsockname_ipv6_any_once{false};
std::atomic<int> g_fail_getsockname_on_call{0};
std::atomic<int> g_fail_getsockname_errno{ENOTSOCK};
std::atomic<int> g_getsockname_call_count{0};

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

void fail_next_setsockopt(const int level, const int optname, const int err)
{
    g_fail_setsockopt_level.store(level, std::memory_order_release);
    g_fail_setsockopt_optname.store(optname, std::memory_order_release);
    g_fail_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_setsockopt_once.store(true, std::memory_order_release);
}

void fail_getsockname_on_call(const int nth_call, const int err)
{
    g_getsockname_call_count.store(0, std::memory_order_release);
    g_fail_getsockname_errno.store(err, std::memory_order_release);
    g_fail_getsockname_on_call.store(nth_call, std::memory_order_release);
}

void mock_next_getsockname_ipv6_any() { g_mock_getsockname_ipv6_any_once.store(true, std::memory_order_release); }

extern "C" int __real_close(int fd);                                                                           
extern "C" int __real_bind(int sockfd, const sockaddr* addr, socklen_t addrlen);                               
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);    
extern "C" int __real_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen);                             

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

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)    
{
    if (g_fail_setsockopt_once.exchange(false, std::memory_order_acq_rel) && level == g_fail_setsockopt_level.load(std::memory_order_acquire))
    {
        const int configured_optname = g_fail_setsockopt_optname.load(std::memory_order_acquire);
        if (configured_optname >= 0 && optname != configured_optname)
        {
            return __real_setsockopt(sockfd, level, optname, optval, optlen);    
        }
        errno = g_fail_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);    
}

extern "C" int __wrap_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen)    
{
    if (g_mock_getsockname_ipv6_any_once.exchange(false, std::memory_order_acq_rel))
    {
        if (addr == nullptr || addrlen == nullptr || *addrlen < sizeof(sockaddr_in6))
        {
            errno = EINVAL;
            return -1;
        }
        sockaddr_in6 mock_addr{};
        mock_addr.sin6_family = AF_INET6;
        mock_addr.sin6_addr = in6addr_any;
        std::memcpy(addr, &mock_addr, sizeof(mock_addr));
        *addrlen = sizeof(mock_addr);
        return 0;
    }

    const int target_call = g_fail_getsockname_on_call.load(std::memory_order_acquire);
    if (target_call > 0)
    {
        const int current_call = g_getsockname_call_count.fetch_add(1, std::memory_order_acq_rel) + 1;
        if (current_call == target_call)
        {
            g_fail_getsockname_on_call.store(0, std::memory_order_release);
            errno = g_fail_getsockname_errno.load(std::memory_order_acquire);
            return -1;
        }
    }
    return __real_getsockname(sockfd, addr, addrlen);    
}

struct tcp_socket_pair
{
    boost::asio::ip::tcp::socket client;
    boost::asio::ip::tcp::socket server;
};

tcp_socket_pair make_tcp_socket_pair(boost::asio::io_context& ctx)
{
    boost::asio::ip::tcp::acceptor acceptor(ctx);
    if (!mux::test::open_ephemeral_tcp_acceptor(acceptor))
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(ctx), .server = boost::asio::ip::tcp::socket(ctx)};
    }
    boost::asio::ip::tcp::socket client(ctx);
    boost::asio::ip::tcp::socket server(ctx);

    boost::system::error_code ec;
    client.connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(ctx), .server = boost::asio::ip::tcp::socket(ctx)};
    }
    acceptor.accept(server, ec);
    if (ec)
    {
        return tcp_socket_pair{.client = boost::asio::ip::tcp::socket(ctx), .server = boost::asio::ip::tcp::socket(ctx)};
    }
    return tcp_socket_pair{.client = std::move(client), .server = std::move(server)};
}

std::shared_ptr<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>> make_test_tunnel(boost::asio::io_context& io_context,
                                                                                     const std::uint32_t conn_id = 100)
{
    return std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context), io_context, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, conn_id);
}

}    // namespace

TEST(UdpSocksSessionTest, PrepareUdpAssociateFailureBranches)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;

    auto session_with_closed_tcp = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 1, timeout_cfg);

    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            boost::asio::ip::address local_addr;
            std::uint16_t udp_bind_port = 0;
            const auto stream = co_await session_with_closed_tcp->prepare_udp_associate(local_addr, udp_bind_port);
            EXPECT_EQ(stream, nullptr);
            done = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    EXPECT_TRUE(done);

    ctx.restart();
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.server.is_open());

    auto session_without_tunnel = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 2, timeout_cfg);

    done = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            boost::asio::ip::address local_addr;
            std::uint16_t udp_bind_port = 0;
            const auto stream = co_await session_without_tunnel->prepare_udp_associate(local_addr, udp_bind_port);
            EXPECT_EQ(stream, nullptr);
            done = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    EXPECT_TRUE(done);
}

TEST(UdpSocksSessionTest, ShouldStopStreamToUdpCoversExpectedAndUnexpectedErrors)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 30, timeout_cfg);

    EXPECT_FALSE(session->should_stop_stream_to_udp(boost::system::error_code{}, std::vector<std::uint8_t>{0x01}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(boost::asio::experimental::error::channel_closed, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(boost::asio::experimental::error::channel_cancelled, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(boost::asio::error::operation_aborted, {}));
    EXPECT_TRUE(session->should_stop_stream_to_udp(boost::asio::error::connection_reset, {}));
}

TEST(UdpSocksSessionTest, ForwardAndReceiveStopBranches)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 3, timeout_cfg);

    EXPECT_TRUE(session->should_stop_stream_to_udp(boost::asio::error::connection_reset, {}));

    bool returned = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            co_await session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x01, 0x02});
            returned = true;
            co_return;
        },
        boost::asio::detached);
    ctx.run();
    EXPECT_TRUE(returned);
}

TEST(UdpSocksSessionTest, StreamToUdpSockForwardsDataToTrackedEndpoint)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 31, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    boost::asio::ip::udp::socket recv_socket(ctx);
    recv_socket.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    recv_socket.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    recv_socket.non_blocking(true, ec);
    ASSERT_FALSE(ec);

    session->has_client_ep_ = true;
    session->client_ep_ = recv_socket.local_endpoint(ec);
    ASSERT_FALSE(ec);
    ASSERT_NE(session->client_ep_.port(), 0);

    session->on_data({0x51, 0x52, 0x53});
    boost::asio::steady_timer stop_timer(ctx);
    stop_timer.expires_after(std::chrono::milliseconds(30));
    stop_timer.async_wait([session](const boost::system::error_code&) { session->on_close(); });

    mux::test::run_awaitable_void(ctx, session->stream_to_udp_sock(nullptr));

    std::array<std::uint8_t, 8> recv_buf = {0};
    boost::asio::ip::udp::endpoint sender;
    const auto recv_n = recv_socket.receive_from(boost::asio::buffer(recv_buf), sender, 0, ec);
    EXPECT_FALSE(ec);
    ASSERT_EQ(recv_n, 3U);
    EXPECT_EQ(recv_buf[0], 0x51);
    EXPECT_EQ(recv_buf[1], 0x52);
    EXPECT_EQ(recv_buf[2], 0x53);
}

TEST(UdpSocksSessionTest, ForwardStreamDataToClientHandlesZeroPortAndSendError)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 32, timeout_cfg);

    session->has_client_ep_ = true;
    session->client_ep_ = {boost::asio::ip::make_address("127.0.0.1"), 0};
    mux::test::run_awaitable_void(ctx, session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x01}));

    session->client_ep_ = {boost::asio::ip::make_address("127.0.0.1"), 5353};
    mux::test::run_awaitable_void(ctx, session->forward_stream_data_to_client(std::vector<std::uint8_t>{0x02}));
}

TEST(UdpSocksSessionTest, UdpSockToStreamValidationBranches)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 4, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    const auto recv_ep = session->udp_socket_.local_endpoint(ec);
    ASSERT_FALSE(ec);

    auto conn = std::make_shared<mux::mock_mux_connection>(ctx);
    EXPECT_CALL(*conn, mock_send_async(1, mux::kCmdDat, testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(boost::system::error_code{}));

    auto stream = std::make_shared<mux::mux_stream>(1, 1, "trace", conn, ctx);
    boost::asio::co_spawn(
        ctx,
        [session, stream]() -> boost::asio::awaitable<void>
        {
            co_await session->udp_sock_to_stream(stream);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&ctx]() { ctx.run(); });

    boost::asio::io_context send_ctx;
    boost::asio::ip::udp::socket sender1(send_ctx);
    boost::asio::ip::udp::socket sender2(send_ctx);
    sender1.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender2.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender1.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    sender2.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    auto send_packet = [&](boost::asio::ip::udp::socket& sender, const std::vector<std::uint8_t>& data)
    {
        sender.send_to(boost::asio::buffer(data), recv_ep, 0, ec);
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

    socks_udp_header empty_host_header;
    empty_host_header.frag = 0x00;
    empty_host_header.addr = "";
    empty_host_header.port = 53;
    auto empty_host_packet = socks_codec::encode_udp_header(empty_host_header);
    empty_host_packet.push_back(0x44);
    send_packet(sender1, empty_host_packet);

    socks_udp_header zero_port_header;
    zero_port_header.frag = 0x00;
    zero_port_header.addr = "1.1.1.1";
    zero_port_header.port = 0;
    auto zero_port_packet = socks_codec::encode_udp_header(zero_port_header);
    zero_port_packet.push_back(0x45);
    send_packet(sender1, zero_port_packet);

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

TEST(UdpSocksSessionTest, UdpSockToStreamDropsMessageSizeAndContinues)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 40, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    const auto recv_ep = session->udp_socket_.local_endpoint(ec);
    ASSERT_FALSE(ec);

    auto conn = std::make_shared<mux::mock_mux_connection>(ctx);
    EXPECT_CALL(*conn, mock_send_async(2, mux::kCmdDat, testing::_))
        .Times(2)
        .WillOnce(testing::Return(boost::asio::error::message_size))
        .WillOnce(testing::Return(boost::system::error_code{}));

    auto stream = std::make_shared<mux::mux_stream>(2, 2, "trace", conn, ctx);
    boost::asio::co_spawn(
        ctx,
        [session, stream]() -> boost::asio::awaitable<void>
        {
            co_await session->udp_sock_to_stream(stream);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&ctx]() { ctx.run(); });

    boost::asio::io_context send_ctx;
    boost::asio::ip::udp::socket sender(send_ctx);
    sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    socks_udp_header header;
    header.frag = 0x00;
    header.addr = "1.1.1.1";
    header.port = 53;

    auto too_large_packet = socks_codec::encode_udp_header(header);
    too_large_packet.resize(mux::kMaxPayloadPerRecord, 0x6a);
    sender.send_to(boost::asio::buffer(too_large_packet), recv_ep, 0, ec);
    ASSERT_FALSE(ec);

    auto valid_packet = socks_codec::encode_udp_header(header);
    valid_packet.push_back(0x33);
    sender.send_to(boost::asio::buffer(valid_packet), recv_ep, 0, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    session->on_close();

    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(UdpSocksSessionTest, UdpSockToStreamRespectsExpectedClientEndpointOnFirstPacket)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 41, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    const auto recv_ep = session->udp_socket_.local_endpoint(ec);
    ASSERT_FALSE(ec);

    boost::asio::io_context send_ctx;
    boost::asio::ip::udp::socket sender_ok(send_ctx);
    boost::asio::ip::udp::socket sender_bad(send_ctx);
    sender_ok.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender_bad.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    sender_ok.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    sender_bad.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    const auto expected_ep = sender_ok.local_endpoint(ec);
    ASSERT_FALSE(ec);
    session->expected_client_addr_ = boost::asio::ip::make_address("127.0.0.1");
    session->expected_client_port_ = expected_ep.port();

    auto conn = std::make_shared<mux::mock_mux_connection>(ctx);
    EXPECT_CALL(*conn, mock_send_async(3, mux::kCmdDat, testing::_)).Times(1).WillOnce(testing::Return(boost::system::error_code{}));
    auto stream = std::make_shared<mux::mux_stream>(3, 3, "trace", conn, ctx);

    boost::asio::co_spawn(
        ctx,
        [session, stream]() -> boost::asio::awaitable<void>
        {
            co_await session->udp_sock_to_stream(stream);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&ctx]() { ctx.run(); });

    socks_udp_header header;
    header.frag = 0x00;
    header.addr = "1.1.1.1";
    header.port = 53;
    auto packet = socks_codec::encode_udp_header(header);
    packet.push_back(0x33);

    sender_bad.send_to(boost::asio::buffer(packet), recv_ep, 0, ec);
    ASSERT_FALSE(ec);
    sender_ok.send_to(boost::asio::buffer(packet), recv_ep, 0, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    session->on_close();

    if (runner.joinable())
    {
        runner.join();
    }

    EXPECT_TRUE(session->has_client_ep_);
    EXPECT_EQ(session->client_ep_.address(), expected_ep.address());
    EXPECT_EQ(session->client_ep_.port(), expected_ep.port());
}

TEST(UdpSocksSessionTest, KeepTcpAliveCoversExpectedErrorCodes)
{
    mux::config::timeout_t const timeout_cfg;

    {
        boost::asio::io_context ctx;
        auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 33, timeout_cfg);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());

        boost::system::error_code ec;
        session->socket_.open(boost::asio::ip::tcp::v4(), ec);
        ASSERT_FALSE(ec);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }

    {
        boost::asio::io_context ctx;
        auto pair = make_tcp_socket_pair(ctx);
        ASSERT_TRUE(pair.client.is_open());
        ASSERT_TRUE(pair.server.is_open());
        auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 34, timeout_cfg);

        boost::system::error_code ec;
        pair.client.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        ASSERT_FALSE(ec);
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }

    {
        boost::asio::io_context ctx;
        auto pair = make_tcp_socket_pair(ctx);
        ASSERT_TRUE(pair.server.is_open());
        auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 35, timeout_cfg);
        boost::asio::steady_timer timer(ctx);
        timer.expires_after(std::chrono::milliseconds(10));
        timer.async_wait(
            [session](const boost::system::error_code&)
            {
                boost::system::error_code close_ec;
                session->socket_.close(close_ec);
            });
        mux::test::run_awaitable_void(ctx, session->keep_tcp_alive());
    }
}

TEST(UdpSocksSessionTest, KeepTcpAliveDoesNotStopWhenTcpDataArrives)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 59, timeout_cfg);
    std::atomic<bool> keepalive_done{false};
    std::atomic<bool> sent_data{false};

    boost::asio::steady_timer send_timer(ctx);
    send_timer.expires_after(std::chrono::milliseconds(20));
    send_timer.async_wait(
        [&pair, &sent_data](const boost::system::error_code&)
        {
            const std::array<std::uint8_t, 1> data = {0x01};
            boost::system::error_code send_ec;
            (void)pair.client.send(boost::asio::buffer(data), 0, send_ec);
            sent_data.store(true, std::memory_order_release);
        });

    boost::asio::steady_timer close_timer(ctx);
    close_timer.expires_after(std::chrono::milliseconds(150));
    close_timer.async_wait(
        [&pair](const boost::system::error_code&)
        {
            boost::system::error_code close_ec;
            pair.client.close(close_ec);
        });

    boost::asio::co_spawn(
        ctx,
        [session, &keepalive_done]() -> boost::asio::awaitable<void>
        {
            co_await session->keep_tcp_alive();
            keepalive_done.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&ctx]() { ctx.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    EXPECT_TRUE(sent_data.load(std::memory_order_acquire));
    EXPECT_FALSE(keepalive_done.load(std::memory_order_acquire));

    std::this_thread::sleep_for(std::chrono::milliseconds(220));
    EXPECT_TRUE(keepalive_done.load(std::memory_order_acquire));

    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateIPv6PathBranches)
{
    const auto rep = mux::detail::build_udp_associate_reply(boost::asio::ip::make_address("::1"), 5353);
    ASSERT_GE(rep.size(), 4U + 16U + 2U);
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);
    EXPECT_EQ(rep[3], socks::kAtypIpv6);
    EXPECT_EQ(rep[rep.size() - 2], static_cast<std::uint8_t>((5353 >> 8) & 0xFF));
    EXPECT_EQ(rep[rep.size() - 1], static_cast<std::uint8_t>(5353 & 0xFF));
}

TEST(UdpSocksSessionTest, IdleWatchdogDisabledWhenIdleTimeoutZero)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t timeout_cfg;
    timeout_cfg.idle = 0;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 37, timeout_cfg);
    session->last_activity_time_ms_.store(0, std::memory_order_release);
    mux::test::run_awaitable_void(ctx, session->idle_watchdog());

    EXPECT_FALSE(session->closed_.load(std::memory_order_acquire));
    EXPECT_TRUE(session->socket_.is_open());

    session->on_close();
    boost::system::error_code ec;
    pair.client.close(ec);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesBindFailureAndStartPath)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 36, timeout_cfg);
    fail_next_bind(EADDRINUSE);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesUdpLocalEndpointFailure)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 40, timeout_cfg);
    fail_getsockname_on_call(2, ENOTSOCK);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesIpv6V6OnlyOptionFailure)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 41, timeout_cfg);
    mock_next_getsockname_ipv6_any();
    fail_next_setsockopt(IPPROTO_IPV6, -1, EPERM);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesNullTunnelConnection)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 203);
    tunnel->connection_ = nullptr;
    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 42, timeout_cfg);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateHandlesClosedTunnelConnection)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 204);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    mock_conn->connection_state_.store(mux::mux_connection_state::kClosed, std::memory_order_release);
    tunnel->connection_ = mock_conn;
    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 43, timeout_cfg);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateSynFailureRemovesCreatedStream)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 205);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(205));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_)).WillOnce(testing::Return(true));
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_))
        .WillOnce(testing::Return(std::make_error_code(std::errc::broken_pipe)));
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{}))
        .WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 45, timeout_cfg);
    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateAckFailureRemovesCreatedStream)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 206);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(206));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillOnce(
            [&ctx](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> iface) -> bool
            {
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }
                boost::asio::post(ctx, [stream]() { stream->on_reset(); });
                return true;
            });
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{})).Times(0);
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 46, timeout_cfg);
    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepGenFail);
}

TEST(UdpSocksSessionTest, PrepareUdpAssociateSuccessReplyFailureCleansUpSessionAndStream)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 207);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 47, timeout_cfg);
    auto* session_raw = session.get();

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(207));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillOnce(
            [&ctx, session_raw](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> iface) -> bool
            {
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }

                boost::asio::post(ctx,
                                  [session_raw]()
                                  {
                                      boost::system::error_code close_ec;
                                      session_raw->socket_.close(close_ec);
                                  });

                mux::ack_payload ack{};
                ack.socks_rep = socks::kRepSuccess;
                std::vector<std::uint8_t> ack_data;
                mux::mux_codec::encode_ack(ack, ack_data);
                boost::asio::post(ctx, [stream, ack_data]() { stream->on_data(ack_data); });
                return true;
            });
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{}))
        .WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    EXPECT_EQ(stream, nullptr);
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, StartSpawnsRunAndWritesHostUnreachWhenTunnelUnavailable)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, nullptr, 37, timeout_cfg);
    session->start("ignored.example", 1234);
    ctx.run();

    std::uint8_t err[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(err));
    EXPECT_EQ(err[0], socks::kVer);
    EXPECT_EQ(err[1], socks::kRepHostUnreach);
}

TEST(UdpSocksSessionTest, RunReturnsWhenAlreadyClosed)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 209);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(209));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).Times(0);

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 39, timeout_cfg);
    session->on_close();

    mux::test::run_awaitable_void(ctx, session->run("ignored.example", 1234));
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, PrepareAndFinalizeUdpAssociateSuccess)
{
    mux::config::timeout_t const timeout_cfg;
    boost::asio::io_context ctx;
    auto pair = make_tcp_socket_pair(ctx);
    ASSERT_TRUE(pair.client.is_open());
    ASSERT_TRUE(pair.server.is_open());

    auto tunnel = make_test_tunnel(ctx, 201);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(201));
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillOnce(
            [&ctx](const std::uint32_t, std::shared_ptr<mux::mux_stream_interface> iface) -> bool
            {
                auto stream = std::dynamic_pointer_cast<mux::mux_stream>(iface);
                EXPECT_NE(stream, nullptr);
                if (stream == nullptr)
                {
                    return false;
                }
                mux::ack_payload ack{};
                ack.socks_rep = socks::kRepSuccess;
                std::vector<std::uint8_t> ack_data;
                mux::mux_codec::encode_ack(ack, ack_data);
                boost::asio::post(ctx, [stream, ack_data]() { stream->on_data(ack_data); });
                return true;
            });
    testing::Sequence const cleanup_seq;
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{}))
        .InSequence(cleanup_seq)
        .WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).InSequence(cleanup_seq);

    auto session = std::make_shared<mux::udp_socks_session>(std::move(pair.server), ctx, tunnel, 38, timeout_cfg);
    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = mux::test::run_awaitable(ctx, session->prepare_udp_associate(local_addr, udp_bind_port));
    ASSERT_NE(stream, nullptr);
    EXPECT_NE(udp_bind_port, 0);
    mux::test::run_awaitable_void(ctx, session->finalize_udp_associate(stream));

    std::uint8_t rep[10] = {0};
    boost::asio::read(pair.client, boost::asio::buffer(rep));
    EXPECT_EQ(rep[0], socks::kVer);
    EXPECT_EQ(rep[1], socks::kRepSuccess);
}

TEST(UdpSocksSessionTest, CloseImplLogsCloseFailureBranch)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 5, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);

    fail_next_close(EIO);
    session->close_impl();

    session->close_impl();

    auto session_bad_descriptor = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 44, timeout_cfg);
    session_bad_descriptor->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session_bad_descriptor->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    fail_next_close(EBADF);
    session_bad_descriptor->close_impl();
}

TEST(UdpSocksSessionTest, OnCloseRunsInlineWhenIoContextStopped)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 45, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    ctx.stop();
    session->on_close();
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, OnDataTriggersCloseWhenIoContextStopped)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 48, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    session->recv_channel_.close();
    ctx.stop();

    session->on_data({0x11});
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, OnDataDispatchesFromForeignThread)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 58, timeout_cfg);

    std::promise<std::vector<std::uint8_t>> received_promise;
    auto received_future = received_promise.get_future();

    boost::asio::co_spawn(
        ctx,
        [session, &received_promise]() -> boost::asio::awaitable<void>
        {
            const auto [ec, data] = co_await session->recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                received_promise.set_value({});
                co_return;
            }
            received_promise.set_value(data);
        },
        boost::asio::detached);

    std::thread io_thread([&ctx]() { ctx.run(); });
    session->on_data({0x21, 0x22});

    ASSERT_EQ(received_future.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    const auto data = received_future.get();
    ASSERT_EQ(data.size(), 2U);
    EXPECT_EQ(data[0], 0x21);
    EXPECT_EQ(data[1], 0x22);
    EXPECT_FALSE(session->closed_.load(std::memory_order_acquire));

    session->on_close();
    ctx.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(UdpSocksSessionTest, OnCloseRunsWhenIoContextNotRunning)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 46, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    session->on_close();
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, OnDataTriggersCloseWhenIoContextNotRunning)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 50, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    session->recv_channel_.close();
    session->on_data({0x11});

    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());
}

TEST(UdpSocksSessionTest, OnDataTriggersCloseWhenIoQueueBlocked)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 49, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    session->recv_channel_.close();

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(ctx,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { ctx.run(); });
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
        ctx.stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    session->on_data({0x11});
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    ctx.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(UdpSocksSessionTest, OnCloseRunsWhenIoQueueBlocked)
{
    boost::asio::io_context ctx;
    mux::config::timeout_t const timeout_cfg;
    auto session = std::make_shared<mux::udp_socks_session>(boost::asio::ip::tcp::socket(ctx), ctx, nullptr, 47, timeout_cfg);

    boost::system::error_code ec;
    session->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    session->udp_socket_.bind({boost::asio::ip::make_address("127.0.0.1"), 0}, ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->udp_socket_.is_open());

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(ctx,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { ctx.run(); });
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
        ctx.stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    session->on_close();
    EXPECT_TRUE(session->closed_.load(std::memory_order_acquire));
    EXPECT_FALSE(session->udp_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    ctx.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}
