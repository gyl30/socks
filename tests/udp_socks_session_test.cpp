#include <thread>
#include <chrono>
#include <memory>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include "protocol.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "mock_mux_connection.h"
#define private public
#include "udp_socks_session.h"
#undef private

namespace
{

asio::ip::tcp::socket make_connected_server_socket(asio::io_context& ctx)
{
    asio::ip::tcp::acceptor acceptor(ctx, {asio::ip::tcp::v4(), 0});
    asio::ip::tcp::socket client(ctx);
    asio::ip::tcp::socket server(ctx);

    std::error_code ec;
    client.connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        return asio::ip::tcp::socket(ctx);
    }
    acceptor.accept(server, ec);
    if (ec)
    {
        return asio::ip::tcp::socket(ctx);
    }
    return server;
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
    auto server_socket = make_connected_server_socket(ctx);
    ASSERT_TRUE(server_socket.is_open());

    auto session_without_tunnel =
        std::make_shared<mux::udp_socks_session>(std::move(server_socket), ctx, nullptr, 2, timeout_cfg);

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
