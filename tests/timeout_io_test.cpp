#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <system_error>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <gtest/gtest.h>

#include "test_util.h"
#include "timeout_io.h"

namespace
{

struct tcp_socket_pair
{
    std::shared_ptr<boost::asio::ip::tcp::socket> client;
    std::shared_ptr<boost::asio::ip::tcp::socket> server;
};

tcp_socket_pair make_connected_tcp_socket_pair(boost::asio::io_context& io_context)
{
    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    if (!mux::test::open_ephemeral_tcp_acceptor(acceptor))
    {
        ADD_FAILURE() << "open ephemeral acceptor failed";
        return {};
    }

    auto client = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    auto server = std::make_shared<boost::asio::ip::tcp::socket>(io_context);

    client->connect(acceptor.local_endpoint(), ec);
    if (ec)
    {
        ADD_FAILURE() << "client connect failed: " << ec.message();
        return {};
    }
    acceptor.accept(*server, ec);
    if (ec)
    {
        ADD_FAILURE() << "accept failed: " << ec.message();
        return {};
    }
    return tcp_socket_pair{
        .client = std::move(client),
        .server = std::move(server)};
}

}    // namespace

TEST(timeout_io_test, ReadTimeoutCancelsSocketAndReturnsTimedOut)
{
    boost::asio::io_context io_context;
    auto pair = make_connected_tcp_socket_pair(io_context);
    ASSERT_TRUE(pair.client);
    ASSERT_TRUE(pair.server);

    std::array<std::uint8_t, 1> read_buf = {};
    mux::timeout_io::timed_tcp_read_result read_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       read_res = co_await mux::timeout_io::async_read_with_timeout(
                           pair.client, boost::asio::buffer(read_buf), 1, true, "timeout-io-test");
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    EXPECT_FALSE(read_res.ok);
    EXPECT_TRUE(read_res.timed_out);
    EXPECT_EQ(read_res.ec, boost::asio::error::timed_out);
    EXPECT_FALSE(pair.client->is_open());
}

TEST(timeout_io_test, ZeroReadTimeoutDisablesStageTimeout)
{
    boost::asio::io_context io_context;
    auto pair = make_connected_tcp_socket_pair(io_context);
    ASSERT_TRUE(pair.client);
    ASSERT_TRUE(pair.server);

    std::array<std::uint8_t, 1> payload = {0x42};
    boost::system::error_code delayed_wait_ec;
    boost::system::error_code delayed_write_ec;
    std::size_t delayed_write_n = 0;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       boost::asio::steady_timer delayed_writer(io_context);
                       delayed_writer.expires_after(std::chrono::milliseconds(1200));
                       const auto [wait_ec] = co_await delayed_writer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
                       delayed_wait_ec = wait_ec;
                       const auto [write_ec, write_n] =
                           co_await boost::asio::async_write(*pair.server, boost::asio::buffer(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
                       delayed_write_ec = write_ec;
                       delayed_write_n = write_n;
                       co_return;
                   },
                   boost::asio::detached);

    std::array<std::uint8_t, 1> read_buf = {};
    mux::timeout_io::timed_tcp_read_result read_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       read_res = co_await mux::timeout_io::async_read_with_timeout(
                           pair.client, boost::asio::buffer(read_buf), 0, true, "timeout-io-test");
                       co_return;
                   },
                   boost::asio::detached);

    io_context.run();

    EXPECT_FALSE(delayed_wait_ec);
    EXPECT_FALSE(delayed_write_ec);
    EXPECT_EQ(delayed_write_n, 1U);
    EXPECT_TRUE(read_res.ok);
    EXPECT_FALSE(read_res.timed_out);
    EXPECT_EQ(read_res.read_size, 1U);
    EXPECT_EQ(read_buf[0], payload[0]);
}

TEST(timeout_io_test, ConnectFailureReturnsNonTimeoutError)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    const auto port = acceptor.local_endpoint().port();
    acceptor.close(ec);
    ASSERT_FALSE(ec);

    boost::asio::ip::tcp::socket socket(io_context);
    socket.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);

    mux::timeout_io::timed_tcp_connect_result connect_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       connect_res = co_await mux::timeout_io::async_connect_with_timeout(
                           socket,
                           boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port),
                           3,
                           "timeout-io-test");
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    EXPECT_FALSE(connect_res.ok);
    EXPECT_FALSE(connect_res.timed_out);
    EXPECT_TRUE(connect_res.ec);
    EXPECT_NE(connect_res.ec, boost::asio::error::timed_out);
}
