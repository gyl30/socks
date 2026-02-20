// NOLINTBEGIN(misc-include-cleaner)
#include <memory>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>

#include "test_util.h"

#define private public
#include "mux_stream.h"

#undef private
#include "mux_protocol.h"
#include "mock_mux_connection.h"

class mux_stream_test_fixture : public ::testing::Test
{
   protected:
    boost::asio::io_context& ctx() { return ctx_; }

   private:
    boost::asio::io_context ctx_;
};

TEST_F(mux_stream_test_fixture, WriteSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdDat, data)).WillOnce(::testing::Return(boost::system::error_code()));

    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_FALSE(ec);
}

TEST_F(mux_stream_test_fixture, WriteSomeFailurePropagatesError)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdDat, data)).WillOnce(::testing::Return(boost::asio::error::broken_pipe));

    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, boost::asio::error::broken_pipe);
}

TEST_F(mux_stream_test_fixture, ReadSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {10, 20, 30};
    stream->on_data(data);

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_FALSE(ec);
    EXPECT_EQ(read_data, data);
}

TEST_F(mux_stream_test_fixture, CloseSendsFin)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, std::vector<std::uint8_t>())).WillOnce(::testing::Return(boost::system::error_code()));

    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test_fixture, CloseIsIdempotent)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, std::vector<std::uint8_t>()))
        .Times(1)
        .WillOnce(::testing::Return(boost::system::error_code()));

    mux::test::run_awaitable_void(ctx(), stream->close());
    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test_fixture, CloseWithoutConnection)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    mock_conn.reset();
    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test_fixture, OnCloseUnblocksReader)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_close();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());

    EXPECT_EQ(ec, boost::asio::error::eof);
}

TEST_F(mux_stream_test_fixture, OnCloseSecondCallDoesNotInjectExtraEOF)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> payload = {42};
    stream->on_close();
    stream->on_close();
    stream->on_data(payload);

    const auto [first_ec, first_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_EQ(first_ec, boost::asio::error::eof);
    EXPECT_TRUE(first_data.empty());

    const auto [second_ec, second_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_FALSE(second_ec);
    EXPECT_EQ(second_data, payload);
}

TEST_F(mux_stream_test_fixture, WriteAfterClose)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, ::testing::_)).WillOnce(::testing::Return(boost::system::error_code()));
    mux::test::run_awaitable_void(ctx(), stream->close());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, boost::asio::error::operation_aborted);
}

TEST_F(mux_stream_test_fixture, WriteAfterConnectionDestroyed)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    mock_conn.reset();

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, boost::asio::error::connection_aborted);
}

TEST_F(mux_stream_test_fixture, OnReset)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_reset();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_TRUE(ec);
}

TEST_F(mux_stream_test_fixture, OnDataIgnoredAfterReset)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_reset();
    stream->on_data({1, 2, 3});

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_TRUE(ec);
    EXPECT_TRUE(read_data.empty());
}

TEST_F(mux_stream_test_fixture, OnDataChannelFullClosesStream)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    for (int i = 0; i < 1024; ++i)
    {
        stream->on_data({1});
    }

    stream->on_data({2});

    const std::vector<std::uint8_t> data = {9};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, boost::asio::error::operation_aborted);
}

TEST_F(mux_stream_test_fixture, OnCloseChannelFullClosesStream)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    for (int i = 0; i < 1024; ++i)
    {
        stream->on_data({1});
    }

    stream->on_close();

    const std::vector<std::uint8_t> data = {9};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, boost::asio::error::operation_aborted);
}

TEST_F(mux_stream_test_fixture, OnDataClosedChannelTriggersUnavailableBranch)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->recv_channel_.close();
    stream->on_data({7, 8, 9});

    EXPECT_TRUE(stream->is_closed_.load(std::memory_order_acquire));
}

TEST_F(mux_stream_test_fixture, OnCloseClosedChannelTriggersUnavailableBranch)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->recv_channel_.close();
    stream->on_close();

    EXPECT_TRUE(stream->is_closed_.load(std::memory_order_acquire));
    EXPECT_TRUE(stream->fin_received_.load(std::memory_order_acquire));
}
// NOLINTEND(misc-include-cleaner)
