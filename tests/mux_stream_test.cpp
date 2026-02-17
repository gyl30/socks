#include <memory>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio/io_context.hpp>

#include "test_util.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "mock_mux_connection.h"

class mux_stream_test : public ::testing::Test
{
   protected:
    asio::io_context& ctx() { return ctx_; }

   private:
    asio::io_context ctx_;
};

TEST_F(mux_stream_test, WriteSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdDat, data)).WillOnce(::testing::Return(std::error_code()));

    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_FALSE(ec);
}

TEST_F(mux_stream_test, WriteSomeFailurePropagatesError)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdDat, data)).WillOnce(::testing::Return(asio::error::broken_pipe));

    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, asio::error::broken_pipe);
}

TEST_F(mux_stream_test, ReadSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> data = {10, 20, 30};
    stream->on_data(data);

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_FALSE(ec);
    EXPECT_EQ(read_data, data);
}

TEST_F(mux_stream_test, CloseSendsFin)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, std::vector<std::uint8_t>())).WillOnce(::testing::Return(std::error_code()));

    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test, CloseIsIdempotent)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, std::vector<std::uint8_t>())).Times(1).WillOnce(::testing::Return(std::error_code()));

    mux::test::run_awaitable_void(ctx(), stream->close());
    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test, CloseWithoutConnection)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    mock_conn.reset();
    mux::test::run_awaitable_void(ctx(), stream->close());
}

TEST_F(mux_stream_test, OnCloseUnblocksReader)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_close();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());

    EXPECT_EQ(ec, asio::error::eof);
}

TEST_F(mux_stream_test, OnCloseSecondCallDoesNotInjectExtraEOF)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    const std::vector<std::uint8_t> payload = {42};
    stream->on_close();
    stream->on_close();
    stream->on_data(payload);

    const auto [first_ec, first_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_EQ(first_ec, asio::error::eof);
    EXPECT_TRUE(first_data.empty());

    const auto [second_ec, second_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_FALSE(second_ec);
    EXPECT_EQ(second_data, payload);
}

TEST_F(mux_stream_test, WriteAfterClose)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, ::testing::_)).WillOnce(::testing::Return(std::error_code()));
    mux::test::run_awaitable_void(ctx(), stream->close());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, asio::error::operation_aborted);
}

TEST_F(mux_stream_test, WriteAfterConnectionDestroyed)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    mock_conn.reset();

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx(), stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, asio::error::connection_aborted);
}

TEST_F(mux_stream_test, OnReset)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_reset();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_TRUE(ec);
}

TEST_F(mux_stream_test, OnDataIgnoredAfterReset)
{
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx());
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx());

    stream->on_reset();
    stream->on_data({1, 2, 3});

    const auto [ec, read_data] = mux::test::run_awaitable(ctx(), stream->async_read_some());
    EXPECT_TRUE(ec);
    EXPECT_TRUE(read_data.empty());
}

TEST_F(mux_stream_test, OnDataChannelFullClosesStream)
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
    EXPECT_EQ(ec, asio::error::operation_aborted);
}

TEST_F(mux_stream_test, OnCloseChannelFullClosesStream)
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
    EXPECT_EQ(ec, asio::error::operation_aborted);
}
