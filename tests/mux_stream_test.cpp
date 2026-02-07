#include <memory>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <asio/io_context.hpp>

#include "test_util.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "mock_mux_connection.h"

class MuxStreamTest : public ::testing::Test
{
   protected:
    asio::io_context ctx_;
};

TEST_F(MuxStreamTest, WriteSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdDat, data)).WillOnce(::testing::Return(std::error_code()));

    const auto ec = mux::test::run_awaitable(ctx_, stream->async_write_some(data.data(), data.size()));
    EXPECT_FALSE(ec);
}

TEST_F(MuxStreamTest, ReadSomeSuccess)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    const std::vector<std::uint8_t> data = {10, 20, 30};
    stream->on_data(data);

    const auto [ec, read_data] = mux::test::run_awaitable(ctx_, stream->async_read_some());
    EXPECT_FALSE(ec);
    EXPECT_EQ(read_data, data);
}

TEST_F(MuxStreamTest, CloseSendsFin)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, std::vector<std::uint8_t>())).WillOnce(::testing::Return(std::error_code()));

    mux::test::run_awaitable_void(ctx_, stream->close());
}

TEST_F(MuxStreamTest, OnCloseUnblocksReader)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    stream->on_close();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx_, stream->async_read_some());

    EXPECT_EQ(ec, asio::error::eof);
}

TEST_F(MuxStreamTest, WriteAfterClose)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::kCmdFin, ::testing::_)).WillOnce(::testing::Return(std::error_code()));
    mux::test::run_awaitable_void(ctx_, stream->close());

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx_, stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, asio::error::operation_aborted);
}

TEST_F(MuxStreamTest, WriteAfterConnectionDestroyed)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    mock_conn.reset();

    const std::vector<std::uint8_t> data = {1, 2, 3, 4};
    const auto ec = mux::test::run_awaitable(ctx_, stream->async_write_some(data.data(), data.size()));
    EXPECT_EQ(ec, asio::error::connection_aborted);
}

TEST_F(MuxStreamTest, OnReset)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx_);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx_.get_executor());

    stream->on_reset();

    const auto [ec, read_data] = mux::test::run_awaitable(ctx_, stream->async_read_some());
    EXPECT_TRUE(ec);
}
