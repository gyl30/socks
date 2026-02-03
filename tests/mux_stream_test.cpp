#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mux_stream.h"
#include "mock_mux_connection.h"
#include "test_util.h"

class MuxStreamTest : public ::testing::Test
{
   protected:
    asio::io_context ctx;
};

TEST_F(MuxStreamTest, WriteSome_Success)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    std::vector<uint8_t> data = {1, 2, 3, 4};

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::CMD_DAT, data)).WillOnce(::testing::Return(std::error_code()));

    auto ec = mux::test::run_awaitable(ctx, stream->async_write_some(data.data(), data.size()));
    EXPECT_FALSE(ec);
}

TEST_F(MuxStreamTest, ReadSome_Success)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    std::vector<uint8_t> data = {10, 20, 30};
    stream->on_data(data);

    auto [ec, read_data] = mux::test::run_awaitable(ctx, stream->async_read_some());
    EXPECT_FALSE(ec);
    EXPECT_EQ(read_data, data);
}

TEST_F(MuxStreamTest, Close_SendsFin)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    EXPECT_CALL(*mock_conn, mock_send_async(1, mux::CMD_FIN, std::vector<uint8_t>())).WillOnce(::testing::Return(std::error_code()));

    mux::test::run_awaitable_void(ctx, stream->close());
}

TEST_F(MuxStreamTest, OnClose_UnblocksReader)
{
    auto mock_conn = std::make_shared<mux::MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    stream->on_close();

    auto [ec, read_data] = mux::test::run_awaitable(ctx, stream->async_read_some());

    EXPECT_TRUE(ec);
}
