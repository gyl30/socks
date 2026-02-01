#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mux_stream.h"
#include "mock_mux_connection.h"
#include "test_util.h"

using namespace mux;
using namespace mux::test;
using testing::_;
using testing::Return;

class MuxStreamTest : public ::testing::Test
{
   protected:
    asio::io_context ctx;
};

TEST_F(MuxStreamTest, WriteSome_Success)
{
    auto mock_conn = std::make_shared<MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    std::vector<uint8_t> data = {1, 2, 3, 4};

    EXPECT_CALL(*mock_conn, mock_send_async(1, CMD_DAT, data)).WillOnce(Return(std::error_code()));

    auto ec = run_awaitable(ctx, stream->async_write_some(data.data(), data.size()));
    EXPECT_FALSE(ec);
}

TEST_F(MuxStreamTest, ReadSome_Success)
{
    auto mock_conn = std::make_shared<MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    std::vector<uint8_t> data = {10, 20, 30};
    stream->on_data(data);

    auto [ec, read_data] = run_awaitable(ctx, stream->async_read_some());
    EXPECT_FALSE(ec);
    EXPECT_EQ(read_data, data);
}

TEST_F(MuxStreamTest, Close_SendsFin)
{
    auto mock_conn = std::make_shared<MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    EXPECT_CALL(*mock_conn, mock_send_async(1, CMD_FIN, std::vector<uint8_t>())).WillOnce(Return(std::error_code()));

    run_awaitable_void(ctx, stream->close());
}

TEST_F(MuxStreamTest, OnClose_UnblocksReader)
{
    auto mock_conn = std::make_shared<MockMuxConnection>(ctx);
    auto stream = std::make_shared<mux_stream>(1, 100, "trace-1", mock_conn, ctx.get_executor());

    stream->on_close();

    auto [ec, read_data] = run_awaitable(ctx, stream->async_read_some());

    EXPECT_TRUE(ec);
}
