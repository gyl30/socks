#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mux_connection.h"
#include "mux_stream_interface.h"
#include "test_util.h"

using namespace mux;
using namespace mux::test;

class MockStream : public mux_stream_interface
{
   public:
    MOCK_METHOD(void, on_data, (std::vector<uint8_t> data), (override));
    MOCK_METHOD(void, on_close, (), (override));
    MOCK_METHOD(void, on_reset, (), (override));
};

class MuxConnectionTest : public ::testing::Test
{
   protected:
    asio::io_context ctx;
};

TEST_F(MuxConnectionTest, StreamManagement)
{
    asio::ip::tcp::socket socket(ctx);
    mux_connection conn(std::move(socket), reality_engine{{}, {}, {}, {}}, true, 123);

    auto stream = std::make_shared<MockStream>();
    conn.register_stream(10, stream);

    uint32_t id1 = conn.acquire_next_id();
    uint32_t id2 = conn.acquire_next_id();
    EXPECT_NE(id1, id2);
    EXPECT_EQ(conn.id(), 123);
}

TEST_F(MuxConnectionTest, InitialState)
{
    asio::ip::tcp::socket socket(ctx);
    mux_connection conn(std::move(socket), reality_engine{{}, {}, {}, {}}, true, 1);
    EXPECT_TRUE(conn.is_open());
}
