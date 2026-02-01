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

// This test focuses on stream registration and command dispatching logic
// Without actually running the read/write loops which require a real socket.
TEST_F(MuxConnectionTest, StreamManagement)
{
    asio::ip::tcp::socket socket(ctx);
    mux_connection conn(std::move(socket), reality_engine{{}, {}, {}, {}}, true, 123);

    auto stream = std::make_shared<MockStream>();
    conn.register_stream(10, stream);

    // Check next_id logic (initial for client is usually 1, then increments by 2)
    uint32_t id1 = conn.acquire_next_id();
    uint32_t id2 = conn.acquire_next_id();
    EXPECT_NE(id1, id2);
    EXPECT_EQ(conn.id(), 123);
}

// We can test the internal 'on_mux_frame' if we make it accessible or via a friend
// For now, let's verify public state transitions.
TEST_F(MuxConnectionTest, InitialState)
{
    asio::ip::tcp::socket socket(ctx);
    mux_connection conn(std::move(socket), reality_engine{{}, {}, {}, {}}, true, 1);
    EXPECT_TRUE(conn.is_open());    // Starts as connected since the underlying layer is assumed ready
}
