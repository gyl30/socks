#include <memory>
#include <vector>
#include <cstdint>
#include <utility>

#include <openssl/evp.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <gmock/gmock-spec-builders.h>
#include <gmock/gmock-function-mocker.h>

#include "mux_connection.h"
#include "mux_stream_interface.h"

class MockStream : public mux::mux_stream_interface
{
   public:
    MOCK_METHOD(void, on_data, (std::vector<uint8_t> data), (override));
    MOCK_METHOD(void, on_close, (), (override));
    MOCK_METHOD(void, on_reset, (), (override));
};

class MuxConnectionTest : public ::testing::Test
{
   protected:
    asio::io_context ctx_;
};

TEST_F(MuxConnectionTest, StreamManagement)
{
    asio::ip::tcp::socket socket(ctx_);
    mux::mux_connection conn(std::move(socket), mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 123);

    auto stream = std::make_shared<MockStream>();
    conn.register_stream(10, stream);

    const uint32_t id1 = conn.acquire_next_id();
    const uint32_t id2 = conn.acquire_next_id();
    EXPECT_NE(id1, id2);
    EXPECT_EQ(conn.id(), 123);
}

TEST_F(MuxConnectionTest, InitialState)
{
    asio::ip::tcp::socket socket(ctx_);
    const mux::mux_connection conn(std::move(socket), mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 1);
    EXPECT_TRUE(conn.is_open());
}
