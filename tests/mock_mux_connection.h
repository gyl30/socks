#ifndef SOCKS_MOCK_MUX_CONNECTION_H
#define SOCKS_MOCK_MUX_CONNECTION_H

#include <gmock/gmock.h>
#include "mux_connection.h"

namespace mux
{

class MockMuxConnection : public mux_connection
{
   public:
    MockMuxConnection(asio::io_context& ctx) : mux_connection(asio::ip::tcp::socket(ctx), reality_engine{{}, {}, {}, {}}, true, 0) {}

    MOCK_METHOD(void, register_stream, (uint32_t id, std::shared_ptr<mux_stream_interface> stream), (override));
    MOCK_METHOD(void, remove_stream, (uint32_t id), (override));
    MOCK_METHOD(uint32_t, id, (), (const, override));

    asio::awaitable<std::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload) override
    {
        co_return mock_send_async(stream_id, cmd, payload);
    }
    MOCK_METHOD(std::error_code, mock_send_async, (uint32_t stream_id, uint8_t cmd, const std::vector<uint8_t>& payload));
};

}    // namespace mux

#endif
