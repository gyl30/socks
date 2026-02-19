#ifndef SOCKS_MOCK_MUX_CONNECTION_H
#define SOCKS_MOCK_MUX_CONNECTION_H

#include <memory>
#include <vector>
#include <cstdint>
#include <system_error>

#include <boost/asio.hpp>
#include <gmock/gmock.h>

#include "mux_connection.h"

namespace mux
{

class mock_mux_connection : public mux_connection
{
   public:
    mock_mux_connection(boost::asio::io_context& ctx)
        : mux_connection(boost::asio::ip::tcp::socket(ctx), ctx, reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 0)
    {
    }

    MOCK_METHOD(bool, register_stream, (uint32_t id, std::shared_ptr<mux_stream_interface> stream), (override));
    bool register_stream_checked(const uint32_t id, std::shared_ptr<mux_stream_interface> stream) override
    {
        return register_stream(id, std::move(stream));
    }
    MOCK_METHOD(void, remove_stream, (uint32_t id), (override));
    MOCK_METHOD(uint32_t, id, (), (const, override));

    boost::asio::awaitable<boost::system::error_code> send_async(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload) override
    {
        co_return mock_send_async(stream_id, cmd, payload);
    }
    MOCK_METHOD(boost::system::error_code, mock_send_async, (uint32_t stream_id, uint8_t cmd, const std::vector<uint8_t>& payload));
};

}                    

#endif
