#ifndef MUX_STREAM_INTERFACE_H
#define MUX_STREAM_INTERFACE_H

#include <vector>
#include <cstdint>

#include <boost/asio/awaitable.hpp>

#include "mux_protocol.h"

namespace mux
{

class mux_stream_interface
{
   public:
    virtual ~mux_stream_interface() = default;

   public:
    virtual uint32_t id() = 0;
    virtual boost::asio::awaitable<void> on_data(mux_frame) = 0;
    virtual boost::asio::awaitable<void> write(const std::vector<uint8_t>&) = 0;
};

}    // namespace mux

#endif
