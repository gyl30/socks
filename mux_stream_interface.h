#ifndef MUX_STREAM_INTERFACE_H
#define MUX_STREAM_INTERFACE_H

#include <vector>
#include <cstdint>

namespace mux
{

class mux_stream_interface
{
   public:
    virtual ~mux_stream_interface() = default;
    virtual void on_data(std::vector<std::uint8_t> data) = 0;
    virtual void on_close() = 0;
    virtual void on_reset() = 0;
};

}    // namespace mux

#endif
