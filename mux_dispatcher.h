#ifndef MUX_DISPATCHER_H
#define MUX_DISPATCHER_H

#include <span>
#include <vector>
#include <cstdint>
#include <cstring>

#include <boost/asio/streambuf.hpp>
#include <boost/system/error_code.hpp>

#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

class mux_dispatcher
{
   public:
    mux_dispatcher();

   public:
    void set_context(connection_context ctx);
    void set_max_buffer(std::size_t max_buffer);
    void on_plaintext_data(std::span<const std::uint8_t> data, std::vector<mux_frame>& frames, boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> pack(std::uint32_t stream_id, std::uint8_t cmd, const std::vector<std::uint8_t>& payload);

   private:
    void process_frames(std::vector<mux_frame>& frames, boost::system::error_code& ec);

   private:
    boost::asio::streambuf buffer_;
    connection_context ctx_;
    std::size_t max_buffer_ = 0;
};

}    // namespace mux

#endif
