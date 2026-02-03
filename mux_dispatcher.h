#ifndef MUX_DISPATCHER_H
#define MUX_DISPATCHER_H

#include <cstring>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>
#include <asio/buffer.hpp>
#include <asio/streambuf.hpp>

#include "log_context.h"
#include "mux_codec.h"
#include "mux_protocol.h"

class mux_dispatcher
{
   public:
    using frame_callback_t = std::function<void(mux::frame_header, std::vector<uint8_t>)>;

    mux_dispatcher();

    void set_callback(frame_callback_t cb);
    void set_context(connection_context ctx);

    void on_plaintext_data(std::span<const uint8_t> data);

    [[nodiscard]] static std::vector<uint8_t> pack(uint32_t stream_id, uint8_t cmd, const std::vector<uint8_t>& payload);

   private:
    void process_frames();

   private:
    frame_callback_t callback_;
    asio::streambuf buffer_;
    connection_context ctx_;
};

#endif
