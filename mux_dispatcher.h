#ifndef MUX_DISPATCHER_H
#define MUX_DISPATCHER_H

#include <span>
#include <atomic>
#include <vector>
#include <cstdint>
#include <cstring>
#include <functional>

#include <asio/buffer.hpp>
#include <asio/streambuf.hpp>

#include "mux_codec.h"
#include "log_context.h"
#include "mux_protocol.h"

namespace mux
{

class mux_dispatcher
{
   public:
    using frame_callback_t = std::function<void(mux::frame_header, std::vector<std::uint8_t>)>;

    mux_dispatcher();

    void set_callback(frame_callback_t cb);
    void set_context(connection_context ctx);
    void set_max_buffer(std::size_t max_buffer);

    void on_plaintext_data(std::span<const std::uint8_t> data);

    [[nodiscard]] static std::vector<std::uint8_t> pack(std::uint32_t stream_id, std::uint8_t cmd, const std::vector<std::uint8_t>& payload);
    [[nodiscard]] bool overflowed() const { return overflowed_.load(std::memory_order_acquire); }

   private:
    void process_frames();

   private:
    frame_callback_t callback_;
    asio::streambuf buffer_;
    connection_context ctx_;
    std::size_t max_buffer_ = 0;
    std::atomic<bool> overflowed_{false};
};

}    // namespace mux

#endif
