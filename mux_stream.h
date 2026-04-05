#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <cstdint>
#include <functional>
#include <memory>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/system/error_code.hpp>

#include "config.h"
#include "mux_protocol.h"

namespace mux
{

class mux_stream
{
   public:
    using frame_sender = std::function<boost::asio::awaitable<void>(mux_frame, uint32_t, boost::system::error_code&)>;

    mux_stream(uint32_t id, const config& cfg, boost::asio::io_context& io_context, frame_sender send_frame);

    ~mux_stream();

    [[nodiscard]] uint32_t id() const;
    void close();
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<mux_frame> async_read(uint32_t timeout_sec, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> on_frame(mux_frame, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write(mux_frame, boost::system::error_code& ec) const;

   private:
    uint32_t id_ = 0;
    const config& cfg_;
    frame_sender send_frame_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, mux_frame)> recv_channel_;
};

}    // namespace mux

#endif
