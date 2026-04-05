#include <cstdint>
#include <memory>
#include <vector>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "constants.h"
#include "net_utils.h"
#include "mux_protocol.h"
#include "mux_stream.h"

namespace mux
{

mux_stream::mux_stream(uint32_t id, const config& cfg, boost::asio::io_context& io_context, frame_sender send_frame)
    : id_(id), cfg_(cfg), send_frame_(std::move(send_frame)), recv_channel_(io_context, constants::mux::kStreamRecvChannelCapacity)
{
}

mux_stream::~mux_stream() = default;

uint32_t mux_stream::id() const { return id_; }

void mux_stream::close() { recv_channel_.close(); }

boost::asio::awaitable<void> mux_stream::on_frame(mux_frame frame, boost::system::error_code& ec)
{
    co_await net::wait_send_with_timeout<mux_frame>(recv_channel_, std::move(frame), cfg_.timeout.write, ec);
}
boost::asio::awaitable<mux_frame> mux_stream::async_read(boost::system::error_code& ec)
{
    auto data = co_await async_read(cfg_.timeout.read, ec);
    co_return data;
}

boost::asio::awaitable<mux_frame> mux_stream::async_read(uint32_t timeout_sec, boost::system::error_code& ec)
{
    auto data = co_await net::wait_receive_with_timeout<mux_frame>(recv_channel_, timeout_sec, ec);
    co_return data;
}

boost::asio::awaitable<void> mux_stream::async_write(mux_frame frame, boost::system::error_code& ec) const
{
    if (!send_frame_)
    {
        ec = boost::asio::error::connection_aborted;
        co_return;
    }

    frame.h.stream_id = id_;
    if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
    {
        co_await send_frame_(std::move(frame), constants::mux::kControlFrameSendTimeoutSec, ec);
    }
    else
    {
        co_await send_frame_(std::move(frame), 0, ec);
    }
    if (ec)
    {
        co_return;
    }
}

}    // namespace mux
