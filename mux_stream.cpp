#include <memory>
#include <utility>
#include <vector>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "mux_stream.h"
#include "timeout_io.h"
#include "mux_protocol.h"
#include "mux_connection.h"

namespace mux
{

namespace
{

constexpr std::uint32_t kControlFrameSendTimeoutSec = 1;

}    // namespace

mux_stream::mux_stream(std::uint32_t id, const config& cfg, boost::asio::io_context& io_context, const std::shared_ptr<mux_connection>& connection)
    : id_(id), cfg_(cfg), connection_(connection), recv_channel_(io_context, 1024)
{
}

mux_stream::~mux_stream() = default;

std::uint32_t mux_stream::id() const { return id_; }

void mux_stream::close() { recv_channel_.close(); }

boost::asio::awaitable<void> mux_stream::on_frame(mux_frame frame, boost::system::error_code& ec)
{
    co_await timeout_io::wait_send_with_timeout<mux_frame>(recv_channel_, std::move(frame), cfg_.timeout.write, ec);
}
boost::asio::awaitable<mux_frame> mux_stream::async_read(boost::system::error_code& ec)
{
    auto data = co_await async_read(cfg_.timeout.read, ec);
    co_return data;
}

boost::asio::awaitable<mux_frame> mux_stream::async_read(const std::uint32_t timeout_sec, boost::system::error_code& ec)
{
    auto data = co_await timeout_io::wait_receive_with_timeout<mux_frame>(recv_channel_, timeout_sec, ec);
    co_return data;
}

boost::asio::awaitable<void> mux_stream::async_write(mux_frame frame, boost::system::error_code& ec) const
{
    const auto connection = connection_.lock();
    if (!connection)
    {
        ec = boost::asio::error::connection_aborted;
        co_return;
    }

    frame.h.stream_id = id_;
    if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
    {
        co_await connection->send_async_with_timeout(std::move(frame), kControlFrameSendTimeoutSec, ec);
    }
    else
    {
        co_await connection->send_async(std::move(frame), ec);
    }
    if (ec)
    {
        co_return;
    }
}

}    // namespace mux
