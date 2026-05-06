#include "stream_relay_transport.h"

#include <algorithm>

#include <boost/asio/buffer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "net_utils.h"
#include "proxy_stream_relay_transport.h"

namespace relay
{

namespace
{

std::size_t consume_pending_read_data(std::vector<uint8_t>& pending_read_data, std::size_t& pending_read_offset, std::span<uint8_t> buffer)
{
    const auto remaining = pending_read_data.size() - pending_read_offset;
    const auto size = std::min(buffer.size(), remaining);
    std::copy_n(pending_read_data.data() + static_cast<std::ptrdiff_t>(pending_read_offset), static_cast<std::ptrdiff_t>(size), buffer.data());
    pending_read_offset += size;
    if (pending_read_offset == pending_read_data.size())
    {
        pending_read_data.clear();
        pending_read_offset = 0;
    }
    return size;
}

}    // namespace

proxy_connection_tcp_stream::proxy_connection_tcp_stream(std::shared_ptr<proxy_reality_connection> connection)
    : connection_(std::move(connection))
{
}

void proxy_connection_tcp_stream::reset(std::shared_ptr<proxy_reality_connection> connection)
{
    connection_ = std::move(connection);
    pending_read_data_.clear();
    pending_read_offset_ = 0;
    recv_state_.reset();
    send_state_.reset();
}

boost::asio::awaitable<std::size_t> proxy_connection_tcp_stream::read(
    std::span<uint8_t> buffer, const uint32_t read_timeout, boost::system::error_code& ec)
{
    ec.clear();
    if (buffer.empty())
    {
        co_return 0;
    }
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }
    if (!pending_read_data_.empty())
    {
        co_return consume_pending_read_data(pending_read_data_, pending_read_offset_, buffer);
    }
    if (recv_state_.shutdown_seen())
    {
        ec = boost::asio::error::eof;
        co_return 0;
    }

    for (;;)
    {
        const auto packet = co_await connection_->read_packet(read_timeout, ec);
        if (ec)
        {
            co_return 0;
        }

        proxy::tcp_stream_frame frame;
        if (!proxy::decode_tcp_stream_frame(packet.data(), packet.size(), frame))
        {
            ec = boost::asio::error::invalid_argument;
            co_return 0;
        }
        if (!recv_state_.accept(frame))
        {
            ec = boost::asio::error::invalid_argument;
            co_return 0;
        }
        if (recv_state_.shutdown_seen())
        {
            ec = boost::asio::error::eof;
            co_return 0;
        }

        pending_read_data_ = std::move(frame.payload);
        pending_read_offset_ = 0;
        if (!pending_read_data_.empty())
        {
            co_return consume_pending_read_data(pending_read_data_, pending_read_offset_, buffer);
        }
    }
}

boost::asio::awaitable<std::size_t> proxy_connection_tcp_stream::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    ec.clear();
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }
    if (!send_state_.can_send_data(data))
    {
        ec = send_state_.shutdown_sent() ? boost::asio::error::broken_pipe : boost::asio::error::message_size;
        co_return 0;
    }

    std::vector<uint8_t> packet;
    if (!proxy::encode_tcp_stream_data(data, packet))
    {
        ec = boost::asio::error::message_size;
        co_return 0;
    }

    co_await connection_->write_packet(packet, ec);
    if (ec)
    {
        co_return 0;
    }
    co_return data.size();
}

boost::asio::awaitable<void> proxy_connection_tcp_stream::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }
    if (!send_state_.can_send_shutdown())
    {
        co_return;
    }

    std::vector<uint8_t> packet;
    if (!proxy::encode_tcp_stream_shutdown(packet))
    {
        ec = boost::asio::error::invalid_argument;
        co_return;
    }
    co_await connection_->write_packet(packet, ec);
    if (!ec)
    {
        send_state_.mark_shutdown_sent();
    }
}

boost::asio::awaitable<void> proxy_connection_tcp_stream::close()
{
    if (connection_ != nullptr)
    {
        boost::system::error_code ec;
        connection_->close(ec);
    }
    reset();
    co_return;
}

tcp_socket_stream_relay_transport::tcp_socket_stream_relay_transport(boost::asio::ip::tcp::socket& socket, const config::timeout_t& timeout)
    : socket_(socket), timeout_(timeout)
{
}

boost::asio::awaitable<std::size_t> tcp_socket_stream_relay_transport::read(std::span<uint8_t> buffer, boost::system::error_code& ec)
{
    ec.clear();
    if (buffer.empty())
    {
        co_return 0;
    }

    const auto bytes_read = co_await socket_.async_read_some(
        boost::asio::buffer(buffer.data(), buffer.size()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        co_return 0;
    }
    co_return bytes_read;
}

boost::asio::awaitable<std::size_t> tcp_socket_stream_relay_transport::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    ec.clear();
    if (data.empty())
    {
        co_return 0;
    }

    const auto bytes_written = co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(data.data(), data.size()), timeout_.write, ec);
    if (ec)
    {
        co_return 0;
    }
    co_return bytes_written;
}

boost::asio::awaitable<void> tcp_socket_stream_relay_transport::shutdown_send(boost::system::error_code& ec)
{
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    co_return;
}

boost::asio::awaitable<void> tcp_socket_stream_relay_transport::close()
{
    boost::system::error_code ec;
    ec = socket_.close(ec);
    (void)ec;
    co_return;
}

proxy_connection_stream_relay_transport::proxy_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection,
                                                                                 const config::timeout_t& timeout)
    : stream_(std::move(connection)), timeout_(timeout)
{
}

boost::asio::awaitable<std::size_t> proxy_connection_stream_relay_transport::read(std::span<uint8_t> buffer, boost::system::error_code& ec)
{
    if (!stream_.has_connection())
    {
        ec = boost::asio::error::operation_aborted;
        co_return 0;
    }
    const auto read_timeout = timeout_.idle == 0 ? timeout_.read : std::max(timeout_.read, timeout_.idle + 2U);
    const auto bytes_read = co_await stream_.read(buffer, read_timeout, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec = boost::asio::error::operation_aborted;
        co_return 0;
    }
    co_return bytes_read;
}

boost::asio::awaitable<std::size_t> proxy_connection_stream_relay_transport::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    if (!stream_.has_connection())
    {
        ec = boost::asio::error::operation_aborted;
        co_return 0;
    }
    const auto bytes_written = co_await stream_.write(data, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec = boost::asio::error::operation_aborted;
        co_return 0;
    }
    co_return bytes_written;
}

boost::asio::awaitable<void> proxy_connection_stream_relay_transport::shutdown_send(boost::system::error_code& ec)
{
    if (!stream_.has_connection())
    {
        ec = boost::asio::error::operation_aborted;
        co_return;
    }
    co_await stream_.shutdown_send(ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec = boost::asio::error::operation_aborted;
    }
}

boost::asio::awaitable<void> proxy_connection_stream_relay_transport::close()
{
    co_await stream_.close();
    co_return;
}

}    // namespace relay
