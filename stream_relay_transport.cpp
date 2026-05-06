#include <algorithm>

#include <boost/asio/buffer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "net_utils.h"
#include "stream_relay_transport.h"
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

vision_connection_tcp_stream::vision_connection_tcp_stream(std::shared_ptr<proxy_reality_connection> connection,
                                                           const vision::direction write_direction,
                                                           const vision::direction read_direction)
    : connection_(std::move(connection)), write_direction_(write_direction), read_direction_(read_direction)
{
}

void vision_connection_tcp_stream::reset(std::shared_ptr<proxy_reality_connection> connection,
                                         const vision::direction write_direction,
                                         const vision::direction read_direction)
{
    connection_ = std::move(connection);
    parser_ = vision::block_parser{};
    tracker_ = vision::tls_tracker{};
    pending_read_data_.clear();
    pending_read_offset_ = 0;
    pending_read_switch_raw_ = false;
    pending_read_switch_outer_plain_ = false;
    raw_read_mode_ = false;
    raw_write_mode_ = false;
    outer_plain_read_mode_ = false;
    outer_plain_write_mode_ = false;
    write_direction_ = write_direction;
    read_direction_ = read_direction;
}

boost::asio::awaitable<void> vision_connection_tcp_stream::apply_pending_read_switch(boost::system::error_code& ec)
{
    if (!pending_read_data_.empty())
    {
        ec.clear();
        co_return;
    }
    if (pending_read_switch_raw_)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            co_return;
        }
        pending_read_switch_raw_ = false;
        co_await connection_->enter_raw_read_mode(ec);
        if (ec)
        {
            co_return;
        }
        raw_read_mode_ = true;
    }
    if (pending_read_switch_outer_plain_)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            co_return;
        }
        pending_read_switch_outer_plain_ = false;
        outer_plain_read_mode_ = true;
    }
    ec.clear();
}

boost::asio::awaitable<std::size_t> vision_connection_tcp_stream::read_outer_plain(std::span<uint8_t> buffer,
                                                                                   const uint32_t read_timeout,
                                                                                   boost::system::error_code& ec)
{
    std::vector<uint8_t> outer_buffer(buffer.size());
    const auto bytes_read = co_await connection_->read_some(outer_buffer, read_timeout, ec);
    if (ec)
    {
        co_return 0;
    }
    std::copy_n(outer_buffer.data(), static_cast<std::ptrdiff_t>(bytes_read), buffer.data());
    co_return bytes_read;
}

boost::asio::awaitable<std::size_t> vision_connection_tcp_stream::read(std::span<uint8_t> buffer,
                                                                       const uint32_t read_timeout,
                                                                       boost::system::error_code& ec)
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
        const auto bytes = consume_pending_read_data(pending_read_data_, pending_read_offset_, buffer);
        co_await apply_pending_read_switch(ec);
        co_return bytes;
    }
    if (raw_read_mode_)
    {
        co_return co_await connection_->read_raw(buffer, read_timeout, ec);
    }
    if (outer_plain_read_mode_)
    {
        co_return co_await read_outer_plain(buffer, read_timeout, ec);
    }

    for (;;)
    {
        vision::block parsed;
        const auto status = parser_.next(parsed, ec);
        if (status == vision::parse_status::kError)
        {
            co_return 0;
        }
        if (status == vision::parse_status::kBlock)
        {
            if (!parsed.content.empty())
            {
                tracker_.observe(read_direction_, parsed.content);
                pending_read_data_ = std::move(parsed.content);
                pending_read_offset_ = 0;
                pending_read_switch_raw_ = parsed.cmd == vision::command::kDirect;
                pending_read_switch_outer_plain_ = parsed.cmd == vision::command::kEnd;
                const auto bytes = consume_pending_read_data(pending_read_data_, pending_read_offset_, buffer);
                co_await apply_pending_read_switch(ec);
                co_return bytes;
            }
            if (parsed.cmd == vision::command::kDirect)
            {
                if (!parser_.empty())
                {
                    ec = boost::asio::error::invalid_argument;
                    co_return 0;
                }
                co_await connection_->enter_raw_read_mode(ec);
                if (ec)
                {
                    co_return 0;
                }
                raw_read_mode_ = true;
                co_return co_await connection_->read_raw(buffer, read_timeout, ec);
            }
            if (parsed.cmd == vision::command::kEnd)
            {
                if (!parser_.empty())
                {
                    ec = boost::asio::error::invalid_argument;
                    co_return 0;
                }
                outer_plain_read_mode_ = true;
                co_return co_await read_outer_plain(buffer, read_timeout, ec);
            }
            continue;
        }

        std::vector<uint8_t> outer_buffer(buffer.size());
        const auto bytes_read = co_await connection_->read_some(outer_buffer, read_timeout, ec);
        if (ec)
        {
            co_return 0;
        }
        parser_.append(std::span<const uint8_t>(outer_buffer.data(), bytes_read));
    }
}

boost::asio::awaitable<std::size_t> vision_connection_tcp_stream::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    ec.clear();
    if (data.empty())
    {
        co_return 0;
    }
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return 0;
    }
    if (raw_write_mode_)
    {
        co_await connection_->write_raw(data, ec);
        co_return ec ? 0 : data.size();
    }
    if (outer_plain_write_mode_)
    {
        co_await connection_->write(data, ec);
        co_return ec ? 0 : data.size();
    }

    const auto segments = tracker_.process(write_direction_, data);
    for (const auto& segment : segments)
    {
        const auto mode = segment.cmd == vision::command::kContinue
                              ? (tracker_.tls13_confirmed() ? vision::padding_mode::kShort : vision::padding_mode::kLong)
                              : vision::padding_mode::kNone;
        std::vector<uint8_t> encoded;
        if (!vision::encode_block(segment.cmd, segment.content, mode, encoded, ec))
        {
            co_return 0;
        }
        co_await connection_->write(encoded, ec);
        if (ec)
        {
            co_return 0;
        }
        if (segment.switch_to_raw_after)
        {
            co_await connection_->enter_raw_write_mode(ec);
            if (ec)
            {
                co_return 0;
            }
            raw_write_mode_ = true;
        }
        if (segment.switch_to_outer_plain_after)
        {
            outer_plain_write_mode_ = true;
        }
    }
    co_return data.size();
}

boost::asio::awaitable<void> vision_connection_tcp_stream::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }
    co_await connection_->shutdown_send(ec);
}

boost::asio::awaitable<void> vision_connection_tcp_stream::close()
{
    if (connection_ != nullptr)
    {
        boost::system::error_code ec;
        connection_->close(ec);
    }
    reset();
    co_return;
}

vision_connection_stream_relay_transport::vision_connection_stream_relay_transport(std::shared_ptr<proxy_reality_connection> connection,
                                                                                   const config::timeout_t& timeout,
                                                                                   const vision::direction write_direction,
                                                                                   const vision::direction read_direction)
    : stream_(std::move(connection), write_direction, read_direction), timeout_(timeout)
{
}

boost::asio::awaitable<std::size_t> vision_connection_stream_relay_transport::read(std::span<uint8_t> buffer, boost::system::error_code& ec)
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

boost::asio::awaitable<std::size_t> vision_connection_stream_relay_transport::write(std::span<const uint8_t> data,
                                                                                    boost::system::error_code& ec)
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

boost::asio::awaitable<void> vision_connection_stream_relay_transport::shutdown_send(boost::system::error_code& ec)
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

boost::asio::awaitable<void> vision_connection_stream_relay_transport::close()
{
    co_await stream_.close();
    co_return;
}

}    // namespace relay
