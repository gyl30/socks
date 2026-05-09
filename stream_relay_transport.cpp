#include <mutex>
#include <cstdint>
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
        co_await connection_->async_close(ec);
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

void vision_connection_tcp_stream::clear_state_locked()
{
    parser_ = vision::block_parser{};
    tracker_ = vision::tls_tracker{};
    pending_read_data_.clear();
    pending_read_offset_ = 0;
    pending_read_switch_ = pending_read_switch::kNone;
    read_mode_ = read_mode::kVision;
    write_mode_ = write_mode::kVision;
    first_continue_padding_ = true;
}

void vision_connection_tcp_stream::finalize_pending_read_step_locked(read_step& step, boost::system::error_code& ec)
{
    if (!pending_read_data_.empty())
    {
        step.action = read_action::kReturn;
        return;
    }

    if (pending_read_switch_ == pending_read_switch::kRaw)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            return;
        }
        pending_read_switch_ = pending_read_switch::kNone;
        step.action = read_action::kEnterRawThenReturn;
        return;
    }

    if (pending_read_switch_ == pending_read_switch::kOuterReality)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            return;
        }
        pending_read_switch_ = pending_read_switch::kNone;
        read_mode_ = read_mode::kOuterReality;
    }

    step.action = read_action::kReturn;
}

void vision_connection_tcp_stream::plan_pending_read_step_locked(read_step& step,
                                                                 const std::span<uint8_t> buffer,
                                                                 boost::system::error_code& ec)
{
    step.bytes = consume_pending_read_data(pending_read_data_, pending_read_offset_, buffer);
    finalize_pending_read_step_locked(step, ec);
}

void vision_connection_tcp_stream::plan_parsed_read_step_locked(vision::block parsed,
                                                                read_step& step,
                                                                const std::span<uint8_t> buffer,
                                                                boost::system::error_code& ec)
{
    if (!parsed.content.empty())
    {
        tracker_.observe(read_direction_, parsed.content);
        pending_read_data_ = std::move(parsed.content);
        pending_read_offset_ = 0;
        if (parsed.cmd == vision::command::kDirect)
        {
            pending_read_switch_ = pending_read_switch::kRaw;
        }
        else if (parsed.cmd == vision::command::kEnd)
        {
            pending_read_switch_ = pending_read_switch::kOuterReality;
        }
        else
        {
            pending_read_switch_ = pending_read_switch::kNone;
        }
        plan_pending_read_step_locked(step, buffer, ec);
        return;
    }

    if (parsed.cmd == vision::command::kDirect)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            return;
        }
        step.action = read_action::kEnterRawThenReadRaw;
        return;
    }

    if (parsed.cmd == vision::command::kEnd)
    {
        if (!parser_.empty())
        {
            ec = boost::asio::error::invalid_argument;
            return;
        }
        read_mode_ = read_mode::kOuterReality;
        step.action = read_action::kReadOuter;
        return;
    }

    step.action = read_action::kReadOuterBlock;
}

vision_connection_tcp_stream::read_step vision_connection_tcp_stream::plan_read_step_locked(
    const std::span<uint8_t> buffer, boost::system::error_code& ec)
{
    read_step step;
    step.connection = connection_;
    step.generation = generation_;

    if (!pending_read_data_.empty())
    {
        plan_pending_read_step_locked(step, buffer, ec);
        return step;
    }

    if (read_mode_ == read_mode::kRaw)
    {
        step.action = read_action::kReadRaw;
        return step;
    }

    if (read_mode_ == read_mode::kOuterReality)
    {
        step.action = read_action::kReadOuter;
        return step;
    }

    vision::block parsed;
    const auto status = parser_.next(parsed, ec);
    if (status == vision::parse_status::kError)
    {
        return step;
    }
    if (status == vision::parse_status::kNeedMore)
    {
        step.action = read_action::kReadOuterBlock;
        return step;
    }

    plan_parsed_read_step_locked(std::move(parsed), step, buffer, ec);
    return step;
}

bool vision_connection_tcp_stream::validate_generation_locked(const std::shared_ptr<proxy_reality_connection>& connection,
                                                              const uint64_t generation,
                                                              boost::system::error_code& ec) const
{
    if (generation_ == generation && connection_ == connection)
    {
        return true;
    }
    ec = boost::asio::error::operation_aborted;
    return false;
}

void vision_connection_tcp_stream::capture_write_plan_locked(std::span<const uint8_t> data,
                                                             std::shared_ptr<proxy_reality_connection>& connection,
                                                             uint64_t& generation,
                                                             write_action& action,
                                                             std::vector<encoded_segment>& segments,
                                                             boost::system::error_code& ec)
{
    if (connection_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        return;
    }

    connection = connection_;
    generation = generation_;

    if (write_mode_ == write_mode::kRaw)
    {
        action = write_action::kRaw;
        return;
    }

    if (write_mode_ == write_mode::kOuterReality)
    {
        action = write_action::kOuter;
        return;
    }

    const auto processed_segments = tracker_.process(write_direction_, data);
    segments.reserve(processed_segments.size());
    for (const auto& segment : processed_segments)
    {
        auto mode = vision::padding_mode::kNone;
        if (segment.cmd == vision::command::kContinue)
        {
            mode = vision::next_continue_padding_mode(first_continue_padding_);
        }
        segments.push_back(encoded_segment{
            .segment = segment,
            .mode = mode,
        });
    }
}

void vision_connection_tcp_stream::reset(std::shared_ptr<proxy_reality_connection> connection,
                                         const vision::direction write_direction,
                                         const vision::direction read_direction)
{
    std::scoped_lock lock(mutex_);
    connection_ = std::move(connection);
    clear_state_locked();
    write_direction_ = write_direction;
    read_direction_ = read_direction;
    generation_++;
}

bool vision_connection_tcp_stream::has_connection() const
{
    std::scoped_lock lock(mutex_);
    return connection_ != nullptr;
}

boost::asio::awaitable<std::size_t> vision_connection_tcp_stream::read_outer_reality(std::shared_ptr<proxy_reality_connection> connection,
                                                                                     std::span<uint8_t> buffer,
                                                                                     const uint32_t read_timeout,
                                                                                     boost::system::error_code& ec)
{
    std::vector<uint8_t> outer_buffer(buffer.size());
    const auto bytes_read = co_await connection->read_some(outer_buffer, read_timeout, ec);
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

    for (;;)
    {
        read_step step;
        {
            std::scoped_lock lock(mutex_);
            if (connection_ == nullptr)
            {
                ec = boost::asio::error::not_connected;
                co_return 0;
            }
            step = plan_read_step_locked(buffer, ec);
        }
        if (ec)
        {
            co_return 0;
        }

        if (step.action == read_action::kReturn)
        {
            co_return step.bytes;
        }
        if (step.action == read_action::kReadRaw)
        {
            const auto bytes_read = co_await step.connection->read_raw(buffer, read_timeout, ec);
            {
                std::scoped_lock lock(mutex_);
                if (!validate_generation_locked(step.connection, step.generation, ec))
                {
                    co_return 0;
                }
            }
            co_return bytes_read;
        }
        if (step.action == read_action::kReadOuter)
        {
            const auto bytes_read = co_await read_outer_reality(step.connection, buffer, read_timeout, ec);
            {
                std::scoped_lock lock(mutex_);
                if (!validate_generation_locked(step.connection, step.generation, ec))
                {
                    co_return 0;
                }
            }
            co_return bytes_read;
        }
        if (step.action == read_action::kReadOuterBlock)
        {
            std::vector<uint8_t> outer_buffer(buffer.size());
            const auto bytes_read = co_await step.connection->read_some(outer_buffer, read_timeout, ec);
            if (ec)
            {
                co_return 0;
            }
            {
                std::scoped_lock lock(mutex_);
                if (!validate_generation_locked(step.connection, step.generation, ec))
                {
                    co_return 0;
                }
                parser_.append(std::span<const uint8_t>(outer_buffer.data(), bytes_read));
            }
            continue;
        }

        co_await step.connection->enter_raw_read_mode(ec);
        if (ec)
        {
            co_return step.bytes;
        }
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(step.connection, step.generation, ec))
            {
                co_return step.bytes;
            }
            read_mode_ = read_mode::kRaw;
        }
        if (step.action == read_action::kEnterRawThenReturn)
        {
            if (step.bytes < buffer.size())
            {
                const auto pending_raw_bytes = co_await step.connection->read_raw_pending(buffer.subspan(step.bytes));
                co_return step.bytes + pending_raw_bytes;
            }
            co_return step.bytes;
        }
        const auto bytes_read = co_await step.connection->read_raw(buffer, read_timeout, ec);
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(step.connection, step.generation, ec))
            {
                co_return 0;
            }
        }
        co_return bytes_read;
    }
}

boost::asio::awaitable<std::size_t> vision_connection_tcp_stream::write(std::span<const uint8_t> data, boost::system::error_code& ec)
{
    ec.clear();
    if (data.empty())
    {
        co_return 0;
    }
    std::shared_ptr<proxy_reality_connection> connection;
    uint64_t generation = 0;
    write_action action = write_action::kSegments;
    std::vector<encoded_segment> segments;
    {
        std::scoped_lock lock(mutex_);
        capture_write_plan_locked(data, connection, generation, action, segments, ec);
    }
    if (ec)
    {
        co_return 0;
    }

    if (action == write_action::kRaw)
    {
        co_await connection->write_raw(data, ec);
        if (!ec)
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(connection, generation, ec))
            {
                co_return 0;
            }
        }
        co_return ec ? 0 : data.size();
    }
    if (action == write_action::kOuter)
    {
        co_await connection->write(data, ec);
        if (!ec)
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(connection, generation, ec))
            {
                co_return 0;
            }
        }
        co_return ec ? 0 : data.size();
    }

    for (const auto& item : segments)
    {
        std::vector<uint8_t> encoded;
        if (!vision::encode_block(item.segment.cmd, item.segment.content, item.mode, encoded, ec))
        {
            co_return 0;
        }
        co_await connection->write(encoded, ec);
        if (ec)
        {
            co_return 0;
        }
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(connection, generation, ec))
            {
                co_return 0;
            }
        }
        if (item.segment.switch_to_raw_after)
        {
            co_await connection->enter_raw_write_mode(ec);
            if (ec)
            {
                co_return 0;
            }
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(connection, generation, ec))
            {
                co_return 0;
            }
            write_mode_ = write_mode::kRaw;
        }
        if (item.segment.switch_to_outer_reality_after)
        {
            std::scoped_lock lock(mutex_);
            if (!validate_generation_locked(connection, generation, ec))
            {
                co_return 0;
            }
            write_mode_ = write_mode::kOuterReality;
        }
    }
    co_return data.size();
}

boost::asio::awaitable<void> vision_connection_tcp_stream::shutdown_send(boost::system::error_code& ec)
{
    ec.clear();
    std::shared_ptr<proxy_reality_connection> connection;
    {
        std::scoped_lock lock(mutex_);
        connection = connection_;
    }
    if (connection == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }
    co_await connection->shutdown_send(ec);
}

boost::asio::awaitable<void> vision_connection_tcp_stream::close()
{
    std::shared_ptr<proxy_reality_connection> connection;
    {
        std::scoped_lock lock(mutex_);
        connection = std::move(connection_);
        connection_.reset();
        clear_state_locked();
        generation_++;
    }
    if (connection != nullptr)
    {
        boost::system::error_code ec;
        co_await connection->async_close(ec);
    }
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
