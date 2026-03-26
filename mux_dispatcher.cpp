#include <span>
#include <array>
#include <vector>
#include <limits>
#include <cstdint>
#include <cstring>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "mux_codec.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"

namespace mux
{

mux_dispatcher::mux_dispatcher() : buffer_(std::numeric_limits<std::size_t>::max()) { LOG_DEBUG("mux dispatcher initialized"); }

void mux_dispatcher::set_context(connection_context ctx) { ctx_ = std::move(ctx); }

void mux_dispatcher::set_max_buffer(std::size_t max_buffer) { max_buffer_ = max_buffer; }

void mux_dispatcher::on_plaintext_data(std::span<const std::uint8_t> data, std::vector<mux_frame>& frames, boost::system::error_code& ec)
{
    ec.clear();
    if (data.empty())
    {
        return;
    }

    if (max_buffer_ > 0 && buffer_.size() + data.size() > max_buffer_)
    {
        LOG_CTX_ERROR(ctx_, "{} mux dispatcher buffer overflow", log_event::kMux);
        buffer_.consume(buffer_.size());
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    auto mutable_bufs = buffer_.prepare(data.size());
    const std::size_t n = boost::asio::buffer_copy(mutable_bufs, boost::asio::buffer(data.data(), data.size()));
    buffer_.commit(n);
    process_frames(frames, ec);
}

std::vector<std::uint8_t> mux_dispatcher::pack(std::uint32_t stream_id, std::uint8_t cmd, const std::vector<std::uint8_t>& payload)
{
    if (payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("mux dispatcher pack payload too large {} max {}", payload.size(), mux::kMaxPayload);
        return {};
    }

    std::vector<std::uint8_t> frame;
    frame.reserve(mux::kHeaderSize + payload.size());

    const mux::frame_header h{.stream_id = stream_id, .length = static_cast<std::uint16_t>(payload.size()), .command = cmd};
    mux::mux_codec::encode_header(h, frame);

    if (!payload.empty())
    {
        frame.insert(frame.end(), payload.begin(), payload.end());
    }
    return frame;
}

void mux_dispatcher::process_frames(std::vector<mux_frame>& frames, boost::system::error_code& ec)
{
    while (buffer_.size() >= mux::kHeaderSize)
    {
        const auto data_buffers = buffer_.data();
        std::array<std::uint8_t, mux::kHeaderSize> header_bytes{};
        if (boost::asio::buffer_copy(boost::asio::buffer(header_bytes), data_buffers) < mux::kHeaderSize)
        {
            break;
        }
        mux::frame_header header;
        if (!mux::mux_codec::decode_header(header_bytes.data(), header_bytes.size(), header))
        {
            LOG_CTX_ERROR(ctx_, "{} mux dispatcher invalid header", log_event::kMux);
            buffer_.consume(buffer_.size());
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            break;
        }
        const std::uint32_t total_frame_len = mux::kHeaderSize + header.length;

        if (header.length > mux::kMaxPayload)
        {
            LOG_CTX_ERROR(ctx_, "{} received oversized frame length {} stream {}", log_event::kMux, header.length, header.stream_id);
            buffer_.consume(buffer_.size());
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            break;
        }

        if (buffer_.size() < total_frame_len)
        {
            break;
        }

        std::vector<std::uint8_t> frame_bytes(total_frame_len);
        if (boost::asio::buffer_copy(boost::asio::buffer(frame_bytes), data_buffers) < total_frame_len)
        {
            break;
        }

        std::vector<std::uint8_t> payload;
        if (header.length > 0)
        {
            payload.assign(frame_bytes.begin() + static_cast<std::vector<std::uint8_t>::difference_type>(mux::kHeaderSize), frame_bytes.end());
        }

        buffer_.consume(total_frame_len);

        mux_frame frame;
        frame.h = header;
        frame.payload = std::move(payload);
        frames.push_back(std::move(frame));
    }
}

}    // namespace mux
