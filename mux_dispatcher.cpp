#include <span>
#include <atomic>
#include <vector>
#include <limits>
#include <cstdint>
#include <cstring>
#include <utility>

#include <boost/asio/buffer.hpp>

#include "log.h"
#include "mux_codec.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"

namespace mux
{

mux_dispatcher::mux_dispatcher() : buffer_(std::numeric_limits<std::size_t>::max()) { LOG_DEBUG("mux dispatcher initialized"); }

void mux_dispatcher::set_callback(frame_callback_t cb) { callback_ = std::move(cb); }

void mux_dispatcher::set_context(connection_context ctx) { ctx_ = std::move(ctx); }

void mux_dispatcher::set_max_buffer(const std::size_t max_buffer) { max_buffer_ = max_buffer; }

void mux_dispatcher::set_fatal_error(const mux_dispatcher_fatal_reason reason)
{
    auto expected = mux_dispatcher_fatal_reason::kNone;
    (void)fatal_reason_.compare_exchange_strong(expected, reason, std::memory_order_acq_rel, std::memory_order_acquire);
}

void mux_dispatcher::on_plaintext_data(std::span<const std::uint8_t> data)
{
    if (has_fatal_error())
    {
        return;
    }

    if (data.empty())
    {
        return;
    }

    if (max_buffer_ > 0 && buffer_.size() + data.size() > max_buffer_)
    {
        LOG_CTX_ERROR(ctx_, "{} mux dispatcher buffer overflow", log_event::kMux);
        buffer_.consume(buffer_.size());
        overflowed_.store(true, std::memory_order_release);
        set_fatal_error(mux_dispatcher_fatal_reason::kBufferOverflow);
        return;
    }

    auto mutable_bufs = buffer_.prepare(data.size());
    const std::size_t n = boost::asio::buffer_copy(mutable_bufs, boost::asio::buffer(data.data(), data.size()));
    buffer_.commit(n);
    process_frames();
}

std::vector<std::uint8_t> mux_dispatcher::pack(std::uint32_t stream_id, std::uint8_t cmd, const std::vector<std::uint8_t>& payload)
{
    if (payload.size() > mux::kMaxPayloadPerRecord)
    {
        LOG_ERROR("mux dispatcher pack payload too large for single record {} max {}", payload.size(), mux::kMaxPayloadPerRecord);
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

void mux_dispatcher::process_frames()
{
    while (buffer_.size() >= mux::kHeaderSize)
    {
        const auto* ptr = static_cast<const std::uint8_t*>(buffer_.data().data());
        mux::frame_header header;
        if (!mux::mux_codec::decode_header(ptr, buffer_.size(), header))
        {
            break;
        }
        const std::uint32_t total_frame_len = mux::kHeaderSize + header.length;

        if (header.length > mux::kMaxPayloadPerRecord)
        {
            LOG_CTX_ERROR(ctx_, "{} received oversized frame length {} stream {}", log_event::kMux, header.length, header.stream_id);
            buffer_.consume(buffer_.size());
            set_fatal_error(mux_dispatcher_fatal_reason::kOversizedFrame);
            break;
        }

        if (buffer_.size() < total_frame_len)
        {
            break;
        }

        std::vector<std::uint8_t> payload(ptr + mux::kHeaderSize, ptr + total_frame_len);

        buffer_.consume(total_frame_len);

        if (callback_)
        {
            callback_(header, std::move(payload));
        }
    }
}

}    // namespace mux
