#include <span>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstring>
#include <utility>

#include <asio/buffer.hpp>

#include "log.h"
#include "mux_codec.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_dispatcher.h"

namespace mux
{

mux_dispatcher::mux_dispatcher() : buffer_(64L * 1024) { LOG_DEBUG("mux dispatcher initialized"); }

void mux_dispatcher::set_callback(frame_callback_t cb) { callback_ = std::move(cb); }

void mux_dispatcher::set_context(connection_context ctx) { ctx_ = std::move(ctx); }

void mux_dispatcher::on_plaintext_data(std::span<const std::uint8_t> data)
{
    if (data.empty())
    {
        return;
    }

    auto mutable_bufs = buffer_.prepare(data.size());
    const std::size_t n = asio::buffer_copy(mutable_bufs, asio::buffer(data.data(), data.size()));
    buffer_.commit(n);

    process_frames();
}

std::vector<std::uint8_t> mux_dispatcher::pack(std::uint32_t stream_id, std::uint8_t cmd, const std::vector<std::uint8_t>& payload)
{
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

        if (header.length > mux::kMaxPayload)
        {
            LOG_CTX_ERROR(ctx_, "{} received oversized frame length {} stream {}", log_event::kMux, header.length, header.stream_id);
            buffer_.consume(buffer_.size());
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
