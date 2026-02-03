#include "mux_dispatcher.h"

#include "log.h"

mux_dispatcher::mux_dispatcher() : buffer_(64L * 1024) { LOG_DEBUG("mux dispatcher initialized"); }

void mux_dispatcher::set_callback(frame_callback_t cb) { callback_ = std::move(cb); }

void mux_dispatcher::set_context(connection_context ctx) { ctx_ = std::move(ctx); }

void mux_dispatcher::on_plaintext_data(std::span<const uint8_t> data)
{
    if (data.empty())
    {
        return;
    }

    auto mutable_bufs = buffer_.prepare(data.size());
    const size_t n = asio::buffer_copy(mutable_bufs, asio::buffer(data.data(), data.size()));
    buffer_.commit(n);

    process_frames();
}

std::vector<uint8_t> mux_dispatcher::pack(uint32_t stream_id, uint8_t cmd, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> frame;
    frame.reserve(mux::HEADER_SIZE + payload.size());

    const mux::frame_header h{.stream_id = stream_id, .length = static_cast<uint16_t>(payload.size()), .command = cmd};
    mux::mux_codec::encode_header(h, frame);

    if (!payload.empty())
    {
        frame.insert(frame.end(), payload.begin(), payload.end());
    }
    return frame;
}

void mux_dispatcher::process_frames()
{
    while (buffer_.size() >= mux::HEADER_SIZE)
    {
        const auto* ptr = static_cast<const uint8_t*>(buffer_.data().data());
        auto header = mux::mux_codec::decode_header(ptr);
        const uint32_t total_frame_len = mux::HEADER_SIZE + header.length;

        if (header.length > mux::MAX_PAYLOAD)
        {
            LOG_CTX_ERROR(ctx_, "{} received oversized frame length {} stream {}", log_event::MUX, header.length, header.stream_id);
            buffer_.consume(buffer_.size());
            break;
        }

        if (buffer_.size() < total_frame_len)
        {
            break;
        }

        std::vector<uint8_t> payload(ptr + mux::HEADER_SIZE, ptr + total_frame_len);

        buffer_.consume(total_frame_len);

        if (callback_)
        {
            callback_(header, std::move(payload));
        }
    }
}
