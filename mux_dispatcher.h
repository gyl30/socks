#ifndef MUX_DISPATCHER_H
#define MUX_DISPATCHER_H

#include <functional>
#include <vector>
#include <cstring>
#include "mux_protocol.h"
#include "log.h"

class mux_dispatcher
{
   public:
    using frame_callback_t = std::function<void(mux::frame_header, std::vector<uint8_t>)>;

    mux_dispatcher()
    {
        buffer_.reserve(8192);
        LOG_DEBUG("mux dispatcher initialized");
    }

    void set_callback(frame_callback_t cb) { callback_ = std::move(cb); }

    void on_plaintext_data(const std::vector<uint8_t>& data)
    {
        if (data.empty())
        {
            return;
        }
        buffer_.insert(buffer_.end(), data.begin(), data.end());

        while (buffer_.size() - read_pos_ >= mux::HEADER_SIZE)
        {
            const uint8_t* ptr = buffer_.data() + read_pos_;
            auto header = mux::frame_header::decode(ptr);
            const uint32_t total_frame_len = mux::HEADER_SIZE + header.length_;

            if (header.length_ > mux::MAX_PAYLOAD)
            {
                LOG_ERROR("mux dispatcher received oversized frame length {} stream {}", header.length_, header.stream_id_);
                buffer_.clear();
                read_pos_ = 0;
                break;
            }

            if (buffer_.size() - read_pos_ < total_frame_len)
            {
                break;
            }

            std::vector<uint8_t> payload(buffer_.begin() + read_pos_ + mux::HEADER_SIZE, buffer_.begin() + read_pos_ + total_frame_len);

            read_pos_ += total_frame_len;

            LOG_DEBUG("mux dispatcher parsed frame stream {} cmd {} length {}", header.stream_id_, static_cast<int>(header.command_), header.length_);

            if (callback_)
            {
                callback_(header, std::move(payload));
            }
        }

        if (read_pos_ > 4096)
        {
            const size_t remaining = buffer_.size() - read_pos_;
            if (remaining > 0)
            {
                std::memmove(buffer_.data(), buffer_.data() + read_pos_, remaining);
            }
            buffer_.resize(remaining);
            read_pos_ = 0;
        }
    }

    [[nodiscard]] static std::vector<uint8_t> pack(uint32_t stream_id, uint8_t cmd, const std::vector<uint8_t>& payload)
    {
        std::vector<uint8_t> frame(mux::HEADER_SIZE + payload.size());
        const mux::frame_header h{stream_id, static_cast<uint16_t>(payload.size()), cmd};
        h.encode(frame.data());
        if (!payload.empty())
        {
            std::memcpy(frame.data() + mux::HEADER_SIZE, payload.data(), payload.size());
        }
        return frame;
    }

   private:
    uint32_t read_pos_ = 0;
    frame_callback_t callback_;
    std::vector<uint8_t> buffer_;
};

#endif
