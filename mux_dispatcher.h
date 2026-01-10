#ifndef MUX_DISPATCHER_H
#define MUX_DISPATCHER_H

#include <functional>
#include <vector>
#include <cstring>
#include <boost/system/error_code.hpp>
#include "mux_protocol.h"
#include "log.h"

class MuxDispatcher
{
   public:
    using FrameCallback = std::function<void(mux::FrameHeader, std::vector<uint8_t>)>;

    MuxDispatcher() { LOG_DEBUG("MuxDispatcher initialized."); }

    void set_callback(FrameCallback cb) { callback_ = std::move(cb); }

    void on_plaintext_data(const std::vector<uint8_t>& data)
    {
        if (data.empty())
            return;
        buffer_.insert(buffer_.end(), data.begin(), data.end());

        while (buffer_.size() >= mux::HEADER_SIZE)
        {
            auto header = mux::FrameHeader::decode(buffer_.data());
            size_t total_frame_len = mux::HEADER_SIZE + header.length;

            if (total_frame_len > mux::MAX_PAYLOAD + mux::HEADER_SIZE)
            {
                LOG_ERROR("MuxDispatcher received oversized frame {}, stream {}", header.length, header.stream_id);
                buffer_.clear();
                break;
            }

            if (buffer_.size() < total_frame_len)
                break;

            std::vector<uint8_t> payload(buffer_.begin() + mux::HEADER_SIZE, buffer_.begin() + total_frame_len);
            buffer_.erase(buffer_.begin(), buffer_.begin() + total_frame_len);
            LOG_DEBUG("MuxDispatcher parsed frame: stream_id={}, cmd={}, length={}", header.stream_id, (int)header.command, header.length);

            if (callback_)
                callback_(header, std::move(payload));
        }
    }

    static std::vector<uint8_t> pack(uint32_t stream_id, uint8_t cmd, std::vector<uint8_t> payload)
    {
        std::vector<uint8_t> frame(mux::HEADER_SIZE + payload.size());
        mux::FrameHeader h{stream_id, static_cast<uint16_t>(payload.size()), cmd};
        h.encode(frame.data());
        std::memcpy(frame.data() + mux::HEADER_SIZE, payload.data(), payload.size());
        return frame;
    }

   private:
    std::vector<uint8_t> buffer_;
    FrameCallback callback_;
};

#endif
