#include <span>
#include <atomic>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>

#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "constants.h"
#include "mux_codec.h"
#include "mux_protocol.h"
namespace mux
{

namespace
{

std::atomic<uint64_t> g_decode_warn_total{0};
constexpr std::size_t kSynTraceIdSize = sizeof(uint64_t);

[[nodiscard]] uint64_t next_decode_warn_total() { return g_decode_warn_total.fetch_add(1, std::memory_order_relaxed) + 1; }

[[nodiscard]] bool should_log_decode_warn(uint64_t total)
{
    if (total <= 4)
    {
        return true;
    }
    return (total & (total - 1)) == 0;
}

[[nodiscard]] bool is_printable_ascii_text(const std::string_view value)
{
    if (value.size() > 255)
    {
        return false;
    }
    return std::ranges::all_of(value,
                               [](const char c)
                               {
                                   const auto uc = static_cast<unsigned char>(c);
                                   return uc >= 0x20 && uc <= 0x7e;
                               });
}

bool encode_addr_payload(uint8_t first_byte, std::string_view addr, uint16_t port, const char* payload_name, std::vector<uint8_t>& buf)
{
    if (!is_printable_ascii_text(addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage encode_addr_payload payload {} invalid_addr len {} warn_total {}",
                     log_event::kMuxFrame,
                     payload_name,
                     addr.size(),
                     warn_total);
        }
        return false;
    }

    buf.push_back(first_byte);
    const auto addr_len = static_cast<uint8_t>(addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), addr.begin(), addr.begin() + addr_len);
    buf.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(port & 0xFF));
    return true;
}

void encode_u64_be(const uint64_t value, std::vector<uint8_t>& buf)
{
    buf.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

[[nodiscard]] uint64_t decode_u64_be(const uint8_t* data)
{
    return (static_cast<uint64_t>(data[0]) << 56) | (static_cast<uint64_t>(data[1]) << 48) | (static_cast<uint64_t>(data[2]) << 40) |
           (static_cast<uint64_t>(data[3]) << 32) | (static_cast<uint64_t>(data[4]) << 24) | (static_cast<uint64_t>(data[5]) << 16) |
           (static_cast<uint64_t>(data[6]) << 8) | static_cast<uint64_t>(data[7]);
}

}    // namespace

void mux_codec::encode_header(const frame_header& h, std::vector<uint8_t>& buf)
{
    buf.push_back(static_cast<uint8_t>((h.stream_id >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((h.stream_id >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((h.stream_id >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(h.stream_id & 0xFF));

    buf.push_back(static_cast<uint8_t>((h.length >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(h.length & 0xFF));

    buf.push_back(h.command);
}

void mux_codec::decode_header(const uint8_t* buf, frame_header& out)
{
    out.stream_id = (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) | (static_cast<uint32_t>(buf[2]) << 8) |
                    (static_cast<uint32_t>(buf[3]));

    out.length = static_cast<uint16_t>((static_cast<uint16_t>(buf[4]) << 8) | static_cast<uint16_t>(buf[5]));
    out.command = buf[6];
}

std::vector<uint8_t> mux_codec::encode_frame(const frame_header& h, std::span<const uint8_t> payload)
{
    if (payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("event {} stage encode_frame payload_too_large size {} max {}", log_event::kMuxFrame, payload.size(), mux::kMaxPayload);
        return {};
    }

    std::vector<uint8_t> frame;
    frame.reserve(mux::kHeaderSize + payload.size());

    frame_header header = h;
    header.length = static_cast<uint16_t>(payload.size());
    encode_header(header, frame);

    if (!payload.empty())
    {
        frame.insert(frame.end(), payload.begin(), payload.end());
    }
    return frame;
}

void mux_codec::decode_frames(std::vector<uint8_t>& pending,
                              const std::span<const uint8_t> data,
                              std::size_t max_buffer,
                              std::vector<mux_frame>& frames,
                              boost::system::error_code& ec)
{
    if (data.empty())
    {
        return;
    }

    if (max_buffer > 0 && pending.size() + data.size() > max_buffer)
    {
        LOG_WARN("event {} stage decode_frames buffer_limit exceeded pending {} input {} max {}",
                 log_event::kMuxFrame,
                 pending.size(),
                 data.size(),
                 max_buffer);
        pending.clear();
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    pending.insert(pending.end(), data.begin(), data.end());

    std::size_t offset = 0;
    while (pending.size() - offset >= mux::kHeaderSize)
    {
        frame_header header;
        decode_header(pending.data() + static_cast<std::ptrdiff_t>(offset), header);
        if (header.length > mux::kMaxPayload)
        {
            LOG_WARN("event {} stage decode_frames invalid_header_len {} max {}", log_event::kMuxFrame, header.length, mux::kMaxPayload);
            pending.clear();
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return;
        }

        const std::size_t total_frame_len = mux::kHeaderSize + static_cast<std::size_t>(header.length);
        if (pending.size() - offset < total_frame_len)
        {
            break;
        }

        mux_frame frame;
        frame.h = header;
        if (header.length > 0)
        {
            const auto payload_begin = pending.begin() + static_cast<std::ptrdiff_t>(offset + mux::kHeaderSize);
            const auto payload_end = pending.begin() + static_cast<std::ptrdiff_t>(offset + total_frame_len);
            frame.payload.assign(payload_begin, payload_end);
        }
        frames.push_back(std::move(frame));
        offset += total_frame_len;
    }

    if (offset == 0)
    {
        return;
    }
    if (offset == pending.size())
    {
        pending.clear();
        return;
    }

    pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(offset));
}

bool mux_codec::encode_syn(const syn_payload& p, std::vector<uint8_t>& buf)
{
    if (!is_printable_ascii_text(p.addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage encode_addr_payload payload {} invalid_addr len {} warn_total {}",
                     log_event::kMuxFrame,
                     "syn",
                     p.addr.size(),
                     warn_total);
        }
        return false;
    }

    buf.push_back(p.socks_cmd);
    encode_u64_be(p.trace_id, buf);
    const auto addr_len = static_cast<uint8_t>(p.addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), p.addr.begin(), p.addr.begin() + addr_len);
    buf.push_back(static_cast<uint8_t>((p.port >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(p.port & 0xFF));
    return true;
}

bool mux_codec::decode_syn(const uint8_t* data, std::size_t len, syn_payload& out)
{
    if (len < 1 + kSynTraceIdSize + 1 + 2)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_syn payload_too_short size {} warn_total {}", log_event::kMuxFrame, len, warn_total);
        }
        return false;
    }
    out.socks_cmd = data[0];
    out.trace_id = decode_u64_be(data + 1);
    const uint8_t addr_len = data[1 + static_cast<std::ptrdiff_t>(kSynTraceIdSize)];
    if (len != 1 + kSynTraceIdSize + 1 + static_cast<std::size_t>(addr_len) + 2)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_syn invalid_len addr_len {} size {} warn_total {}", log_event::kMuxFrame, addr_len, len, warn_total);
        }
        return false;
    }
    const auto addr_offset = 1 + static_cast<std::ptrdiff_t>(kSynTraceIdSize) + 1;
    out.addr = std::string(reinterpret_cast<const char*>(data + addr_offset), addr_len);
    if (!is_printable_ascii_text(out.addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_syn invalid_addr_chars warn_total {}", log_event::kMuxFrame, warn_total);
        }
        return false;
    }
    const uint8_t* port_ptr = data + addr_offset + static_cast<std::ptrdiff_t>(addr_len);
    out.port = static_cast<uint16_t>((static_cast<uint16_t>(port_ptr[0]) << 8) | static_cast<uint16_t>(port_ptr[1]));
    return true;
}

bool mux_codec::encode_ack(const ack_payload& p, std::vector<uint8_t>& buf)
{
    return encode_addr_payload(p.socks_rep, p.bnd_addr, p.bnd_port, "ack", buf);
}

bool mux_codec::decode_ack(const uint8_t* data, std::size_t len, ack_payload& out)
{
    if (len < 4)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_ack payload_too_short size {} warn_total {}", log_event::kMuxFrame, len, warn_total);
        }
        return false;
    }
    out.socks_rep = data[0];
    const uint8_t addr_len = data[1];
    const std::size_t expected_len = 2 + static_cast<std::size_t>(addr_len) + 2;
    if (len != expected_len)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_ack invalid_len expected {} size {} warn_total {}", log_event::kMuxFrame, expected_len, len, warn_total);
        }
        return false;
    }
    out.bnd_addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
    if (!is_printable_ascii_text(out.bnd_addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("event {} stage decode_ack invalid_addr_chars warn_total {}", log_event::kMuxFrame, warn_total);
        }
        return false;
    }
    const uint8_t* port_ptr = &data[2 + addr_len];
    out.bnd_port = static_cast<uint16_t>((static_cast<uint16_t>(port_ptr[0]) << 8) | static_cast<uint16_t>(port_ptr[1]));
    return true;
}

}    // namespace mux
