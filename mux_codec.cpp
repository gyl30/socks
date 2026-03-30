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
#include "mux_codec.h"
#include "mux_protocol.h"

namespace mux
{

namespace
{

std::atomic<uint64_t> g_decode_warn_total{0};

[[nodiscard]] uint64_t next_decode_warn_total() { return g_decode_warn_total.fetch_add(1, std::memory_order_relaxed) + 1; }

[[nodiscard]] bool should_log_decode_warn(const uint64_t total)
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
    out.stream_id = (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) |
                    (static_cast<uint32_t>(buf[2]) << 8) | (static_cast<uint32_t>(buf[3]));

    out.length = static_cast<uint16_t>((static_cast<uint16_t>(buf[4]) << 8) | static_cast<uint16_t>(buf[5]));
    out.command = buf[6];
}

std::vector<uint8_t> mux_codec::encode_frame(const frame_header& h, std::span<const uint8_t> payload)
{
    if (payload.size() > mux::kMaxPayload)
    {
        LOG_ERROR("mux frame encode payload too large {} max {}", payload.size(), mux::kMaxPayload);
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
                              const std::size_t max_buffer,
                              std::vector<mux_frame>& frames,
                              boost::system::error_code& ec)
{
    if (data.empty())
    {
        return;
    }

    if (max_buffer > 0 && pending.size() + data.size() > max_buffer)
    {
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
    if (!is_printable_ascii_text(p.addr) || !is_printable_ascii_text(p.trace_id))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload encode invalid field addr_len {} trace_len {} warn_total {}", p.addr.size(), p.trace_id.size(), warn_total);
        }
        return false;
    }
    buf.push_back(p.socks_cmd);

    const auto addr_len = static_cast<uint8_t>(p.addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), p.addr.begin(), p.addr.begin() + addr_len);

    buf.push_back(static_cast<uint8_t>((p.port >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(p.port & 0xFF));

    const auto trace_id_len = static_cast<uint8_t>(p.trace_id.size());
    buf.push_back(trace_id_len);
    if (trace_id_len > 0)
    {
        buf.insert(buf.end(), p.trace_id.begin(), p.trace_id.begin() + trace_id_len);
    }
    return true;
}

bool mux_codec::decode_syn(const uint8_t* data, const std::size_t len, syn_payload& out)
{
    if (len < 4)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload too short size {} warn_total {}", len, warn_total);
        }
        return false;
    }
    out.socks_cmd = data[0];
    out.trace_id.clear();
    const uint8_t addr_len = data[1];
    if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload length invalid for addr len {} warn_total {}", addr_len, warn_total);
        }
        return false;
    }
    out.addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
    if (!is_printable_ascii_text(out.addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload contains invalid chars in addr warn_total {}", warn_total);
        }
        return false;
    }
    const uint8_t* port_ptr = &data[2 + addr_len];
    out.port = static_cast<uint16_t>((static_cast<uint16_t>(port_ptr[0]) << 8) | static_cast<uint16_t>(port_ptr[1]));

    std::size_t current_pos = 2 + addr_len + 2;
    if (len == current_pos)
    {
        return true;
    }

    const uint8_t trace_id_len = data[current_pos];
    current_pos++;
    const std::size_t expected_len = current_pos + trace_id_len;
    if (len != expected_len)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload length invalid expected {} got {} warn_total {}", expected_len, len, warn_total);
        }
        return false;
    }
    out.trace_id = std::string(reinterpret_cast<const char*>(&data[current_pos]), trace_id_len);
    if (!is_printable_ascii_text(out.trace_id))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload contains invalid chars in trace id warn_total {}", warn_total);
        }
        return false;
    }
    return true;
}

bool mux_codec::encode_ack(const ack_payload& p, std::vector<uint8_t>& buf)
{
    if (!is_printable_ascii_text(p.bnd_addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("ack payload encode invalid addr len {} warn_total {}", p.bnd_addr.size(), warn_total);
        }
        return false;
    }
    buf.push_back(p.socks_rep);

    const auto addr_len = static_cast<uint8_t>(p.bnd_addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), p.bnd_addr.begin(), p.bnd_addr.begin() + addr_len);

    buf.push_back(static_cast<uint8_t>((p.bnd_port >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(p.bnd_port & 0xFF));
    return true;
}

bool mux_codec::decode_ack(const uint8_t* data, const std::size_t len, ack_payload& out)
{
    if (len < 4)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("ack payload too short size {} warn_total {}", len, warn_total);
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
            LOG_WARN("ack payload length invalid expected {} got {} warn_total {}", expected_len, len, warn_total);
        }
        return false;
    }
    out.bnd_addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
    if (!is_printable_ascii_text(out.bnd_addr))
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("ack payload contains invalid chars in addr warn_total {}", warn_total);
        }
        return false;
    }
    const uint8_t* port_ptr = &data[2 + addr_len];
    out.bnd_port = static_cast<uint16_t>((static_cast<uint16_t>(port_ptr[0]) << 8) | static_cast<uint16_t>(port_ptr[1]));
    return true;
}

}    // namespace mux
