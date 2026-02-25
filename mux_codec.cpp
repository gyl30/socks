#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <atomic>

#include "log.h"
#include "mux_codec.h"
#include "mux_protocol.h"

namespace mux
{

namespace
{

std::atomic<std::uint64_t> g_decode_warn_total{0};

[[nodiscard]] std::uint64_t next_decode_warn_total() { return g_decode_warn_total.fetch_add(1, std::memory_order_relaxed) + 1; }

[[nodiscard]] bool should_log_decode_warn(const std::uint64_t total)
{
    if (total <= 4)
    {
        return true;
    }
    return (total & (total - 1)) == 0;
}

}    // namespace

void mux_codec::encode_header(const frame_header& h, std::vector<std::uint8_t>& buf)
{
    buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(h.stream_id & 0xFF));

    buf.push_back(static_cast<std::uint8_t>((h.length >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(h.length & 0xFF));

    buf.push_back(h.command);
}

bool mux_codec::decode_header(const std::uint8_t* buf, std::size_t len, frame_header& out)
{
    if (len < 7)
    {
        return false;
    }
    out.stream_id = (static_cast<std::uint32_t>(buf[0]) << 24) | (static_cast<std::uint32_t>(buf[1]) << 16) |
                    (static_cast<std::uint32_t>(buf[2]) << 8) | (static_cast<std::uint32_t>(buf[3]));

    out.length = static_cast<std::uint16_t>((static_cast<std::uint16_t>(buf[4]) << 8) | static_cast<std::uint16_t>(buf[5]));
    out.command = buf[6];
    return true;
}

bool mux_codec::encode_syn(const syn_payload& p, std::vector<std::uint8_t>& buf)
{
    if (p.addr.size() > 255 || p.trace_id.size() > 255)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("syn payload encode length invalid addr {} trace {} warn_total {}", p.addr.size(), p.trace_id.size(), warn_total);
        }
        return false;
    }
    buf.push_back(p.socks_cmd);

    const auto addr_len = static_cast<std::uint8_t>(p.addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), p.addr.begin(), p.addr.begin() + addr_len);

    buf.push_back(static_cast<std::uint8_t>((p.port >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(p.port & 0xFF));

    const auto trace_id_len = static_cast<std::uint8_t>(p.trace_id.size());
    buf.push_back(trace_id_len);
    if (trace_id_len > 0)
    {
        buf.insert(buf.end(), p.trace_id.begin(), p.trace_id.begin() + trace_id_len);
    }
    return true;
}

bool mux_codec::decode_syn(const std::uint8_t* data, const std::size_t len, syn_payload& out)
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
    const std::uint8_t addr_len = data[1];
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
    const std::uint8_t* port_ptr = &data[2 + addr_len];
    out.port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));

    std::size_t current_pos = 2 + addr_len + 2;
    if (len == current_pos)
    {
        return true;
    }

    const std::uint8_t trace_id_len = data[current_pos];
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
    return true;
}

bool mux_codec::encode_ack(const ack_payload& p, std::vector<std::uint8_t>& buf)
{
    if (p.bnd_addr.size() > 255)
    {
        const auto warn_total = next_decode_warn_total();
        if (should_log_decode_warn(warn_total))
        {
            LOG_WARN("ack payload encode length invalid addr {} warn_total {}", p.bnd_addr.size(), warn_total);
        }
        return false;
    }
    buf.push_back(p.socks_rep);

    const auto addr_len = static_cast<std::uint8_t>(p.bnd_addr.size());
    buf.push_back(addr_len);
    buf.insert(buf.end(), p.bnd_addr.begin(), p.bnd_addr.begin() + addr_len);

    buf.push_back(static_cast<std::uint8_t>((p.bnd_port >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(p.bnd_port & 0xFF));
    return true;
}

bool mux_codec::decode_ack(const std::uint8_t* data, const std::size_t len, ack_payload& out)
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
    const std::uint8_t addr_len = data[1];
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
    const std::uint8_t* port_ptr = &data[2 + addr_len];
    out.bnd_port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));
    return true;
}

}    // namespace mux
