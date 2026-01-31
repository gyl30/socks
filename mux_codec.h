#ifndef MUX_CODEC_H
#define MUX_CODEC_H

#include <vector>
#include <string>
#include <cstring>

#include <openssl/x509.h>
#include "log.h"
#include "mux_protocol.h"

namespace mux
{
class mux_codec
{
   public:
    static void encode_header(const frame_header& h, std::vector<std::uint8_t>& buf)
    {
        buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 24) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((h.stream_id >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(h.stream_id & 0xFF));

        buf.push_back(static_cast<std::uint8_t>((h.length >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(h.length & 0xFF));

        buf.push_back(h.command);
    }

    [[nodiscard]] static frame_header decode_header(const std::uint8_t* buf)
    {
        frame_header h;
        h.stream_id = (static_cast<std::uint32_t>(buf[0]) << 24) | (static_cast<std::uint32_t>(buf[1]) << 16) |
                      (static_cast<std::uint32_t>(buf[2]) << 8) | (static_cast<std::uint32_t>(buf[3]));

        h.length = static_cast<uint16_t>((static_cast<std::uint16_t>(buf[4]) << 8) | static_cast<std::uint16_t>(buf[5]));
        h.command = buf[6];
        return h;
    }

    static void encode_syn(const syn_payload& p, std::vector<std::uint8_t>& buf)
    {
        buf.push_back(p.socks_cmd);

        const std::uint8_t addr_len = static_cast<std::uint8_t>(std::min(p.addr.size(), static_cast<std::size_t>(255)));
        buf.push_back(addr_len);
        buf.insert(buf.end(), p.addr.begin(), p.addr.begin() + addr_len);

        buf.push_back(static_cast<std::uint8_t>((p.port >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(p.port & 0xFF));

        const std::uint8_t trace_id_len = static_cast<std::uint8_t>(std::min(p.trace_id.size(), static_cast<std::size_t>(255)));
        buf.push_back(trace_id_len);
        if (trace_id_len > 0)
        {
            buf.insert(buf.end(), p.trace_id.begin(), p.trace_id.begin() + trace_id_len);
        }
    }

    [[nodiscard]] static bool decode_syn(const std::uint8_t* data, std::size_t len, syn_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("syn payload too short size {}", len);
            return false;
        }
        out.socks_cmd = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("syn payload length invalid for addr len {}", addr_len);
            return false;
        }
        out.addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.port = static_cast<uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));

        std::size_t current_pos = 2 + addr_len + 2;
        if (len > current_pos)
        {
            const std::uint8_t trace_id_len = data[current_pos];
            current_pos++;
            if (len >= current_pos + trace_id_len)
            {
                out.trace_id = std::string(reinterpret_cast<const char*>(&data[current_pos]), trace_id_len);
            }
        }
        return true;
    }

    static void encode_ack(const ack_payload& p, std::vector<std::uint8_t>& buf)
    {
        buf.push_back(p.socks_rep);

        const std::uint8_t addr_len = static_cast<std::uint8_t>(std::min(p.bnd_addr.size(), static_cast<std::size_t>(255)));
        buf.push_back(addr_len);
        buf.insert(buf.end(), p.bnd_addr.begin(), p.bnd_addr.begin() + addr_len);

        buf.push_back(static_cast<std::uint8_t>((p.bnd_port >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(p.bnd_port & 0xFF));
    }

    [[nodiscard]] static bool decode_ack(const std::uint8_t* data, std::size_t len, ack_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("ack payload too short size {}", len);
            return false;
        }
        out.socks_rep = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("ack payload length invalid for addr len {}", addr_len);
            return false;
        }
        out.bnd_addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.bnd_port = static_cast<uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));
        return true;
    }
};

}    // namespace mux

#endif
