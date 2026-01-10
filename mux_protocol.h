#ifndef MUX_PROTOCOL_H
#define MUX_PROTOCOL_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <boost/asio.hpp>
#include "log.h"

namespace mux
{

constexpr std::uint8_t CMD_SYN = 0x01;
constexpr std::uint8_t CMD_ACK = 0x02;
constexpr std::uint8_t CMD_DAT = 0x03;
constexpr std::uint8_t CMD_FIN = 0x04;
constexpr std::uint8_t CMD_RST = 0x05;

constexpr std::size_t HEADER_SIZE = 7;
constexpr std::size_t MAX_PAYLOAD = 16384;

struct frame_header
{
    std::uint32_t stream_id;
    std::uint16_t length;
    std::uint8_t command;

    void encode(std::uint8_t* buf) const
    {
        buf[0] = static_cast<std::uint8_t>((stream_id >> 24) & 0xFF);
        buf[1] = static_cast<std::uint8_t>((stream_id >> 16) & 0xFF);
        buf[2] = static_cast<std::uint8_t>((stream_id >> 8) & 0xFF);
        buf[3] = static_cast<std::uint8_t>(stream_id & 0xFF);

        buf[4] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
        buf[5] = static_cast<std::uint8_t>(length & 0xFF);

        buf[6] = command;
    }

    [[nodiscard]] static frame_header decode(const std::uint8_t* buf)
    {
        frame_header h;
        h.stream_id = (static_cast<std::uint32_t>(buf[0]) << 24) | (static_cast<std::uint32_t>(buf[1]) << 16) |
                      (static_cast<std::uint32_t>(buf[2]) << 8) | (static_cast<std::uint32_t>(buf[3]));

        h.length = (static_cast<std::uint16_t>(buf[4]) << 8) | (static_cast<std::uint16_t>(buf[5]));

        h.command = buf[6];
        return h;
    }
};

struct syn_payload
{
    std::uint8_t socks_cmd;
    std::string addr;
    std::uint16_t port;

    [[nodiscard]] std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_cmd);
        if (addr.size() > 255)
        {
            buf.push_back(static_cast<std::uint8_t>(255));
        }
        else
        {
            buf.push_back(static_cast<std::uint8_t>(addr.size()));
        }

        const std::size_t copy_len = std::min(addr.size(), std::size_t(255));
        buf.insert(buf.end(), addr.begin(), addr.begin() + copy_len);

        buf.push_back(static_cast<std::uint8_t>((port >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(port & 0xFF));
        return buf;
    }

    [[nodiscard]] static bool decode(const std::uint8_t* data, std::size_t len, syn_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("syn payload too short {}", len);
            return false;
        }
        out.socks_cmd = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("syn payload len invalid for addr_len {}", addr_len);
            return false;
        }
        out.addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.port = (static_cast<std::uint16_t>(port_ptr[0]) << 8) | port_ptr[1];
        return true;
    }
};

struct ack_payload
{
    std::uint8_t socks_rep;
    std::string bnd_addr;
    std::uint16_t bnd_port;

    [[nodiscard]] std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_rep);
        if (bnd_addr.size() > 255)
        {
            buf.push_back(0);
        }
        else
        {
            buf.push_back(static_cast<std::uint8_t>(bnd_addr.size()));
            buf.insert(buf.end(), bnd_addr.begin(), bnd_addr.end());
        }
        buf.push_back(static_cast<std::uint8_t>((bnd_port >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(bnd_port & 0xFF));
        return buf;
    }

    [[nodiscard]] static bool decode(const std::uint8_t* data, std::size_t len, ack_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("ack payload too short {}", len);
            return false;
        }
        out.socks_rep = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("ack payload len invalid for addr_len {}", addr_len);
            return false;
        }
        out.bnd_addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.bnd_port = (static_cast<std::uint16_t>(port_ptr[0]) << 8) | port_ptr[1];
        return true;
    }
};

}    // namespace mux

#endif
