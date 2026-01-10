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
    std::uint32_t stream_id_ = 0;
    std::uint16_t length_ = 0;
    std::uint8_t command_ = 0;

    void encode(std::uint8_t* buf) const
    {
        buf[0] = static_cast<std::uint8_t>((stream_id_ >> 24) & 0xFF);
        buf[1] = static_cast<std::uint8_t>((stream_id_ >> 16) & 0xFF);
        buf[2] = static_cast<std::uint8_t>((stream_id_ >> 8) & 0xFF);
        buf[3] = static_cast<std::uint8_t>(stream_id_ & 0xFF);

        buf[4] = static_cast<std::uint8_t>((length_ >> 8) & 0xFF);
        buf[5] = static_cast<std::uint8_t>(length_ & 0xFF);

        buf[6] = command_;
    }

    [[nodiscard]] static frame_header decode(const std::uint8_t* buf)
    {
        frame_header h;
        h.stream_id_ = (static_cast<std::uint32_t>(buf[0]) << 24) | (static_cast<std::uint32_t>(buf[1]) << 16) |
                       (static_cast<std::uint32_t>(buf[2]) << 8) | (static_cast<std::uint32_t>(buf[3]));

        h.length_ = static_cast<uint16_t>((static_cast<std::uint16_t>(buf[4]) << 8) | static_cast<std::uint16_t>(buf[5]));

        h.command_ = buf[6];
        return h;
    }
};

struct syn_payload
{
    std::uint8_t socks_cmd_ = 0;
    std::string addr_;
    std::uint16_t port_ = 0;

    [[nodiscard]] std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_cmd_);

        const std::uint8_t addr_len = static_cast<std::uint8_t>(std::min(addr_.size(), std::size_t(255)));
        buf.push_back(addr_len);
        buf.insert(buf.end(), addr_.begin(), addr_.begin() + addr_len);

        buf.push_back(static_cast<std::uint8_t>((port_ >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(port_ & 0xFF));
        return buf;
    }

    [[nodiscard]] static bool decode(const std::uint8_t* data, std::size_t len, syn_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("syn payload too short size {}", len);
            return false;
        }
        out.socks_cmd_ = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("syn payload length invalid for addr len {}", addr_len);
            return false;
        }
        out.addr_ = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.port_ = static_cast<uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));
        return true;
    }
};

struct ack_payload
{
    std::uint8_t socks_rep_ = 0;
    std::string bnd_addr_;
    std::uint16_t bnd_port_ = 0;

    [[nodiscard]] std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_rep_);

        const std::uint8_t addr_len = static_cast<std::uint8_t>(std::min(bnd_addr_.size(), std::size_t(255)));
        buf.push_back(addr_len);
        buf.insert(buf.end(), bnd_addr_.begin(), bnd_addr_.begin() + addr_len);

        buf.push_back(static_cast<std::uint8_t>((bnd_port_ >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(bnd_port_ & 0xFF));
        return buf;
    }

    [[nodiscard]] static bool decode(const std::uint8_t* data, std::size_t len, ack_payload& out)
    {
        if (len < 4)
        {
            LOG_WARN("ack payload too short size {}", len);
            return false;
        }
        out.socks_rep_ = data[0];
        const std::uint8_t addr_len = data[1];
        if (len < 2 + static_cast<std::size_t>(addr_len) + 2)
        {
            LOG_WARN("ack payload length invalid for addr len {}", addr_len);
            return false;
        }
        out.bnd_addr_ = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        out.bnd_port_ = static_cast<uint16_t>((static_cast<std::uint16_t>(port_ptr[0]) << 8) | static_cast<std::uint16_t>(port_ptr[1]));
        return true;
    }
};
}    // namespace mux

#endif
