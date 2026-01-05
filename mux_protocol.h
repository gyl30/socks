#ifndef MUX_PROTOCOL_H
#define MUX_PROTOCOL_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>
#include <boost/asio.hpp>

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
        buf[0] = (stream_id >> 24) & 0xFF;
        buf[1] = (stream_id >> 16) & 0xFF;
        buf[2] = (stream_id >> 8) & 0xFF;
        buf[3] = (stream_id) & 0xFF;

        buf[4] = (length >> 8) & 0xFF;
        buf[5] = (length) & 0xFF;

        buf[6] = command;
    }

    static frame_header decode(const std::uint8_t* buf)
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

    std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_cmd);
        if (addr.size() > 255)
            throw std::runtime_error("address too long");
        buf.push_back(static_cast<std::uint8_t>(addr.size()));
        buf.insert(buf.end(), addr.begin(), addr.end());
        buf.push_back((port >> 8) & 0xFF);
        buf.push_back(port & 0xFF);
        return buf;
    }

    static syn_payload decode(const std::uint8_t* data, std::size_t len)
    {
        if (len < 4)
            throw std::runtime_error("syn payload too short");
        syn_payload p;
        p.socks_cmd = data[0];
        std::uint8_t addr_len = data[1];
        if (len < 2 + addr_len + 2)
            throw std::runtime_error("syn payload invalid len");
        p.addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        p.port = (static_cast<std::uint16_t>(port_ptr[0]) << 8) | port_ptr[1];
        return p;
    }
};

struct ack_payload
{
    std::uint8_t socks_rep;
    std::string bnd_addr;
    std::uint16_t bnd_port;

    std::vector<std::uint8_t> encode() const
    {
        std::vector<std::uint8_t> buf;
        buf.push_back(socks_rep);
        if (bnd_addr.size() > 255)
            buf.push_back(0);
        else
        {
            buf.push_back(static_cast<std::uint8_t>(bnd_addr.size()));
            buf.insert(buf.end(), bnd_addr.begin(), bnd_addr.end());
        }
        buf.push_back((bnd_port >> 8) & 0xFF);
        buf.push_back(bnd_port & 0xFF);
        return buf;
    }

    static ack_payload decode(const std::uint8_t* data, std::size_t len)
    {
        if (len < 4)
            throw std::runtime_error("ack payload too short");
        ack_payload p;
        p.socks_rep = data[0];
        std::uint8_t addr_len = data[1];
        if (len < 2 + addr_len + 2)
            throw std::runtime_error("ack payload invalid len");
        p.bnd_addr = std::string(reinterpret_cast<const char*>(&data[2]), addr_len);
        const std::uint8_t* port_ptr = &data[2 + addr_len];
        p.bnd_port = (static_cast<std::uint16_t>(port_ptr[0]) << 8) | port_ptr[1];
        return p;
    }
};

}    // namespace mux

#endif
