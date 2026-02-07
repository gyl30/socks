#ifndef MUX_PROTOCOL_H
#define MUX_PROTOCOL_H

#include <string>
#include <cstddef>
#include <cstdint>

namespace mux
{
constexpr std::uint8_t kCmdSyn = 0x01;
constexpr std::uint8_t kCmdAck = 0x02;
constexpr std::uint8_t kCmdDat = 0x03;
constexpr std::uint8_t kCmdFin = 0x04;
constexpr std::uint8_t kCmdRst = 0x05;

constexpr std::uint32_t kStreamIdHeartbeat = 0;

constexpr std::size_t kHeaderSize = 7;
constexpr std::size_t kMaxPayload = (64L * 1024) - 128;

struct frame_header
{
    std::uint32_t stream_id = 0;
    std::uint16_t length = 0;
    std::uint8_t command = 0;
};

struct syn_payload
{
    std::uint8_t socks_cmd = 0;
    std::string addr;
    std::uint16_t port = 0;
    std::string trace_id;
};

struct ack_payload
{
    std::uint8_t socks_rep = 0;
    std::string bnd_addr;
    std::uint16_t bnd_port = 0;
};

}    // namespace mux

#endif
