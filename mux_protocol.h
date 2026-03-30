#ifndef MUX_PROTOCOL_H
#define MUX_PROTOCOL_H

#include <string>
#include <vector>
#include <limits>
#include <cstddef>

#include "tls/core.h"

namespace mux
{
constexpr uint8_t kCmdSyn = 0x01;
constexpr uint8_t kCmdAck = 0x02;
constexpr uint8_t kCmdDat = 0x03;
constexpr uint8_t kCmdFin = 0x04;
constexpr uint8_t kCmdRst = 0x05;
constexpr uint8_t kNoStreamControl = 0x00;

constexpr uint32_t kStreamIdHeartbeat = 0;

constexpr std::size_t kHeaderSize = 7;
constexpr std::size_t kMaxPayload = static_cast<std::size_t>(std::numeric_limits<uint16_t>::max());
constexpr std::size_t kMaxPayloadPerRecord = tls::kMaxTlsApplicationDataPayloadLen - kHeaderSize;

struct frame_header
{
    uint32_t stream_id = 0;
    uint16_t length = 0;
    uint8_t command = 0;
};

struct mux_frame
{
    frame_header h;
    std::vector<uint8_t> payload;
};

struct syn_payload
{
    uint8_t socks_cmd = 0;
    std::string addr;
    uint16_t port = 0;
    std::string trace_id;
};

struct ack_payload
{
    uint8_t socks_rep = 0;
    std::string bnd_addr;
    uint16_t bnd_port = 0;
};

}    // namespace mux

#endif
