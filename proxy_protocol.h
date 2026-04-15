#ifndef PROXY_PROTOCOL_H
#define PROXY_PROTOCOL_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace relay::proxy
{

constexpr uint32_t kMaxPacketSize = 1024U * 1024U;

enum class message_type : uint8_t
{
    kTcpConnectRequest = 0x01,
    kTcpConnectReply = 0x02,
    kUdpAssociateRequest = 0x03,
    kUdpAssociateReply = 0x04,
    kUdpDatagram = 0x05,
};

struct tcp_connect_request
{
    std::string target_host;
    uint16_t target_port = 0;
    uint64_t trace_id = 0;
};

struct tcp_connect_reply
{
    uint8_t socks_rep = 0;
    std::string bind_host;
    uint16_t bind_port = 0;
};

struct udp_associate_request
{
    uint64_t trace_id = 0;
};

struct udp_associate_reply
{
    uint8_t socks_rep = 0;
    std::string bind_host;
    uint16_t bind_port = 0;
};

struct udp_datagram
{
    std::string target_host;
    uint16_t target_port = 0;
    std::vector<uint8_t> payload;
};

[[nodiscard]] std::string_view message_name(message_type type);

[[nodiscard]] bool encode_tcp_connect_request(const tcp_connect_request& request, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_tcp_connect_request(const uint8_t* data, std::size_t len, tcp_connect_request& out);

[[nodiscard]] bool encode_tcp_connect_reply(const tcp_connect_reply& reply, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_tcp_connect_reply(const uint8_t* data, std::size_t len, tcp_connect_reply& out);

[[nodiscard]] bool encode_udp_associate_request(const udp_associate_request& request, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_associate_request(const uint8_t* data, std::size_t len, udp_associate_request& out);

[[nodiscard]] bool encode_udp_associate_reply(const udp_associate_reply& reply, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_associate_reply(const uint8_t* data, std::size_t len, udp_associate_reply& out);

[[nodiscard]] bool encode_udp_datagram(const udp_datagram& datagram, std::vector<uint8_t>& out);

[[nodiscard]] bool decode_udp_datagram(const uint8_t* data, std::size_t len, udp_datagram& out);

}    // namespace relay::proxy

#endif
