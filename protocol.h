#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <asio.hpp>

namespace socks
{
constexpr std::uint8_t VER = 0x05;
constexpr std::uint8_t METHOD_NO_AUTH = 0x00;
constexpr std::uint8_t METHOD_GSSAPI = 0x01;
constexpr std::uint8_t METHOD_PASSWORD = 0x02;
constexpr std::uint8_t METHOD_NO_ACCEPTABLE = 0xFF;

constexpr std::uint8_t CMD_CONNECT = 0x01;
constexpr std::uint8_t CMD_BIND = 0x02;
constexpr std::uint8_t CMD_UDP_ASSOCIATE = 0x03;

constexpr std::uint8_t ATYP_IPV4 = 0x01;
constexpr std::uint8_t ATYP_DOMAIN = 0x03;
constexpr std::uint8_t ATYP_IPV6 = 0x04;

constexpr std::uint8_t REP_SUCCESS = 0x00;
constexpr std::uint8_t REP_GEN_FAIL = 0x01;
constexpr std::uint8_t REP_NOT_ALLOWED = 0x02;
constexpr std::uint8_t REP_NET_UNREACH = 0x03;
constexpr std::uint8_t REP_HOST_UNREACH = 0x04;
constexpr std::uint8_t REP_CONN_REFUSED = 0x05;
constexpr std::uint8_t REP_TTL_EXPIRED = 0x06;
constexpr std::uint8_t REP_CMD_NOT_SUPPORTED = 0x07;
constexpr std::uint8_t REP_ADDR_TYPE_NOT_SUPPORTED = 0x08;
}    // namespace socks

struct socks_udp_header
{
    uint8_t frag = 0;
    std::string addr;
    uint16_t port = 0;
    size_t header_len = 0;
};

class socks_codec
{
   public:
    static asio::ip::address normalize_ip_address(const asio::ip::address& addr);

    [[nodiscard]] static std::vector<uint8_t> encode_udp_header(const socks_udp_header& h);

    [[nodiscard]] static bool decode_udp_header(const uint8_t* data, size_t len, socks_udp_header& out);
};

#endif
