#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <boost/asio/ip/address.hpp>

namespace socks
{

constexpr std::uint8_t kVer = 0x05;
constexpr std::uint8_t kMethodNoAuth = 0x00;
constexpr std::uint8_t kMethodGssapi = 0x01;
constexpr std::uint8_t kMethodPassword = 0x02;
constexpr std::uint8_t kMethodNoAcceptable = 0xFF;

constexpr std::uint8_t kCmdConnect = 0x01;
constexpr std::uint8_t kCmdBind = 0x02;
constexpr std::uint8_t kCmdUdpAssociate = 0x03;

constexpr std::uint8_t kAtypIpv4 = 0x01;
constexpr std::uint8_t kAtypDomain = 0x03;
constexpr std::uint8_t kAtypIpv6 = 0x04;

constexpr std::uint8_t kRepSuccess = 0x00;
constexpr std::uint8_t kRepGenFail = 0x01;
constexpr std::uint8_t kRepNotAllowed = 0x02;
constexpr std::uint8_t kRepNetUnreach = 0x03;
constexpr std::uint8_t kRepHostUnreach = 0x04;
constexpr std::uint8_t kRepConnRefused = 0x05;
constexpr std::uint8_t kRepTtlExpired = 0x06;
constexpr std::uint8_t kRepCmdNotSupported = 0x07;
constexpr std::uint8_t kRepAddrTypeNotSupported = 0x08;

}    // namespace socks

struct socks5_request
{
    std::uint8_t ver = 0;
    std::uint8_t cmd = 0;
    std::uint8_t rsv = 0;
    std::uint8_t atyp = 0;
    std::string addr;
    std::uint16_t port = 0;
    std::size_t header_len = 0;
};

struct socks5_auth_request
{
    std::uint8_t ver = 0;
    std::string username;
    std::string password;
};

struct socks_udp_header
{
    std::uint8_t frag = 0;
    std::string addr;
    std::uint16_t port = 0;
    std::size_t header_len = 0;
};

class socks_codec
{
   public:
    [[nodiscard]] static boost::asio::ip::address normalize_ip_address(const boost::asio::ip::address& addr);

    [[nodiscard]] static std::vector<std::uint8_t> encode_udp_header(const socks_udp_header& h);

    [[nodiscard]] static bool decode_udp_header(const std::uint8_t* data, std::size_t len, socks_udp_header& out);

    [[nodiscard]] static bool decode_socks5_request(const std::uint8_t* data, std::size_t len, socks5_request& out);

    [[nodiscard]] static bool decode_socks5_auth_request(const std::uint8_t* data, std::size_t len, socks5_auth_request& out);
};

#endif
