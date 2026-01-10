#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <boost/asio.hpp>

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

struct SocksUdpHeader
{
    uint8_t frag = 0;
    std::string addr;
    uint16_t port = 0;
    size_t header_len = 0;

    std::vector<uint8_t> encode() const
    {
        std::vector<uint8_t> buf;
        buf.reserve(24);
        buf.push_back(0x00);
        buf.push_back(0x00);
        buf.push_back(frag);

        boost::system::error_code ec;
        auto address = boost::asio::ip::make_address(addr, ec);

        if (!ec && address.is_v4())
        {
            buf.push_back(socks::ATYP_IPV4);
            auto bytes = address.to_v4().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        }
        else if (!ec && address.is_v6())
        {
            buf.push_back(socks::ATYP_IPV6);
            auto bytes = address.to_v6().to_bytes();
            buf.insert(buf.end(), bytes.begin(), bytes.end());
        }
        else
        {
            buf.push_back(socks::ATYP_DOMAIN);
            buf.push_back(static_cast<uint8_t>(addr.size()));
            buf.insert(buf.end(), addr.begin(), addr.end());
        }

        buf.push_back((port >> 8) & 0xFF);
        buf.push_back(port & 0xFF);
        return buf;
    }

    static bool decode(const uint8_t* data, size_t len, SocksUdpHeader& out)
    {
        if (len < 4)
            return false;
        out.frag = data[2];
        uint8_t atyp = data[3];

        size_t pos = 4;
        if (atyp == socks::ATYP_IPV4)
        {
            if (len < pos + 4 + 2)
                return false;
            boost::asio::ip::address_v4::bytes_type b;
            std::memcpy(b.data(), data + pos, 4);
            out.addr = boost::asio::ip::address_v4(b).to_string();
            pos += 4;
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            if (len < pos + 1)
                return false;
            uint8_t dlen = data[pos];
            pos++;
            if (len < pos + dlen + 2)
                return false;
            out.addr = std::string((const char*)data + pos, dlen);
            pos += dlen;
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            if (len < pos + 16 + 2)
                return false;
            boost::asio::ip::address_v6::bytes_type b;
            std::memcpy(b.data(), data + pos, 16);
            out.addr = boost::asio::ip::address_v6(b).to_string();
            pos += 16;
        }
        else
        {
            return false;
        }

        out.port = (data[pos] << 8) | data[pos + 1];
        pos += 2;
        out.header_len = pos;
        return true;
    }
};

#endif
