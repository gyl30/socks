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
    static asio::ip::address normalize_ip_address(const asio::ip::address& addr)
    {
        if (addr.is_v4())
        {
            return addr;
        }

        if (addr.is_v6())
        {
            if (const auto& v6 = addr.to_v6(); v6.is_v4_mapped())
            {
                return asio::ip::make_address_v4(asio::ip::v4_mapped, v6);
            }
        }

        return addr;
    }

    [[nodiscard]] static std::vector<uint8_t> encode_udp_header(const socks_udp_header& h)
    {
        std::vector<uint8_t> buf;
        buf.reserve(24);
        buf.push_back(0x00);
        buf.push_back(0x00);
        buf.push_back(h.frag);

        std::error_code ec;
        auto address = asio::ip::make_address(h.addr, ec);

        if (!ec && address.is_v6())
        {
            address = normalize_ip_address(address);
        }

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
            buf.push_back(static_cast<uint8_t>(h.addr.size()));
            buf.insert(buf.end(), h.addr.begin(), h.addr.end());
        }

        buf.push_back(static_cast<uint8_t>((h.port >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(h.port & 0xFF));
        return buf;
    }

    [[nodiscard]] static bool decode_udp_header(const uint8_t* data, size_t len, socks_udp_header& out)
    {
        if (len < 4)
        {
            return false;
        }

        out.frag = data[2];
        const uint8_t atyp = data[3];

        size_t pos = 4;
        if (atyp == socks::ATYP_IPV4)
        {
            if (len < pos + 4 + 2)
            {
                return false;
            }
            asio::ip::address_v4::bytes_type b;
            std::memcpy(b.data(), data + pos, 4);
            out.addr = asio::ip::address_v4(b).to_string();
            pos += 4;
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            if (len < pos + 1)
            {
                return false;
            }
            const uint8_t dlen = data[pos];
            pos++;
            if (len < pos + dlen + 2)
            {
                return false;
            }
            out.addr = std::string(reinterpret_cast<const char*>(data) + pos, dlen);
            pos += dlen;
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            if (len < pos + 16 + 2)
            {
                return false;
            }
            asio::ip::address_v6::bytes_type b;
            std::memcpy(b.data(), data + pos, 16);
            out.addr = asio::ip::address_v6(b).to_string();
            pos += 16;
        }
        else
        {
            return false;
        }

        out.port = static_cast<uint16_t>((data[pos] << 8) | data[pos + 1]);
        pos += 2;
        out.header_len = pos;
        return true;
    }
};

#endif
