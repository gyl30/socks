#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <system_error>

#include <asio/ip/address.hpp>
#include <asio/ip/address_v4.hpp>
#include <asio/ip/address_v6.hpp>

#include "protocol.h"

namespace
{
}

asio::ip::address socks_codec::normalize_ip_address(const asio::ip::address& addr)
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

std::vector<std::uint8_t> socks_codec::encode_udp_header(const socks_udp_header& h)
{
    std::vector<std::uint8_t> buf;
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
        buf.push_back(socks::kAtypIpv4);
        const auto bytes = address.to_v4().to_bytes();
        buf.insert(buf.end(), bytes.begin(), bytes.end());
    }
    else if (!ec && address.is_v6())
    {
        buf.push_back(socks::kAtypIpv6);
        const auto bytes = address.to_v6().to_bytes();
        buf.insert(buf.end(), bytes.begin(), bytes.end());
    }
    else
    {
        buf.push_back(socks::kAtypDomain);
        buf.push_back(static_cast<std::uint8_t>(h.addr.size()));
        buf.insert(buf.end(), h.addr.begin(), h.addr.end());
    }

    buf.push_back(static_cast<std::uint8_t>((h.port >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(h.port & 0xFF));
    return buf;
}

bool socks_codec::decode_udp_header(const std::uint8_t* data, std::size_t len, socks_udp_header& out)
{
    if (len < 4)
    {
        return false;
    }

    out.frag = data[2];
    const std::uint8_t atyp = data[3];

    std::size_t pos = 4;
    if (atyp == socks::kAtypIpv4)
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
    else if (atyp == socks::kAtypDomain)
    {
        if (len < pos + 1)
        {
            return false;
        }
        const std::uint8_t dlen = data[pos];
        pos++;
        if (len < pos + dlen + 2)
        {
            return false;
        }
        out.addr = std::string(reinterpret_cast<const char*>(data) + pos, dlen);
        pos += dlen;
    }
    else if (atyp == socks::kAtypIpv6)
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

    out.port = static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    out.header_len = pos;
    return true;
}
