#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "protocol.h"

namespace
{

constexpr std::uint8_t kSocks5AuthVer = 0x01;

[[nodiscard]] bool has_remaining(const std::size_t len, const std::size_t pos, const std::size_t need)
{
    if (pos > len)
    {
        return false;
    }
    return len - pos >= need;
}    // namespace

bool parse_ipv4_address(const std::uint8_t* data, const std::size_t len, std::size_t& pos, std::string& addr)
{
    if (!has_remaining(len, pos, 4))
    {
        return false;
    }
    boost::asio::ip::address_v4::bytes_type bytes;
    std::memcpy(bytes.data(), data + pos, 4);
    addr = boost::asio::ip::address_v4(bytes).to_string();
    pos += 4;
    return true;
}    // namespace

bool parse_domain_address(const std::uint8_t* data, const std::size_t len, std::size_t& pos, std::string& addr)
{
    if (!has_remaining(len, pos, 1))
    {
        return false;
    }
    const std::uint8_t domain_len = data[pos];
    ++pos;
    if (domain_len == 0)
    {
        return false;
    }
    if (!has_remaining(len, pos, domain_len))
    {
        return false;
    }
    const auto* domain_begin = data + pos;
    const auto* domain_end = domain_begin + domain_len;
    if (std::find(domain_begin, domain_end, static_cast<std::uint8_t>(0x00)) != domain_end)
    {
        return false;
    }
    addr = std::string(reinterpret_cast<const char*>(domain_begin), domain_len);
    pos += domain_len;
    return true;
}    // namespace

bool parse_ipv6_address(const std::uint8_t* data, const std::size_t len, std::size_t& pos, std::string& addr)
{
    if (!has_remaining(len, pos, 16))
    {
        return false;
    }
    boost::asio::ip::address_v6::bytes_type bytes;
    std::memcpy(bytes.data(), data + pos, 16);
    addr = boost::asio::ip::address_v6(bytes).to_string();
    pos += 16;
    return true;
}

bool parse_port(const std::uint8_t* data, const std::size_t len, std::size_t& pos, std::uint16_t& port)
{
    if (!has_remaining(len, pos, 2))
    {
        return false;
    }
    port = static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    return true;
}

bool parse_address_and_port(const std::uint8_t* data,
                            const std::size_t len,
                            const std::uint8_t atyp,
                            const std::size_t start_pos,
                            std::string& addr,
                            std::uint16_t& port,
                            std::size_t& next_pos)
{
    std::size_t pos = start_pos;
    bool ok = false;
    if (atyp == socks::kAtypIpv4)
    {
        ok = parse_ipv4_address(data, len, pos, addr);
    }
    else if (atyp == socks::kAtypDomain)
    {
        ok = parse_domain_address(data, len, pos, addr);
    }
    else if (atyp == socks::kAtypIpv6)
    {
        ok = parse_ipv6_address(data, len, pos, addr);
    }

    if (!ok)
    {
        return false;
    }
    if (!parse_port(data, len, pos, port))
    {
        return false;
    }
    next_pos = pos;
    return true;
}

void append_udp_ipv4_address(std::vector<std::uint8_t>& buf, const boost::asio::ip::address_v4& address)
{
    buf.push_back(socks::kAtypIpv4);
    const auto bytes = address.to_bytes();
    buf.insert(buf.end(), bytes.begin(), bytes.end());
}

void append_udp_ipv6_address(std::vector<std::uint8_t>& buf, const boost::asio::ip::address_v6& address)
{
    buf.push_back(socks::kAtypIpv6);
    const auto bytes = address.to_bytes();
    buf.insert(buf.end(), bytes.begin(), bytes.end());
}

bool append_udp_domain_address(std::vector<std::uint8_t>& buf, const std::string& host)
{
    constexpr std::size_t kMaxDomainLen = 255;
    if (host.empty() || host.size() > kMaxDomainLen)
    {
        return false;
    }
    const auto domain_len = host.size();
    buf.push_back(socks::kAtypDomain);
    buf.push_back(static_cast<std::uint8_t>(domain_len));
    buf.insert(buf.end(), host.begin(), host.begin() + static_cast<std::ptrdiff_t>(domain_len));
    return true;
}

bool append_udp_target_address(std::vector<std::uint8_t>& buf, const std::string& host)
{
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return append_udp_domain_address(buf, host);
    }
    address = socks_codec::normalize_ip_address(address);
    if (address.is_v4())
    {
        append_udp_ipv4_address(buf, address.to_v4());
        return true;
    }
    if (address.is_v6())
    {
        append_udp_ipv6_address(buf, address.to_v6());
        return true;
    }
    return append_udp_domain_address(buf, host);
}

}    // namespace

boost::asio::ip::address socks_codec::normalize_ip_address(const boost::asio::ip::address& addr)
{
    if (addr.is_v4())
    {
        return addr;
    }

    if (addr.is_v6())
    {
        if (const auto& v6 = addr.to_v6(); v6.is_v4_mapped())
        {
            return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6);
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
    if (!append_udp_target_address(buf, h.addr))
    {
        return {};
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
    if (data[0] != 0x00 || data[1] != 0x00)
    {
        return false;
    }

    out.frag = data[2];
    const std::uint8_t atyp = data[3];
    return parse_address_and_port(data, len, atyp, 4, out.addr, out.port, out.header_len);
}

bool socks_codec::decode_socks5_request(const std::uint8_t* data, std::size_t len, socks5_request& out)
{
    if (len < 4)
    {
        return false;
    }

    out.ver = data[0];
    out.cmd = data[1];
    out.rsv = data[2];
    out.atyp = data[3];
    if (out.ver != socks::kVer || out.rsv != 0)
    {
        return false;
    }
    if (!parse_address_and_port(data, len, out.atyp, 4, out.addr, out.port, out.header_len))
    {
        return false;
    }
    return out.header_len == len;
}

bool socks_codec::decode_socks5_auth_request(const std::uint8_t* data, std::size_t len, socks5_auth_request& out)
{
    std::size_t pos = 0;
    if (len < pos + 2)
    {
        return false;
    }

    out.ver = data[pos++];
    if (out.ver != kSocks5AuthVer)
    {
        return false;
    }
    const std::uint8_t ulen = data[pos++];
    if (ulen == 0)
    {
        return false;
    }

    if (len < pos + ulen + 1)
    {
        return false;
    }

    out.username = std::string(reinterpret_cast<const char*>(data) + pos, ulen);
    pos += ulen;

    const std::uint8_t plen = data[pos++];
    if (plen == 0)
    {
        return false;
    }

    if (len != pos + plen)
    {
        return false;
    }

    out.password = std::string(reinterpret_cast<const char*>(data) + pos, plen);
    return true;
}
