#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <string_view>

#include <boost/asio.hpp>

#include "log.h"
#include "protocol.h"
#include "proxy_protocol.h"

namespace
{

[[nodiscard]] bool has_remaining(std::size_t len, std::size_t pos, std::size_t need)
{
    if (pos > len)
    {
        return false;
    }
    return len - pos >= need;
}

void append_u16(std::vector<uint8_t>& out, uint16_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

void append_u64(std::vector<uint8_t>& out, uint64_t value)
{
    for (int index = 7; index >= 0; --index)
    {
        out.push_back(static_cast<uint8_t>((value >> (index * 8)) & 0xFFU));
    }
}

[[nodiscard]] bool read_u8(const uint8_t* data, std::size_t len, std::size_t& pos, uint8_t& out)
{
    if (!has_remaining(len, pos, 1))
    {
        return false;
    }
    out = data[pos];
    pos += 1;
    return true;
}

[[nodiscard]] bool read_u16(const uint8_t* data, std::size_t len, std::size_t& pos, uint16_t& out)
{
    if (!has_remaining(len, pos, 2))
    {
        return false;
    }
    out = static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1]);
    pos += 2;
    return true;
}

[[nodiscard]] bool read_u64(const uint8_t* data, std::size_t len, std::size_t& pos, uint64_t& out)
{
    if (!has_remaining(len, pos, 8))
    {
        return false;
    }
    out = 0;
    for (std::size_t i = 0; i < 8; ++i)
    {
        out = (out << 8U) | static_cast<uint64_t>(data[pos + i]);
    }
    pos += 8;
    return true;
}

void append_ipv4_address(std::vector<uint8_t>& out, const boost::asio::ip::address_v4& address)
{
    out.push_back(socks::kAtypIpv4);
    const auto bytes = address.to_bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_ipv6_address(std::vector<uint8_t>& out, const boost::asio::ip::address_v6& address)
{
    out.push_back(socks::kAtypIpv6);
    const auto bytes = address.to_bytes();
    out.insert(out.end(), bytes.begin(), bytes.end());
}

[[nodiscard]] bool append_domain_address(std::vector<uint8_t>& out, const std::string& host)
{
    if (host.empty() || host.size() > socks::kMaxDomainLen)
    {
        return false;
    }
    if (!socks::is_valid_domain(host))
    {
        return false;
    }
    out.push_back(socks::kAtypDomain);
    out.push_back(static_cast<uint8_t>(host.size()));
    out.insert(out.end(), host.begin(), host.end());
    return true;
}

[[nodiscard]] bool append_target_endpoint(std::vector<uint8_t>& out, const std::string& host, uint16_t port)
{
    if (host.empty())
    {
        return false;
    }

    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        if (!append_domain_address(out, host))
        {
            return false;
        }
        append_u16(out, port);
        return true;
    }

    address = socks_codec::normalize_ip_address(address);
    if (address.is_v4())
    {
        append_ipv4_address(out, address.to_v4());
    }
    else if (address.is_v6())
    {
        append_ipv6_address(out, address.to_v6());
    }
    else
    {
        return false;
    }
    append_u16(out, port);
    return true;
}

[[nodiscard]] bool parse_ipv4_address(const uint8_t* data, std::size_t len, std::size_t& pos, std::string& host)
{
    if (!has_remaining(len, pos, 4))
    {
        return false;
    }
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), data + pos, bytes.size());
    host = boost::asio::ip::address_v4(bytes).to_string();
    pos += bytes.size();
    return true;
}

[[nodiscard]] bool parse_ipv6_address(const uint8_t* data, std::size_t len, std::size_t& pos, std::string& host)
{
    if (!has_remaining(len, pos, 16))
    {
        return false;
    }
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), data + pos, bytes.size());
    host = boost::asio::ip::address_v6(bytes).to_string();
    pos += bytes.size();
    return true;
}

[[nodiscard]] bool parse_domain_address(const uint8_t* data, std::size_t len, std::size_t& pos, std::string& host)
{
    uint8_t domain_len = 0;
    if (!read_u8(data, len, pos, domain_len))
    {
        return false;
    }
    if (domain_len == 0 || !has_remaining(len, pos, domain_len))
    {
        return false;
    }
    const auto* begin = data + pos;
    const auto* end = begin + domain_len;
    if (std::find(begin, end, static_cast<uint8_t>(0x00)) != end)
    {
        return false;
    }
    const std::string_view domain(reinterpret_cast<const char*>(begin), domain_len);
    if (!socks::is_valid_domain(domain))
    {
        return false;
    }
    host.assign(domain.begin(), domain.end());
    pos += domain_len;
    return true;
}

[[nodiscard]] bool parse_target_endpoint(const uint8_t* data, std::size_t len, std::size_t& pos, std::string& host, uint16_t& port)
{
    uint8_t atyp = 0;
    if (!read_u8(data, len, pos, atyp))
    {
        return false;
    }

    bool ok = false;
    if (atyp == socks::kAtypIpv4)
    {
        ok = parse_ipv4_address(data, len, pos, host);
    }
    else if (atyp == socks::kAtypIpv6)
    {
        ok = parse_ipv6_address(data, len, pos, host);
    }
    else if (atyp == socks::kAtypDomain)
    {
        ok = parse_domain_address(data, len, pos, host);
    }
    if (!ok)
    {
        return false;
    }
    return read_u16(data, len, pos, port);
}

[[nodiscard]] bool has_message_type(const uint8_t* data, std::size_t len, mux::proxy::message_type expected, std::size_t& pos)
{
    pos = 0;
    uint8_t raw_type = 0;
    if (!read_u8(data, len, pos, raw_type))
    {
        return false;
    }
    return raw_type == static_cast<uint8_t>(expected);
}

}    // namespace

namespace mux::proxy
{

std::string_view message_name(const message_type type)
{
    switch (type)
    {
        case message_type::kTcpConnectRequest:
            return "tcp_connect_request";
        case message_type::kTcpConnectReply:
            return "tcp_connect_reply";
        case message_type::kUdpAssociateRequest:
            return "udp_associate_request";
        case message_type::kUdpAssociateReply:
            return "udp_associate_reply";
        case message_type::kUdpDatagram:
            return "udp_datagram";
    }
    return "unknown";
}

bool encode_tcp_connect_request(const tcp_connect_request& request, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(64 + request.target_host.size());
    out.push_back(static_cast<uint8_t>(message_type::kTcpConnectRequest));
    append_u64(out, request.trace_id);
    return append_target_endpoint(out, request.target_host, request.target_port);
}

bool decode_tcp_connect_request(const uint8_t* data, const std::size_t len, tcp_connect_request& out)
{
    std::size_t pos = 0;
    if (!has_message_type(data, len, message_type::kTcpConnectRequest, pos))
    {
        return false;
    }
    if (!read_u64(data, len, pos, out.trace_id))
    {
        return false;
    }
    if (!parse_target_endpoint(data, len, pos, out.target_host, out.target_port))
    {
        return false;
    }
    return pos == len && !out.target_host.empty() && out.target_port != 0;
}

bool encode_tcp_connect_reply(const tcp_connect_reply& reply, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(48 + reply.bind_host.size());
    out.push_back(static_cast<uint8_t>(message_type::kTcpConnectReply));
    out.push_back(reply.socks_rep);
    const auto& bind_host = reply.bind_host.empty() ? std::string("0.0.0.0") : reply.bind_host;
    return append_target_endpoint(out, bind_host, reply.bind_port);
}

bool decode_tcp_connect_reply(const uint8_t* data, const std::size_t len, tcp_connect_reply& out)
{
    std::size_t pos = 0;
    if (!has_message_type(data, len, message_type::kTcpConnectReply, pos))
    {
        return false;
    }
    if (!read_u8(data, len, pos, out.socks_rep))
    {
        return false;
    }
    if (!parse_target_endpoint(data, len, pos, out.bind_host, out.bind_port))
    {
        return false;
    }
    return pos == len;
}

bool encode_udp_associate_request(const udp_associate_request& request, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(16);
    out.push_back(static_cast<uint8_t>(message_type::kUdpAssociateRequest));
    append_u64(out, request.trace_id);
    return true;
}

bool decode_udp_associate_request(const uint8_t* data, const std::size_t len, udp_associate_request& out)
{
    std::size_t pos = 0;
    if (!has_message_type(data, len, message_type::kUdpAssociateRequest, pos))
    {
        return false;
    }
    if (!read_u64(data, len, pos, out.trace_id))
    {
        return false;
    }
    return pos == len;
}

bool encode_udp_associate_reply(const udp_associate_reply& reply, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(48 + reply.bind_host.size());
    out.push_back(static_cast<uint8_t>(message_type::kUdpAssociateReply));
    out.push_back(reply.socks_rep);
    const auto& bind_host = reply.bind_host.empty() ? std::string("0.0.0.0") : reply.bind_host;
    return append_target_endpoint(out, bind_host, reply.bind_port);
}

bool decode_udp_associate_reply(const uint8_t* data, const std::size_t len, udp_associate_reply& out)
{
    std::size_t pos = 0;
    if (!has_message_type(data, len, message_type::kUdpAssociateReply, pos))
    {
        return false;
    }
    if (!read_u8(data, len, pos, out.socks_rep))
    {
        return false;
    }
    if (!parse_target_endpoint(data, len, pos, out.bind_host, out.bind_port))
    {
        return false;
    }
    return pos == len;
}

bool encode_udp_datagram(const udp_datagram& datagram, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(64 + datagram.target_host.size() + datagram.payload.size());
    out.push_back(static_cast<uint8_t>(message_type::kUdpDatagram));
    if (!append_target_endpoint(out, datagram.target_host, datagram.target_port))
    {
        return false;
    }
    out.insert(out.end(), datagram.payload.begin(), datagram.payload.end());
    return out.size() <= kMaxPacketSize;
}

bool decode_udp_datagram(const uint8_t* data, const std::size_t len, udp_datagram& out)
{
    std::size_t pos = 0;
    if (!has_message_type(data, len, message_type::kUdpDatagram, pos))
    {
        return false;
    }
    if (!parse_target_endpoint(data, len, pos, out.target_host, out.target_port))
    {
        return false;
    }
    if (out.target_host.empty() || out.target_port == 0)
    {
        return false;
    }
    out.payload.assign(data + static_cast<std::ptrdiff_t>(pos), data + static_cast<std::ptrdiff_t>(len));
    return true;
}

}    // namespace mux::proxy
