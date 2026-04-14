#include <string>
#include <vector>
#include <cstring>

#include <boost/endian/conversion.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "tun_lwip.h"

namespace mux::tun
{

boost::asio::ip::address lwip_to_address(const ip_addr_t& addr)
{
    if (IP_IS_V4_VAL(addr))
    {
        boost::asio::ip::address_v4::bytes_type bytes{};
        const auto raw = ip_2_ip4(&addr)->addr;
        std::memcpy(bytes.data(), &raw, bytes.size());
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), ip_2_ip6(&addr)->addr, bytes.size());
    return boost::asio::ip::address_v6(bytes);
}

boost::asio::ip::udp::endpoint lwip_to_udp_endpoint(const ip_addr_t& addr, uint16_t port) { return {lwip_to_address(addr), port}; }

std::string lwip_ip_to_string(const ip_addr_t& addr) { return lwip_to_address(addr).to_string(); }

bool address_to_lwip(const boost::asio::ip::address& address, ip_addr_t& out)
{
    if (address.is_v4())
    {
        const auto bytes = address.to_v4().to_bytes();
        out.type = IPADDR_TYPE_V4;
        std::memcpy(&ip_2_ip4(&out)->addr, bytes.data(), bytes.size());
        return true;
    }

    if (address.is_v6())
    {
        const auto bytes = address.to_v6().to_bytes();
        out.type = IPADDR_TYPE_V6;
        std::memcpy(ip_2_ip6(&out)->addr, bytes.data(), bytes.size());
        return true;
    }

    return false;
}

bool endpoint_to_lwip(const boost::asio::ip::udp::endpoint& endpoint, ip_addr_t& out_addr, uint16_t& out_port)
{
    if (!address_to_lwip(endpoint.address(), out_addr))
    {
        return false;
    }

    out_port = endpoint.port();
    return true;
}

std::vector<uint8_t> pbuf_to_vector(const pbuf* buf)
{
    std::vector<uint8_t> out;
    if (buf == nullptr)
    {
        return out;
    }

    out.reserve(buf->tot_len);
    for (auto* current = buf; current != nullptr; current = current->next)
    {
        const auto* ptr = static_cast<const uint8_t*>(current->payload);
        out.insert(out.end(), ptr, ptr + current->len);
    }
    return out;
}

std::string lwip_error_message(const err_t err)
{
#if LWIP_DEBUG
    const char* msg = lwip_strerr(err);
    return msg != nullptr ? std::string(msg) : std::string("unknown");
#else
    return std::to_string(static_cast<int>(err));
#endif
}

}    // namespace mux::tun
