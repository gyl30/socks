#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <expected>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>

#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#endif

#include <asio/ip/udp.hpp>
#include <asio/ip/address.hpp>

#include "net_utils.h"

namespace mux::net
{

namespace
{

bool has_valid_cmsg_payload(const cmsghdr* cm, const std::size_t payload_len)
{
    return cm->cmsg_len >= CMSG_LEN(payload_len);
}

asio::ip::udp::endpoint make_v4_endpoint(const in_addr& addr, const in_port_t port)
{
    asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return asio::ip::udp::endpoint(asio::ip::address_v4(bytes), ntohs(port));
}

asio::ip::udp::endpoint make_v6_endpoint(const in6_addr& addr, const in_port_t port)
{
    asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return asio::ip::udp::endpoint(asio::ip::address_v6(bytes), ntohs(port));
}

std::optional<asio::ip::udp::endpoint> parse_ipv4_original_dst(const cmsghdr* cm)
{
    if (!has_valid_cmsg_payload(cm, sizeof(sockaddr_in)))
    {
        return std::nullopt;
    }
    const auto* addr = reinterpret_cast<const sockaddr_in*>(CMSG_DATA(cm));
    return make_v4_endpoint(addr->sin_addr, addr->sin_port);
}

std::optional<asio::ip::udp::endpoint> parse_ipv6_original_dst(const cmsghdr* cm)
{
    if (!has_valid_cmsg_payload(cm, sizeof(sockaddr_in6)))
    {
        return std::nullopt;
    }
    const auto* addr = reinterpret_cast<const sockaddr_in6*>(CMSG_DATA(cm));
    return make_v6_endpoint(addr->sin6_addr, addr->sin6_port);
}

#ifdef __linux__
std::optional<asio::ip::udp::endpoint> parse_original_dst_control_message(const cmsghdr* cm)
{
    if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_ORIGDSTADDR)
    {
        return parse_ipv4_original_dst(cm);
    }
    if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_ORIGDSTADDR)
    {
        return parse_ipv6_original_dst(cm);
    }
    return std::nullopt;
}
#endif

asio::ip::udp::endpoint endpoint_from_sockaddr_v4(const sockaddr_storage& addr, const std::size_t len)
{
    if (len < sizeof(sockaddr_in))
    {
        return asio::ip::udp::endpoint();
    }
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
    return make_v4_endpoint(v4->sin_addr, v4->sin_port);
}

asio::ip::udp::endpoint endpoint_from_sockaddr_v6(const sockaddr_storage& addr, const std::size_t len)
{
    if (len < sizeof(sockaddr_in6))
    {
        return asio::ip::udp::endpoint();
    }
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    return make_v6_endpoint(v6->sin6_addr, v6->sin6_port);
}

}    // namespace

std::expected<void, std::error_code> set_socket_mark(int fd, const std::uint32_t mark)
{
#ifdef __linux__
    if (mark == 0)
    {
        return {};
    }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    return {};
#else
    (void)fd;
    (void)mark;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, std::error_code> set_socket_transparent(int fd, const bool ipv6)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    if (ipv6)
    {
        if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0)
        {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
    }
    return {};
#else
    (void)fd;
    (void)ipv6;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, std::error_code> set_socket_recv_origdst(int fd, const bool ipv6)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }
    if (ipv6)
    {
        if (setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
        {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
    }
    return {};
#else
    (void)fd;
    (void)ipv6;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

asio::ip::address normalize_address(const asio::ip::address& addr)
{
    if (addr.is_v6())
    {
        const auto v6 = addr.to_v6();
        if (v6.is_v4_mapped())
        {
            const auto bytes = v6.to_bytes();
            asio::ip::address_v4::bytes_type v4_bytes = {bytes[12], bytes[13], bytes[14], bytes[15]};
            return asio::ip::address_v4(v4_bytes);
        }
    }
    return addr;
}

asio::ip::udp::endpoint normalize_endpoint(const asio::ip::udp::endpoint& ep)
{
    return asio::ip::udp::endpoint(normalize_address(ep.address()), ep.port());
}

std::optional<asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg)
{
#ifdef __linux__
    for (auto* cm = CMSG_FIRSTHDR(&msg); cm != nullptr; cm = CMSG_NXTHDR(const_cast<msghdr*>(&msg), cm))
    {
        const auto ep = parse_original_dst_control_message(cm);
        if (ep.has_value())
        {
            return ep;
        }
    }
    return std::nullopt;
#else
    (void)msg;
    return std::nullopt;
#endif
}

asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, const std::size_t len)
{
    if (addr.ss_family == AF_INET)
    {
        return endpoint_from_sockaddr_v4(addr, len);
    }
    if (addr.ss_family == AF_INET6)
    {
        return endpoint_from_sockaddr_v6(addr, len);
    }
    return asio::ip::udp::endpoint();
}

}    // namespace mux::net
