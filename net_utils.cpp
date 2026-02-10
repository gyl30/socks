#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
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

bool set_socket_mark(int fd, const std::uint32_t mark, std::error_code& ec)
{
#ifdef __linux__
    if (mark == 0)
    {
        ec.clear();
        return true;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        ec = std::error_code(errno, std::system_category());
        return false;
    }
    ec.clear();
    return true;
#else
    (void)fd;
    (void)mark;
    ec = std::make_error_code(std::errc::not_supported);
    return false;
#endif
}

bool set_socket_transparent(int fd, const bool ipv6, std::error_code& ec)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        ec = std::error_code(errno, std::system_category());
        return false;
    }
    if (ipv6)
    {
        if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0)
        {
            ec = std::error_code(errno, std::system_category());
            return false;
        }
    }
    ec.clear();
    return true;
#else
    (void)fd;
    (void)ipv6;
    ec = std::make_error_code(std::errc::not_supported);
    return false;
#endif
}

bool set_socket_recv_origdst(int fd, const bool ipv6, std::error_code& ec)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        ec = std::error_code(errno, std::system_category());
        return false;
    }
    if (ipv6)
    {
        if (setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
        {
            ec = std::error_code(errno, std::system_category());
            return false;
        }
    }
    ec.clear();
    return true;
#else
    (void)fd;
    (void)ipv6;
    ec = std::make_error_code(std::errc::not_supported);
    return false;
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
        if (cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_ORIGDSTADDR)
        {
            if (cm->cmsg_len < CMSG_LEN(sizeof(sockaddr_in)))
            {
                continue;
            }
            const auto* addr = reinterpret_cast<const sockaddr_in*>(CMSG_DATA(cm));
            asio::ip::address_v4::bytes_type bytes;
            std::memcpy(bytes.data(), &addr->sin_addr, bytes.size());
            return asio::ip::udp::endpoint(asio::ip::address_v4(bytes), ntohs(addr->sin_port));
        }
        if (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_ORIGDSTADDR)
        {
            if (cm->cmsg_len < CMSG_LEN(sizeof(sockaddr_in6)))
            {
                continue;
            }
            const auto* addr = reinterpret_cast<const sockaddr_in6*>(CMSG_DATA(cm));
            asio::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &addr->sin6_addr, bytes.size());
            return asio::ip::udp::endpoint(asio::ip::address_v6(bytes), ntohs(addr->sin6_port));
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
        const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
        asio::ip::address_v4::bytes_type bytes;
        std::memcpy(bytes.data(), &v4->sin_addr, bytes.size());
        return asio::ip::udp::endpoint(asio::ip::address_v4(bytes), ntohs(v4->sin_port));
    }
    if (addr.ss_family == AF_INET6)
    {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        asio::ip::address_v6::bytes_type bytes;
        std::memcpy(bytes.data(), &v6->sin6_addr, bytes.size());
        return asio::ip::udp::endpoint(asio::ip::address_v6(bytes), ntohs(v6->sin6_port));
    }
    (void)len;
    return asio::ip::udp::endpoint();
}

}    // namespace mux::net
