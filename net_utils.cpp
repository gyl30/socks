#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __linux__
#include <linux/in.h>
#include <linux/in6.h>

#include <asm-generic/socket.h>

#endif

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/detail/system_category.hpp>

#include "net_utils.h"

namespace mux::net
{

namespace
{

bool has_valid_cmsg_payload(const cmsghdr* cm, const std::size_t payload_len) { return cm->cmsg_len >= CMSG_LEN(payload_len); }

boost::asio::ip::udp::endpoint make_v4_endpoint(const in_addr& addr, const in_port_t port)
{
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v4(bytes), ntohs(port)};
}

boost::asio::ip::udp::endpoint make_v6_endpoint(const in6_addr& addr, const in_port_t port)
{
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v6(bytes), ntohs(port)};
}

std::optional<boost::asio::ip::udp::endpoint> parse_ipv4_original_dst(const cmsghdr* cm)
{
    if (!has_valid_cmsg_payload(cm, sizeof(sockaddr_in)))
    {
        return std::nullopt;
    }
    const auto* addr = reinterpret_cast<const sockaddr_in*>(CMSG_DATA(cm));
    return make_v4_endpoint(addr->sin_addr, addr->sin_port);
}

std::optional<boost::asio::ip::udp::endpoint> parse_ipv6_original_dst(const cmsghdr* cm)
{
    if (!has_valid_cmsg_payload(cm, sizeof(sockaddr_in6)))
    {
        return std::nullopt;
    }
    const auto* addr = reinterpret_cast<const sockaddr_in6*>(CMSG_DATA(cm));
    return make_v6_endpoint(addr->sin6_addr, addr->sin6_port);
}

#ifdef __linux__
std::optional<boost::asio::ip::udp::endpoint> parse_original_dst_control_message(const cmsghdr* cm)
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

boost::asio::ip::udp::endpoint endpoint_from_sockaddr_v4(const sockaddr_storage& addr, const std::size_t len)
{
    if (len < sizeof(sockaddr_in))
    {
        return {};
    }
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
    return make_v4_endpoint(v4->sin_addr, v4->sin_port);
}

boost::asio::ip::udp::endpoint endpoint_from_sockaddr_v6(const sockaddr_storage& addr, const std::size_t len)
{
    if (len < sizeof(sockaddr_in6))
    {
        return {};
    }
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    return make_v6_endpoint(v6->sin6_addr, v6->sin6_port);
}

}    // namespace

std::expected<void, boost::system::error_code> set_socket_mark(int fd, const std::uint32_t mark)
{
#ifdef __linux__
    if (mark == 0)
    {
        return {};
    }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        return std::unexpected(boost::system::error_code(errno, boost::system::system_category()));
    }
    return {};
#else
    (void)fd;
    (void)mark;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, boost::system::error_code> set_socket_transparent_v4(const int fd)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        return std::unexpected(boost::system::error_code(errno, boost::system::system_category()));
    }
    return {};
#else
    (void)fd;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, boost::system::error_code> set_socket_transparent_v6(const int fd)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        return std::unexpected(boost::system::error_code(errno, boost::system::system_category()));
    }
    return {};
#else
    (void)fd;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, boost::system::error_code> set_socket_transparent(const int fd, const bool ipv6)
{
    if (auto result = set_socket_transparent_v4(fd); !result)
    {
        return std::unexpected(result.error());
    }
    if (ipv6)
    {
        if (auto result = set_socket_transparent_v6(fd); !result)
        {
            return std::unexpected(result.error());
        }
    }
    return {};
}

std::expected<void, boost::system::error_code> set_socket_recv_origdst_v4(const int fd)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        return std::unexpected(boost::system::error_code(errno, boost::system::system_category()));
    }
    return {};
#else
    (void)fd;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, boost::system::error_code> set_socket_recv_origdst_v6(const int fd)
{
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        return std::unexpected(boost::system::error_code(errno, boost::system::system_category()));
    }
    return {};
#else
    (void)fd;
    return std::unexpected(std::make_error_code(std::errc::not_supported));
#endif
}

std::expected<void, boost::system::error_code> set_socket_recv_origdst(const int fd, const bool ipv6)
{
    if (auto result = set_socket_recv_origdst_v4(fd); !result)
    {
        return std::unexpected(result.error());
    }
    if (ipv6)
    {
        if (auto result = set_socket_recv_origdst_v6(fd); !result)
        {
            return std::unexpected(result.error());
        }
    }
    return {};
}

boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr)
{
    if (addr.is_v6())
    {
        const auto v6 = addr.to_v6();
        if (v6.is_v4_mapped())
        {
            const auto bytes = v6.to_bytes();
            const boost::asio::ip::address_v4::bytes_type v4_bytes = {bytes[12], bytes[13], bytes[14], bytes[15]};
            return boost::asio::ip::address_v4(v4_bytes);
        }
    }
    return addr;
}

boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep) { return {normalize_address(ep.address()), ep.port()}; }

std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg)
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

boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, const std::size_t len)
{
    if (addr.ss_family == AF_INET)
    {
        return endpoint_from_sockaddr_v4(addr, len);
    }
    if (addr.ss_family == AF_INET6)
    {
        return endpoint_from_sockaddr_v6(addr, len);
    }
    return {};
}

}    // namespace mux::net
