#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#ifdef __linux__
#include <linux/in.h>
#include <linux/in6.h>

#include <asm-generic/socket.h>

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#endif

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/detail/errc.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/detail/system_category.hpp>
#include <boost/endian/conversion.hpp>

#include "constants.h"
#include "net_utils.h"
#include "log.h"

namespace mux::net
{

namespace
{

uint64_t fnv1a_update(uint64_t hash, const unsigned char* data, std::size_t len)
{
    for (std::size_t i = 0; i < len; ++i)
    {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= constants::net::kFnvPrime64;
    }
    return hash;
}

#ifdef __linux__
cmsghdr* next_cmsg_header(const msghdr& msg, cmsghdr* current)
{
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#endif
    auto* next = CMSG_NXTHDR(const_cast<msghdr*>(&msg), current);
#ifdef __clang__
#pragma clang diagnostic pop
#endif
    return next;
}

void log_original_dst_getsockopt_failure(int level, int option, const boost::system::error_code& ec)
{
    static std::atomic<uint64_t> last_log_ms{0};
    static std::atomic<uint32_t> suppressed{0};

    const auto now = now_ms();
    auto last = last_log_ms.load(std::memory_order_relaxed);
    if (now - last < constants::net::kOriginalDstLogIntervalMs)
    {
        suppressed.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!last_log_ms.compare_exchange_strong(last, now, std::memory_order_relaxed))
    {
        suppressed.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    const auto dropped = suppressed.exchange(0, std::memory_order_relaxed);
    LOG_INFO(
        "get original tcp dst getsockopt failed level {} opt {} errno {} error {} suppressed {}", level, option, ec.value(), ec.message(), dropped);
}

boost::system::error_code select_original_dst_error(bool prefer_ipv6,
                                                    const boost::system::error_code& v4_ec,
                                                    const boost::system::error_code& v6_ec)
{
    if (prefer_ipv6)
    {
        if (v6_ec)
        {
            return v6_ec;
        }
        return v4_ec;
    }

    if (v4_ec)
    {
        return v4_ec;
    }
    return v6_ec;
}

bool try_get_original_dst_from_local_endpoint(boost::asio::ip::tcp::socket& socket,
                                              boost::asio::ip::tcp::endpoint& endpoint,
                                              boost::system::error_code& ec)
{
    ec.clear();
    const auto local_endpoint = socket.local_endpoint(ec);
    if (ec)
    {
        return false;
    }
    if (local_endpoint.port() == 0 || local_endpoint.address().is_unspecified())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::address_not_available);
        return false;
    }

    endpoint = local_endpoint;
    return true;
}
#endif

void set_socket_bool_option(int fd, int level, int option, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    constexpr int one = 1;
    if (setsockopt(fd, level, option, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    (void)level;
    (void)option;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

using socket_option_setter = void (*)(int fd, boost::system::error_code& ec);

void set_dual_stack_socket_option(int fd, bool ipv6, socket_option_setter set_v4, socket_option_setter set_v6, boost::system::error_code& ec)
{
    ec.clear();
    if (!ipv6)
    {
        set_v4(fd, ec);
        return;
    }

    boost::system::error_code v4_ec;
    boost::system::error_code v6_ec;
    set_v4(fd, v4_ec);
    set_v6(fd, v6_ec);
    if (!v4_ec || !v6_ec)
    {
        ec.clear();
        return;
    }

    ec = v6_ec;
}

boost::asio::ip::udp::endpoint make_v4_endpoint(const in_addr& addr, uint16_t port)
{
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v4(bytes), boost::endian::big_to_native(port)};
}

boost::asio::ip::udp::endpoint make_v6_endpoint(const in6_addr& addr, uint16_t port, uint32_t scope_id)
{
    boost::asio::ip::address_v6::bytes_type bytes{};
    const auto normalized_scope_id = static_cast<boost::asio::ip::scope_id_type>(scope_id);
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v6(bytes, normalized_scope_id), boost::endian::big_to_native(port)};
}

#ifdef __linux__
bool has_valid_cmsg_payload(const cmsghdr* cm, std::size_t payload_len) { return cm->cmsg_len >= CMSG_LEN(payload_len); }

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
    return make_v6_endpoint(addr->sin6_addr, addr->sin6_port, addr->sin6_scope_id);
}
#endif

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

boost::asio::ip::udp::endpoint endpoint_from_sockaddr_v4(const sockaddr_storage& addr, std::size_t len)
{
    if (len < sizeof(sockaddr_in))
    {
        return {};
    }
    const auto* v4 = reinterpret_cast<const sockaddr_in*>(&addr);
    return make_v4_endpoint(v4->sin_addr, v4->sin_port);
}

boost::asio::ip::udp::endpoint endpoint_from_sockaddr_v6(const sockaddr_storage& addr, std::size_t len)
{
    if (len < sizeof(sockaddr_in6))
    {
        return {};
    }
    const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&addr);
    return make_v6_endpoint(v6->sin6_addr, v6->sin6_port, v6->sin6_scope_id);
}

}    // namespace

void set_socket_mark(const socket_handle_t fd, uint32_t mark, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    if (mark == 0)
    {
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    (void)mark;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

void set_socket_transparent_v4(int fd, boost::system::error_code& ec)
{
    set_socket_bool_option(fd, SOL_IP, IP_TRANSPARENT, ec);
}

void set_socket_transparent_v6(int fd, boost::system::error_code& ec)
{
    set_socket_bool_option(fd, SOL_IPV6, IPV6_TRANSPARENT, ec);
}

void set_socket_transparent(int fd, bool ipv6, boost::system::error_code& ec)
{
    set_dual_stack_socket_option(fd, ipv6, set_socket_transparent_v4, set_socket_transparent_v6, ec);
}

void set_socket_recv_origdst_v4(int fd, boost::system::error_code& ec)
{
    set_socket_bool_option(fd, SOL_IP, IP_RECVORIGDSTADDR, ec);
}

void set_socket_recv_origdst_v6(int fd, boost::system::error_code& ec)
{
    set_socket_bool_option(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, ec);
}

void set_socket_recv_origdst(int fd, bool ipv6, boost::system::error_code& ec)
{
    set_dual_stack_socket_option(fd, ipv6, set_socket_recv_origdst_v4, set_socket_recv_origdst_v6, ec);
}

boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr)
{
    if (!addr.is_v6())
    {
        return addr;
    }
    const auto v6 = addr.to_v6();
    if (!v6.is_v4_mapped())
    {
        return addr;
    }
    return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6);
}

boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep)
{
    const auto addr = normalize_address(ep.address());
    if (addr.is_v6())
    {
        const auto v6 = addr.to_v6();
        return {boost::asio::ip::address_v6(v6.to_bytes(), v6.scope_id()), ep.port()};
    }
    return {addr, ep.port()};
}

uint64_t fnv1a_64(const std::string_view data)
{
    return fnv1a_update(constants::net::kFnvOffsetBasis64, reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

uint64_t endpoint_hash(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized = normalize_endpoint(endpoint);
    uint64_t hash = constants::net::kFnvOffsetBasis64;
    const uint8_t family = normalized.address().is_v4() ? 4U : 6U;
    hash = fnv1a_update(hash, &family, sizeof(family));
    if (normalized.address().is_v4())
    {
        const auto bytes = normalized.address().to_v4().to_bytes();
        hash = fnv1a_update(hash, bytes.data(), bytes.size());
    }
    else
    {
        const auto bytes = normalized.address().to_v6().to_bytes();
        hash = fnv1a_update(hash, bytes.data(), bytes.size());
    }
    const auto port_be = boost::endian::native_to_big(normalized.port());
    hash = fnv1a_update(hash, reinterpret_cast<const unsigned char*>(&port_be), sizeof(port_be));
    return hash;
}

#ifdef __linux__
std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg)
{
    for (auto* cm = CMSG_FIRSTHDR(&msg); cm != nullptr; cm = next_cmsg_header(msg, cm))
    {
        const auto ep = parse_original_dst_control_message(cm);
        if (ep.has_value())
        {
            return ep;
        }
    }
    return std::nullopt;
}
#endif

boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len)
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

bool get_original_tcp_dst(boost::asio::ip::tcp::socket& socket, boost::asio::ip::tcp::endpoint& endpoint, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    boost::system::error_code peer_ec;
    const auto peer_endpoint = socket.remote_endpoint(peer_ec);
    const bool prefer_ipv6 = !peer_ec && peer_endpoint.address().is_v6();

    const auto try_get_original_dst = [&](int level, int option, boost::system::error_code& op_ec) -> bool
    {
        sockaddr_storage addr{};
        decltype(addrinfo{}.ai_addrlen) addr_len = sizeof(addr);
        if (getsockopt(socket.native_handle(), level, option, &addr, &addr_len) != 0)
        {
            op_ec = boost::system::error_code(errno, boost::system::system_category());
            return false;
        }

        const auto udp_endpoint = endpoint_from_sockaddr(addr, addr_len);
        if (udp_endpoint.port() == 0)
        {
            op_ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
            return false;
        }

        endpoint = {udp_endpoint.address(), udp_endpoint.port()};
        op_ec.clear();
        return true;
    };

    if (prefer_ipv6)
    {
        boost::system::error_code v6_ec;
        boost::system::error_code v4_ec;
        if (try_get_original_dst(SOL_IPV6, IP6T_SO_ORIGINAL_DST, v6_ec))
        {
            return true;
        }
        if (try_get_original_dst(SOL_IP, SO_ORIGINAL_DST, v4_ec))
        {
            return true;
        }
#ifdef __linux__
        log_original_dst_getsockopt_failure(SOL_IPV6, IP6T_SO_ORIGINAL_DST, v6_ec);
        log_original_dst_getsockopt_failure(SOL_IP, SO_ORIGINAL_DST, v4_ec);
#endif
        boost::system::error_code local_ec;
        if (try_get_original_dst_from_local_endpoint(socket, endpoint, local_ec))
        {
            LOG_INFO("get original tcp dst fallback to local endpoint {}:{} after getsockopt failure v6 {} v4 {}",
                     endpoint.address().to_string(),
                     endpoint.port(),
                     v6_ec.message(),
                     v4_ec.message());
            return true;
        }
        ec = select_original_dst_error(true, v4_ec, v6_ec);
        if (!ec)
        {
            ec = local_ec;
        }
        return false;
    }

    boost::system::error_code v4_ec;
    boost::system::error_code v6_ec;
    if (try_get_original_dst(SOL_IP, SO_ORIGINAL_DST, v4_ec))
    {
        return true;
    }
    if (try_get_original_dst(SOL_IPV6, IP6T_SO_ORIGINAL_DST, v6_ec))
    {
        return true;
    }
#ifdef __linux__
    log_original_dst_getsockopt_failure(SOL_IP, SO_ORIGINAL_DST, v4_ec);
    log_original_dst_getsockopt_failure(SOL_IPV6, IP6T_SO_ORIGINAL_DST, v6_ec);
#endif
    boost::system::error_code local_ec;
    if (try_get_original_dst_from_local_endpoint(socket, endpoint, local_ec))
    {
        LOG_INFO("get original tcp dst fallback to local endpoint {}:{} after getsockopt failure v4 {} v6 {}",
                 endpoint.address().to_string(),
                 endpoint.port(),
                 v4_ec.message(),
                 v6_ec.message());
        return true;
    }
    ec = select_original_dst_error(false, v4_ec, v6_ec);
    if (!ec)
    {
        ec = local_ec;
    }
    return false;
#else
    (void)socket;
    (void)endpoint;
    ec = std::make_error_code(std::errc::not_supported);
    return false;
#endif
}

}    // namespace mux::net
