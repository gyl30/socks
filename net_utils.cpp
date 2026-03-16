#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <optional>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
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

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/system/detail/system_category.hpp>
#include <boost/endian/conversion.hpp>

#include "net_utils.h"
#include "log.h"

namespace mux::net
{

namespace
{

constexpr std::uint64_t kFnvOffsetBasis64 = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime64 = 1099511628211ULL;

std::uint64_t fnv1a_update(std::uint64_t hash, const unsigned char* data, const std::size_t len)
{
    for (std::size_t i = 0; i < len; ++i)
    {
        hash ^= static_cast<std::uint64_t>(data[i]);
        hash *= kFnvPrime64;
    }
    return hash;
}

#ifdef __linux__
std::uint64_t monotonic_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

void log_original_dst_getsockopt_failure(const int level, const int option, const boost::system::error_code& ec)
{
    constexpr std::uint64_t kLogIntervalMs = 10'000;
    static std::atomic<std::uint64_t> last_log_ms{0};
    static std::atomic<std::uint32_t> suppressed{0};

    const auto now = monotonic_ms();
    auto last = last_log_ms.load(std::memory_order_relaxed);
    if (now - last < kLogIntervalMs)
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
    LOG_INFO("get original tcp dst getsockopt failed level={} opt={} errno={} error={} suppressed={}",
             level,
             option,
             ec.value(),
             ec.message(),
             dropped);
}
#endif

boost::asio::ip::udp::endpoint make_v4_endpoint(const in_addr& addr, const std::uint16_t port)
{
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v4(bytes), boost::endian::big_to_native(port)};
}

boost::asio::ip::udp::endpoint make_v6_endpoint(const in6_addr& addr, const std::uint16_t port)
{
    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), &addr, bytes.size());
    return {boost::asio::ip::address_v6(bytes), boost::endian::big_to_native(port)};
}

#ifdef __linux__
bool has_valid_cmsg_payload(const cmsghdr* cm, const std::size_t payload_len) { return cm->cmsg_len >= CMSG_LEN(payload_len); }

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

void set_socket_mark(int fd, const std::uint32_t mark, boost::system::error_code& ec)
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

void set_socket_transparent_v4(const int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

void set_socket_transparent_v6(const int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

void set_socket_transparent(const int fd, const bool ipv6, boost::system::error_code& ec)
{
    ec.clear();
    if (!ipv6)
    {
        set_socket_transparent_v4(fd, ec);
        return;
    }

    boost::system::error_code v4_ec;
    boost::system::error_code v6_ec;
    set_socket_transparent_v4(fd, v4_ec);
    set_socket_transparent_v6(fd, v6_ec);

    // 双栈或纯 ipv6 场景下只要有一侧成功即可 避免把可用 socket 误判为失败
    if (!v4_ec || !v6_ec)
    {
        ec.clear();
        return;
    }

    ec = v6_ec;
    return;
}

void set_socket_recv_origdst_v4(const int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

void set_socket_recv_origdst_v6(const int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    ec = std::make_error_code(std::errc::not_supported);
    return;
#endif
}

void set_socket_recv_origdst(const int fd, const bool ipv6, boost::system::error_code& ec)
{
    ec.clear();
    if (!ipv6)
    {
        set_socket_recv_origdst_v4(fd, ec);
        return;
    }

    boost::system::error_code v4_ec;
    boost::system::error_code v6_ec;
    set_socket_recv_origdst_v4(fd, v4_ec);
    set_socket_recv_origdst_v6(fd, v6_ec);

    // 原始目标地址辅助信息和透明代理选项保持同样策略 任一协议栈成功即可继续
    if (!v4_ec || !v6_ec)
    {
        ec.clear();
        return;
    }

    ec = v6_ec;
    return;
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

    return addr;
}

boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep) { return {normalize_address(ep.address()), ep.port()}; }

std::uint64_t fnv1a_64(const std::string_view data)
{
    return fnv1a_update(kFnvOffsetBasis64, reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

std::uint64_t endpoint_hash(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized = normalize_endpoint(endpoint);
    std::uint64_t hash = kFnvOffsetBasis64;
    const std::uint8_t family = normalized.address().is_v4() ? 4U : 6U;
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

bool get_original_tcp_dst(boost::asio::ip::tcp::socket& socket, boost::asio::ip::tcp::endpoint& endpoint, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    boost::system::error_code peer_ec;
    const auto peer_endpoint = socket.remote_endpoint(peer_ec);
    const bool prefer_ipv6 = !peer_ec && peer_endpoint.address().is_v6();

    const auto try_get_original_dst = [&](const int level, const int option, boost::system::error_code& op_ec) -> bool
    {
        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        if (getsockopt(socket.native_handle(), level, option, &addr, &addr_len) != 0)
        {
            op_ec = boost::system::error_code(errno, boost::system::system_category());
#ifdef __linux__
            log_original_dst_getsockopt_failure(level, option, op_ec);
#endif
            return false;
        }

        const auto udp_endpoint = endpoint_from_sockaddr(addr, addr_len);
        if (udp_endpoint.port() == 0)
        {
            op_ec = boost::asio::error::address_family_not_supported;
            return false;
        }

        endpoint = {udp_endpoint.address(), udp_endpoint.port()};
        op_ec.clear();
        return true;
    };

    boost::system::error_code last_ec;
    if (prefer_ipv6)
    {
        if (try_get_original_dst(SOL_IPV6, IP6T_SO_ORIGINAL_DST, ec))
        {
            return true;
        }
        last_ec = ec;
        if (try_get_original_dst(SOL_IP, SO_ORIGINAL_DST, ec))
        {
            return true;
        }
        ec = ec ? ec : last_ec;
        return false;
    }

    if (try_get_original_dst(SOL_IP, SO_ORIGINAL_DST, ec))
    {
        return true;
    }
    last_ec = ec;
    if (try_get_original_dst(SOL_IPV6, IP6T_SO_ORIGINAL_DST, ec))
    {
        return true;
    }
    ec = ec ? ec : last_ec;
    return false;
#else
    (void)socket;
    (void)endpoint;
    ec = std::make_error_code(std::errc::not_supported);
    return false;
#endif
}

}    // namespace mux::net
