#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <cstddef>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>

namespace mux::net
{

#ifdef _WIN32
using socket_handle_t = std::uintptr_t;
#else
using socket_handle_t = int;
#endif

void set_socket_mark(socket_handle_t fd, uint32_t mark, boost::system::error_code& ec);

void set_socket_transparent_v4(int fd, boost::system::error_code& ec);

void set_socket_transparent_v6(int fd, boost::system::error_code& ec);

void set_socket_transparent(int fd, bool ipv6, boost::system::error_code& ec);

void set_socket_recv_origdst_v4(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst_v6(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst(int fd, bool ipv6, boost::system::error_code& ec);

[[nodiscard]] boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr);

[[nodiscard]] boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep);

struct udp_endpoint_hash
{
    std::size_t operator()(const boost::asio::ip::udp::endpoint& ep) const noexcept
    {
        const auto normalized = normalize_endpoint(ep);
        std::size_t h = 1469598103934665603ULL;
        auto mix = [&](uint8_t b)
        {
            h ^= b;
            h *= 1099511628211ULL;
        };
        if (normalized.address().is_v4())
        {
            const auto bytes = normalized.address().to_v4().to_bytes();
            for (const auto b : bytes)
            {
                mix(b);
            }
        }
        else
        {
            const auto bytes = normalized.address().to_v6().to_bytes();
            for (const auto b : bytes)
            {
                mix(b);
            }
        }
        const auto port = normalized.port();
        mix(static_cast<uint8_t>(port >> 8));
        mix(static_cast<uint8_t>(port & 0xFF));
        return h;
    }
};

struct udp_endpoint_equal
{
    bool operator()(const boost::asio::ip::udp::endpoint& lhs, const boost::asio::ip::udp::endpoint& rhs) const noexcept
    {
        return normalize_endpoint(lhs) == normalize_endpoint(rhs);
    }
};

[[nodiscard]] uint64_t fnv1a_64(std::string_view data);

[[nodiscard]] uint64_t endpoint_hash(const boost::asio::ip::udp::endpoint& endpoint);

#ifdef __linux__
[[nodiscard]] std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg);
#endif

[[nodiscard]] boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len);

[[nodiscard]] bool get_original_tcp_dst(boost::asio::ip::tcp::socket& socket,
                                        boost::asio::ip::tcp::endpoint& endpoint,
                                        boost::system::error_code& ec);

}    // namespace mux::net

#endif
