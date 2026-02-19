#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <system_error>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>

struct msghdr;
struct sockaddr_storage;

namespace mux::net
{

[[nodiscard]] std::expected<void, boost::system::error_code> set_socket_mark(int fd, std::uint32_t mark);

[[nodiscard]] std::expected<void, boost::system::error_code> set_socket_transparent(int fd, bool ipv6);

[[nodiscard]] std::expected<void, boost::system::error_code> set_socket_recv_origdst(int fd, bool ipv6);

[[nodiscard]] boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr);

[[nodiscard]] boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep);

[[nodiscard]] std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg);

[[nodiscard]] boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len);

}    // namespace mux::net

#endif
