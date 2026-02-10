#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

#include <asio/ip/udp.hpp>
#include <asio/ip/address.hpp>

struct msghdr;
struct sockaddr_storage;

namespace mux::net
{

[[nodiscard]] bool set_socket_mark(int fd, std::uint32_t mark, std::error_code& ec);

[[nodiscard]] bool set_socket_transparent(int fd, bool ipv6, std::error_code& ec);

[[nodiscard]] bool set_socket_recv_origdst(int fd, bool ipv6, std::error_code& ec);

[[nodiscard]] asio::ip::address normalize_address(const asio::ip::address& addr);

[[nodiscard]] asio::ip::udp::endpoint normalize_endpoint(const asio::ip::udp::endpoint& ep);

[[nodiscard]] std::optional<asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg);

[[nodiscard]] asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len);

}    // namespace mux::net

#endif
