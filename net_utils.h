#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

struct msghdr;
struct sockaddr_storage;

namespace mux::net
{

void set_socket_mark(int fd, std::uint32_t mark, boost::system::error_code& ec);

void set_socket_transparent_v4(int fd, boost::system::error_code& ec);

void set_socket_transparent_v6(int fd, boost::system::error_code& ec);

void set_socket_transparent(int fd, bool ipv6, boost::system::error_code& ec);

void set_socket_recv_origdst_v4(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst_v6(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst(int fd, bool ipv6, boost::system::error_code& ec);

[[nodiscard]] boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr);

[[nodiscard]] boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep);

[[nodiscard]] std::uint64_t fnv1a_64(std::string_view data);

[[nodiscard]] std::uint64_t endpoint_hash(const boost::asio::ip::udp::endpoint& endpoint);

[[nodiscard]] std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg);

[[nodiscard]] boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len);

[[nodiscard]] bool get_original_tcp_dst(boost::asio::ip::tcp::socket& socket,
                                        boost::asio::ip::tcp::endpoint& endpoint,
                                        boost::system::error_code& ec);

}    // namespace mux::net

#endif
