#ifndef TUN_LWIP_H
#define TUN_LWIP_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

extern "C"
{
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/ip6.h"
#include "lwip/nd6.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/priv/tcp_priv.h"
}
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address.hpp>
namespace relay::tun
{

[[nodiscard]] boost::asio::ip::address lwip_to_address(const ip_addr_t& addr);

[[nodiscard]] boost::asio::ip::udp::endpoint lwip_to_udp_endpoint(const ip_addr_t& addr, uint16_t port);

[[nodiscard]] std::string lwip_ip_to_string(const ip_addr_t& addr);

[[nodiscard]] bool address_to_lwip(const boost::asio::ip::address& address, ip_addr_t& out);

[[nodiscard]] bool endpoint_to_lwip(const boost::asio::ip::udp::endpoint& endpoint, ip_addr_t& out_addr, uint16_t& out_port);

[[nodiscard]] std::vector<uint8_t> pbuf_to_vector(const pbuf* buf);

[[nodiscard]] std::string lwip_error_message(err_t err);

}    // namespace relay::tun

#endif
