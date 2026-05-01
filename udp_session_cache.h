#ifndef UDP_SESSION_CACHE_H
#define UDP_SESSION_CACHE_H

#include <cstdint>

#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

namespace relay
{

struct udp_endpoint_cache_entry
{
    boost::asio::ip::udp::endpoint endpoint;
    uint64_t expires_at = 0;
    boost::system::error_code last_error;
    bool negative = false;
};

struct udp_peer_cache_entry
{
    uint64_t expires_at = 0;
};

}    // namespace relay

#endif
