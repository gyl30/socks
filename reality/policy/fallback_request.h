#ifndef REALITY_FALLBACK_REQUEST_H
#define REALITY_FALLBACK_REQUEST_H

#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>

namespace reality
{

struct fallback_request
{
    boost::asio::ip::tcp::socket* client_socket = nullptr;
    uint32_t conn_id = 0;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string sni;
    std::vector<uint8_t> client_hello_record;
};

}    // namespace reality

#endif
