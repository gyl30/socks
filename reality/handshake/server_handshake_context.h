#ifndef REALITY_SERVER_HANDSHAKE_CONTEXT_H
#define REALITY_SERVER_HANDSHAKE_CONTEXT_H

#include <string>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>

namespace reality
{

struct server_handshake_context
{
    boost::asio::ip::tcp::socket* socket = nullptr;
    uint32_t conn_id = 0;
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string sni;
};

}    // namespace reality

#endif
