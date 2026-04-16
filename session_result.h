#ifndef SESSION_RESULT_H
#define SESSION_RESULT_H

#include <cstdint>
#include <memory>

#include <boost/system/error_code.hpp>

#include "router.h"
#include "tcp_outbound_stream.h"

namespace relay
{

struct stream_relay_result
{
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    uint64_t duration_ms = 0;
    boost::system::error_code ec;
};

struct tcp_flow_result
{
    route_decision decision;
    std::shared_ptr<tcp_outbound_stream> stream;
    tcp_outbound_connect_result connect_result;
};

enum class udp_flow_mode : uint8_t
{
    kBlock,
    kDirect,
    kProxy
};

struct udp_flow_result
{
    route_decision decision;
    udp_flow_mode mode = udp_flow_mode::kBlock;
};

}    // namespace relay

#endif
