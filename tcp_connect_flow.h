#ifndef TCP_CONNECT_FLOW_H
#define TCP_CONNECT_FLOW_H

#include <memory>
#include <boost/asio/any_io_executor.hpp>

#include "config.h"
#include "router.h"
#include "request_context.h"
#include "tcp_outbound_stream.h"

namespace relay
{

struct tcp_connect_flow_result
{
    route_decision decision;
    std::shared_ptr<tcp_outbound_stream> outbound;
};

[[nodiscard]] tcp_connect_flow_result prepare_tcp_connect_flow(const request_context& request,
                                                               const std::shared_ptr<router>& router_instance,
                                                               const boost::asio::any_io_executor& executor,
                                                               const config& cfg);

}    // namespace relay

#endif
