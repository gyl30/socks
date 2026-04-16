#ifndef UDP_SESSION_FLOW_H
#define UDP_SESSION_FLOW_H

#include <memory>

#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "request_context.h"
#include "router.h"
#include "session_result.h"

namespace relay
{

boost::asio::awaitable<udp_flow_result> prepare_udp_route_flow(const request_context& request, const std::shared_ptr<router>& router);

boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_flow(const boost::asio::any_io_executor& executor,
                                                                                const request_context& request,
                                                                                const std::string& outbound_tag,
                                                                                const config& cfg);

}    // namespace relay

#endif
