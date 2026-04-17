#ifndef ROUTE_FLOW_UTILS_H
#define ROUTE_FLOW_UTILS_H

#include <memory>

#include <boost/asio/awaitable.hpp>

#include "request_context.h"
#include "router.h"

namespace relay
{

[[nodiscard]] route_decision make_no_route_flow_decision();
void mark_no_route_flow_decision(route_decision& decision, bool clear_outbound_tag = false);
[[nodiscard]] boost::asio::awaitable<route_decision> resolve_route_decision_for_request(
    const request_context& request, const std::shared_ptr<router>& router_instance, bool normalize_ip_literal);

}    // namespace relay

#endif
