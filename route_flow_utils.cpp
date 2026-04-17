#include <memory>

#include <boost/asio/ip/address.hpp>

#include "net_utils.h"
#include "route_flow_utils.h"

namespace relay
{

route_decision make_no_route_flow_decision()
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    return decision;
}

void mark_no_route_flow_decision(route_decision& decision, const bool clear_outbound_tag)
{
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    if (clear_outbound_tag)
    {
        decision.outbound_tag.clear();
    }
}

boost::asio::awaitable<route_decision> resolve_route_decision_for_request(
    const request_context& request, const std::shared_ptr<router>& router_instance, const bool normalize_ip_literal)
{
    if (router_instance == nullptr)
    {
        co_return make_no_route_flow_decision();
    }

    boost::system::error_code target_ec;
    auto target_addr = boost::asio::ip::make_address(request.target_host, target_ec);
    if (target_ec)
    {
        co_return co_await router_instance->decide_domain_detail(request.target_host);
    }
    if (normalize_ip_literal)
    {
        target_addr = net::normalize_address(target_addr);
    }
    co_return co_await router_instance->decide_ip_detail(target_addr);
}

}    // namespace relay
