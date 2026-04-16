#include "tcp_connect_flow.h"

#include <utility>

#include <boost/asio/ip/address.hpp>

#include "outbound.h"

namespace relay
{

namespace
{

route_decision make_no_route_decision()
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    return decision;
}

}    // namespace

boost::asio::awaitable<tcp_connect_flow_result> prepare_tcp_connect_flow(const request_context& request,
                                                                         const std::shared_ptr<router>& router_instance,
                                                                         const boost::asio::any_io_executor& executor,
                                                                         const config& cfg)
{
    tcp_connect_flow_result result;
    if (router_instance == nullptr)
    {
        result.decision = make_no_route_decision();
        co_return result;
    }

    boost::system::error_code target_ec;
    const auto target_addr = boost::asio::ip::make_address(request.target_host, target_ec);
    if (target_ec)
    {
        result.decision = co_await router_instance->decide_domain_detail(request.target_host);
    }
    else
    {
        result.decision = co_await router_instance->decide_ip_detail(target_addr);
    }

    if (result.decision.route != route_type::kDirect && result.decision.route != route_type::kProxy)
    {
        co_return result;
    }

    const auto handler = make_outbound_handler(cfg, result.decision.outbound_tag);
    if (handler == nullptr)
    {
        result.decision.route = route_type::kBlock;
        result.decision.outbound_type = "no_route";
        co_return result;
    }
    result.outbound = handler->create_tcp_outbound(executor, request.conn_id, request.trace_id, cfg);
    if (result.outbound == nullptr)
    {
        result.decision.route = route_type::kBlock;
        result.decision.outbound_type = "no_route";
        result.decision.outbound_tag.clear();
    }
    co_return result;
}

}    // namespace relay
