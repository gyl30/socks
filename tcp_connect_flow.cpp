#include "tcp_connect_flow.h"

#include <utility>

#include "outbound.h"
#include "route_flow_utils.h"

namespace relay
{

boost::asio::awaitable<tcp_connect_flow_result> prepare_tcp_connect_flow(const request_context& request,
                                                                         const std::shared_ptr<router>& router_instance,
                                                                         const boost::asio::any_io_executor& executor,
                                                                         const config& cfg)
{
    tcp_connect_flow_result result;
    result.decision = co_await resolve_route_decision_for_request(request, router_instance, false);

    if (result.decision.route != route_type::kDirect && result.decision.route != route_type::kProxy)
    {
        co_return result;
    }

    const auto handler = make_outbound_handler(cfg, result.decision.outbound_tag);
    if (handler == nullptr)
    {
        mark_no_route_flow_decision(result.decision);
        co_return result;
    }
    result.outbound = handler->create_tcp_outbound(executor, request.conn_id, request.trace_id, cfg);
    if (result.outbound == nullptr)
    {
        mark_no_route_flow_decision(result.decision, true);
    }
    co_return result;
}

}    // namespace relay
