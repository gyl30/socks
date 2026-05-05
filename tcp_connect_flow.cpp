#include "tcp_connect_flow.h"

#include <utility>

#include "log.h"
#include "outbound.h"
#include "constants.h"
#include "route_flow_utils.h"

namespace relay
{

tcp_connect_flow_result prepare_tcp_connect_flow(const request_context& request,
                                                 const std::shared_ptr<router>& router_instance,
                                                 const boost::asio::any_io_executor& executor,
                                                 const config& cfg)
{
    tcp_connect_flow_result result;
    result.decision = resolve_route_decision_for_request(request, router_instance, true);

    if (result.decision.route != route_type::kDirect && result.decision.route != route_type::kProxy)
    {
        return result;
    }

    const auto outbound_class = resolve_outbound_class(cfg, result.decision.outbound_tag);
    if (outbound_class == config_type::outbound_class::kUnsupported)
    {
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} stage prepare_connect_flow out_tag {} missing outbound",
                  log_event::kRoute,
                  request.trace_id,
                  request.conn_id,
                  request.target_host,
                  request.target_port,
                  result.decision.outbound_tag.empty() ? "-" : result.decision.outbound_tag);
        mark_no_route_flow_decision(result.decision);
        return result;
    }
    const auto connect_mark = resolve_socket_mark(cfg, request.inbound_tag, result.decision.outbound_tag);
    result.outbound = create_tcp_outbound_for_tag(executor, request.conn_id, request.trace_id, cfg, result.decision.outbound_tag, connect_mark);
    if (result.outbound == nullptr && outbound_class != config_type::outbound_class::kBlock)
    {
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} stage prepare_connect_flow out_tag {} create outbound failed",
                  log_event::kRoute,
                  request.trace_id,
                  request.conn_id,
                  request.target_host,
                  request.target_port,
                  result.decision.outbound_tag.empty() ? "-" : result.decision.outbound_tag);
        mark_no_route_flow_decision(result.decision, true);
        return result;
    }
    return result;
}

}    // namespace relay
