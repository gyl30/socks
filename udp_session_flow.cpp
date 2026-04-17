#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "outbound.h"
#include "request_context.h"
#include "route_flow_utils.h"
#include "router.h"
#include "session_result.h"
#include "udp_session_flow.h"

namespace relay
{

namespace
{

[[nodiscard]] udp_flow_mode to_udp_flow_mode(const route_type route)
{
    switch (route)
    {
        case route_type::kDirect:
            return udp_flow_mode::kDirect;
        case route_type::kProxy:
            return udp_flow_mode::kProxy;
        case route_type::kBlock:
        default:
            return udp_flow_mode::kBlock;
    }
}

}    // namespace

boost::asio::awaitable<udp_flow_result> prepare_udp_route_flow(const request_context& request, const std::shared_ptr<router>& router)
{
    udp_flow_result result;
    result.decision = co_await resolve_route_decision_for_request(request, router, true);
    result.mode = to_udp_flow_mode(result.decision.route);
    co_return result;
}

boost::asio::awaitable<udp_proxy_outbound_connect_result> connect_udp_proxy_flow(const boost::asio::any_io_executor& executor,
                                                                                 const request_context& request,
                                                                                 const std::string& outbound_tag,
                                                                                 const config& cfg)
{
    co_return co_await connect_udp_proxy_outbound(executor, request.conn_id, request.trace_id, cfg, outbound_tag);
}

}    // namespace relay
