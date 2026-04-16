#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "net_utils.h"
#include "outbound.h"
#include "request_context.h"
#include "router.h"
#include "session_result.h"
#include "udp_session_flow.h"

namespace relay
{

namespace
{

route_decision make_blocked_decision()
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    return decision;
}

}    // namespace

boost::asio::awaitable<udp_flow_result> prepare_udp_route_flow(const request_context& request, const std::shared_ptr<router>& router)
{
    udp_flow_result result;
    if (router == nullptr)
    {
        result.decision = make_blocked_decision();
        result.mode = udp_flow_mode::kBlock;
        co_return result;
    }

    boost::system::error_code ec;
    const auto target_addr = boost::asio::ip::make_address(request.target_host, ec);
    if (ec)
    {
        result.decision = co_await router->decide_domain_detail(request.target_host);
    }
    else
    {
        result.decision = co_await router->decide_ip_detail(net::normalize_address(target_addr));
    }

    switch (result.decision.route)
    {
        case route_type::kDirect:
            result.mode = udp_flow_mode::kDirect;
            break;
        case route_type::kProxy:
            result.mode = udp_flow_mode::kProxy;
            break;
        case route_type::kBlock:
        default:
            result.mode = udp_flow_mode::kBlock;
            break;
    }
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
