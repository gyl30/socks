#include <iostream>
#include <memory>
#include <string>

#include <boost/asio/ip/address.hpp>

#include "config.h"
#include "router.h"

namespace
{

relay::config make_router_config()
{
    relay::config cfg;
    cfg.workers = 1;

    relay::config::outbound_entry_t direct_outbound;
    direct_outbound.type = "direct";
    direct_outbound.tag = "direct";
    cfg.outbounds.push_back(direct_outbound);

    relay::config::outbound_entry_t block_outbound;
    block_outbound.type = "block";
    block_outbound.tag = "block";
    cfg.outbounds.push_back(block_outbound);

    relay::config::route_rule_t socks_rule;
    socks_rule.type = "inbound";
    socks_rule.values = {"socks-in"};
    socks_rule.out = "direct";
    cfg.routing.push_back(std::move(socks_rule));

    relay::config::route_rule_t tun_rule;
    tun_rule.type = "inbound";
    tun_rule.values = {"tun-in"};
    tun_rule.out = "block";
    cfg.routing.push_back(std::move(tun_rule));

    return cfg;
}

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

bool require_decision(const relay::route_decision& decision,
                      const relay::route_type expected_route,
                      const std::string& expected_outbound_tag,
                      const std::string& expected_match_type,
                      const std::string& expected_match_value)
{
    return require(decision.route == expected_route, "unexpected route type") &&
           require(decision.outbound_tag == expected_outbound_tag, "unexpected outbound tag") &&
           require(decision.match_type == expected_match_type, "unexpected match type") &&
           require(decision.match_value == expected_match_value, "unexpected match value") &&
           require(decision.matched, "route should be marked matched");
}

}    // namespace

int main()
{
    const relay::config cfg = make_router_config();
    auto shared_state = relay::router::build_shared_state(cfg);
    if (!require(shared_state != nullptr, "failed to build shared router state"))
    {
        return 1;
    }

    relay::router shared_socks_router(shared_state, "socks-in");
    relay::router shared_tun_router(shared_state, "tun-in");
    relay::router legacy_router(cfg, "socks-in");

    const bool ok =
        require_decision(shared_socks_router.decide_domain_detail("example.com"),
                         relay::route_type::kDirect,
                         "direct",
                         "inbound",
                         "socks-in") &&
        require_decision(shared_tun_router.decide_domain_detail("example.com"),
                         relay::route_type::kBlock,
                         "block",
                         "inbound",
                         "tun-in") &&
        require_decision(legacy_router.decide_ip_detail(boost::asio::ip::make_address("203.0.113.7")),
                         relay::route_type::kDirect,
                         "direct",
                         "inbound",
                         "socks-in");

    return ok ? 0 : 1;
}
