#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <filesystem>

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

bool require_file_rule_parse_and_dump()
{
    const auto rules_path = std::filesystem::path("router_regression_domains.txt");
    const auto config_path = std::filesystem::path("router_regression_config.json");
    std::error_code fs_error;
    {
        std::ofstream rules_file(rules_path);
        if (!rules_file.is_open())
        {
            return require(false, "failed to create router regression rules file");
        }
        rules_file << "example.com\n";
    }
    {
        std::ofstream config_file(config_path);
        if (!config_file.is_open())
        {
            std::filesystem::remove(rules_path, fs_error);
            return require(false, "failed to create router regression config file");
        }
        config_file << "{\n"
                    << "  \"workers\": 1,\n"
                    << "  \"log\": {\"level\": \"info\", \"file\": \"router-regression.log\"},\n"
                    << "  \"timeout\": {\"read\": 5, \"write\": 5, \"connect\": 5, \"idle\": 30},\n"
                    << "  \"inbounds\": [\n"
                    << "    {\"type\": \"socks\", \"tag\": \"socks-in\", \"settings\": {\"host\": \"127.0.0.1\", \"port\": 1080, \"auth\": false}}\n"
                    << "  ],\n"
                    << "  \"outbounds\": [\n"
                    << "    {\"type\": \"direct\", \"tag\": \"direct\"},\n"
                    << "    {\"type\": \"block\", \"tag\": \"block\"}\n"
                    << "  ],\n"
                    << "  \"routing\": [\n"
                    << "    {\"type\": \"domain\", \"file\": \"" << rules_path.string() << "\", \"out\": \"direct\"}\n"
                    << "  ]\n"
                    << "}\n";
    }

    const auto parsed = relay::parse_config(config_path.string());
    const std::string dumped = parsed.has_value() ? relay::dump_config(*parsed) : std::string();
    bool ok = require(parsed.has_value(), "failed to parse router regression file-backed config");
    if (ok)
    {
        ok = require(parsed->routing.size() == 1, "unexpected routing count") &&
             require(parsed->routing.front().values.size() == 1, "file-backed values not materialized") &&
             require(parsed->routing.front().values.front() == "example.com", "unexpected file-backed value") &&
             require(parsed->routing.front().file == rules_path.string(), "file path not preserved");
    }
    if (ok)
    {
        auto shared_state = relay::router::build_shared_state(*parsed);
        ok = require(shared_state != nullptr, "failed to build shared state for file-backed rule");
        if (ok)
        {
            relay::router parsed_router(shared_state, "socks-in");
            ok = require_decision(parsed_router.decide_domain_detail("example.com"),
                                  relay::route_type::kDirect,
                                  "direct",
                                  "domain",
                                  "example.com");
        }
    }
    if (ok)
    {
        const auto expected_fragment = std::string("\"file\": \"") + rules_path.string() + "\"";
        ok = require(dumped.find(expected_fragment) != std::string::npos, "dump_config expanded file-backed route");
    }

    std::filesystem::remove(config_path, fs_error);
    std::filesystem::remove(rules_path, fs_error);
    return ok;
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
    relay::router shared_socks_ip_router(shared_state, "socks-in");

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
        require_decision(shared_socks_ip_router.decide_ip_detail(boost::asio::ip::make_address("203.0.113.7")),
                         relay::route_type::kDirect,
                         "direct",
                         "inbound",
                         "socks-in") &&
        require_file_rule_parse_and_dump();

    return ok ? 0 : 1;
}
