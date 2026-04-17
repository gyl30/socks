#include <memory>
#include <string>
#include <vector>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include "log.h"
#include "router.h"
#include "constants.h"
#include "ip_matcher.h"
#include "config_type_facts.h"
#include "domain_matcher.h"

namespace relay
{

struct router::compiled_rule
{
    route_type route = route_type::kBlock;
    std::string type;
    std::string outbound_tag;
    std::string outbound_type;
    std::vector<std::string> values;
    std::shared_ptr<ip_matcher> ip_rules;
    std::shared_ptr<domain_matcher> domain_rules;
};

namespace
{

[[nodiscard]] route_type map_outbound_route(const std::string& outbound_type)
{
    const auto outbound_class = config_type::classify_outbound_type(outbound_type);
    if (outbound_class == config_type::outbound_class::kDirect)
    {
        return route_type::kDirect;
    }
    if (outbound_class == config_type::outbound_class::kProxy)
    {
        return route_type::kProxy;
    }
    return route_type::kBlock;
}

[[nodiscard]] const std::vector<std::string>& get_route_source_values(const config::route_rule_t& rule)
{
    return rule.file.empty() ? rule.values : rule.file_values;
}

}    // namespace

std::string to_string(const route_type& type)
{
    if (type == route_type::kDirect)
    {
        return "direct";
    }
    if (type == route_type::kProxy)
    {
        return "proxy";
    }
    if (type == route_type::kBlock)
    {
        return "block";
    }
    return "unknown";
}

router::router(const config& cfg, std::string inbound_tag) : cfg_(cfg), inbound_tag_(std::move(inbound_tag)) {}

bool router::load()
{
    rules_.clear();
    rules_.reserve(cfg_.routing.size());

    for (const auto& rule : cfg_.routing)
    {
        auto compiled = make_compiled_rule(rule);
        if (compiled == nullptr)
        {
            return false;
        }
        log_loaded_rule(rule, *compiled);
        rules_.push_back(std::move(compiled));
    }
    return true;
}

std::shared_ptr<router::compiled_rule> router::make_compiled_rule(const config::route_rule_t& rule) const
{
    const auto* outbound = find_outbound_entry(cfg_, rule.out);
    if (outbound == nullptr)
    {
        LOG_ERROR("{} inbound_tag {} stage load_rule out {} error outbound_not_found",
                  log_event::kRoute,
                  inbound_tag_,
                  rule.out);
        return nullptr;
    }

    auto compiled = std::make_shared<compiled_rule>();
    compiled->type = rule.type;
    compiled->outbound_tag = rule.out;
    compiled->outbound_type = outbound->type;
    compiled->route = map_outbound_route(outbound->type);
    if (!populate_compiled_rule_values(rule, *compiled))
    {
        return nullptr;
    }
    return compiled;
}

bool router::populate_compiled_rule_values(const config::route_rule_t& rule, compiled_rule& compiled) const
{
    const auto& source_values = get_route_source_values(rule);
    if (rule.type == "inbound")
    {
        compiled.values = source_values;
        return true;
    }
    if (rule.type == "ip")
    {
        compiled.ip_rules = std::make_shared<ip_matcher>();
        for (const auto& value : source_values)
        {
            compiled.ip_rules->add_rule(value);
        }
        compiled.ip_rules->optimize();
        return true;
    }
    if (rule.type == "domain")
    {
        compiled.domain_rules = std::make_shared<domain_matcher>();
        for (const auto& value : source_values)
        {
            compiled.domain_rules->add(value);
        }
        return true;
    }

    LOG_ERROR("{} inbound_tag {} stage load_rule type {} error unsupported",
              log_event::kRoute,
              inbound_tag_,
              rule.type);
    return false;
}

route_decision router::make_no_route_decision(const std::string& match_type, const std::string& match_value) const
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    decision.match_type = match_type;
    decision.match_value = match_value;
    return decision;
}

void router::log_loaded_rule(const config::route_rule_t& rule, const compiled_rule& compiled) const
{
    const auto& source_values = get_route_source_values(rule);
    LOG_INFO("{} inbound_tag {} stage load_rule type {} out_tag {} out_type {} value_count {} file {}",
             log_event::kRoute,
             inbound_tag_,
             compiled.type,
             compiled.outbound_tag,
             compiled.outbound_type,
             source_values.size(),
             rule.file.empty() ? "-" : rule.file);
}

bool router::matches_inbound_rule(const compiled_rule& rule) const
{
    return std::find(rule.values.begin(), rule.values.end(), inbound_tag_) != rule.values.end();
}

route_decision router::make_match_decision(
    const compiled_rule& rule, const std::string& match_type, const std::string& match_value) const
{
    route_decision decision;
    decision.route = rule.route;
    decision.outbound_tag = rule.outbound_tag;
    decision.outbound_type = rule.outbound_type;
    decision.match_type = match_type;
    decision.match_value = match_value;
    decision.matched = true;
    return decision;
}

void router::log_route_match(const char* target_field, const std::string& target_value, const route_decision& decision) const
{
    LOG_INFO("{} inbound_tag {} {} {} match_type {} match_value {} out_tag {} out_type {} route {}",
             log_event::kRoute,
             inbound_tag_,
             target_field,
             target_value,
             decision.match_type,
             decision.match_value,
             decision.outbound_tag,
             decision.outbound_type,
             to_string(decision.route));
}

void router::log_no_route(const char* target_field, const std::string& target_value, const route_decision& decision) const
{
    LOG_WARN("{} inbound_tag {} {} {} match_type {} out_type {} route {}",
             log_event::kRoute,
             inbound_tag_,
             target_field,
             target_value,
             decision.match_type,
             decision.outbound_type,
             to_string(decision.route));
}

boost::asio::awaitable<route_decision> router::decide_ip_detail(const boost::asio::ip::address& addr) const
{
    const auto target = addr.to_string();
    for (const auto& rule : rules_)
    {
        if (rule->type == "inbound")
        {
            if (!matches_inbound_rule(*rule))
            {
                continue;
            }
            const auto decision = make_match_decision(*rule, "inbound", inbound_tag_);
            log_route_match("target_ip", target, decision);
            co_return decision;
        }

        if (rule->type != "ip" || rule->ip_rules == nullptr || !rule->ip_rules->match(addr))
        {
            continue;
        }

        const auto decision = make_match_decision(*rule, "ip", target);
        log_route_match("target_ip", target, decision);
        co_return decision;
    }

    auto decision = make_no_route_decision("ip", target);
    log_no_route("target_ip", target, decision);
    co_return decision;
}

boost::asio::awaitable<route_decision> router::decide_domain_detail(const std::string& host) const
{
    const auto target = host.empty() ? std::string("unknown") : host;
    for (const auto& rule : rules_)
    {
        if (rule->type == "inbound")
        {
            if (!matches_inbound_rule(*rule))
            {
                continue;
            }
            const auto decision = make_match_decision(*rule, "inbound", inbound_tag_);
            log_route_match("target_domain", target, decision);
            co_return decision;
        }

        if (rule->type != "domain" || rule->domain_rules == nullptr || !rule->domain_rules->match(host))
        {
            continue;
        }

        const auto decision = make_match_decision(*rule, "domain", target);
        log_route_match("target_domain", target, decision);
        co_return decision;
    }

    auto decision = make_no_route_decision("domain", target);
    log_no_route("target_domain", target, decision);
    co_return decision;
}

boost::asio::awaitable<route_type> router::decide_ip(const boost::asio::ip::address& addr) const
{
    const auto decision = co_await decide_ip_detail(addr);
    co_return decision.route;
}

boost::asio::awaitable<route_type> router::decide_domain(const std::string& host) const
{
    const auto decision = co_await decide_domain_detail(host);
    co_return decision.route;
}

}    // namespace relay
