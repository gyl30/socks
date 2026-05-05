#ifndef ROUTER_H
#define ROUTER_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/address.hpp>

#include "config.h"

namespace relay
{

enum class route_type : uint8_t
{
    kDirect,
    kProxy,
    kBlock,
};

struct route_decision
{
    route_type route = route_type::kBlock;
    std::string outbound_tag;
    std::string outbound_type;
    std::string match_type;
    std::string match_value;
    bool matched = false;
};

std::string to_string(const route_type& type);

class ip_matcher;
class domain_matcher;

class router
{
   public:
    struct shared_state;

    router(const config& cfg, std::string inbound_tag);
    router(std::shared_ptr<const shared_state> shared_state, std::string inbound_tag);
    ~router() = default;

    router(const router&) = delete;
    router& operator=(const router&) = delete;

    [[nodiscard]] static std::shared_ptr<const shared_state> build_shared_state(const config& cfg);

    [[nodiscard]] route_type decide_ip(const boost::asio::ip::address& addr) const;
    [[nodiscard]] route_type decide_domain(const std::string& host) const;
    [[nodiscard]] route_decision decide_ip_detail(const boost::asio::ip::address& addr) const;
    [[nodiscard]] route_decision decide_domain_detail(const std::string& host) const;

   private:
    struct compiled_rule;

    [[nodiscard]] static bool make_compiled_rule(const config& cfg, const config::route_rule_t& rule, compiled_rule& compiled);
    [[nodiscard]] static bool populate_compiled_rule_values(const config::route_rule_t& rule, compiled_rule& compiled);
    [[nodiscard]] bool matches_inbound_rule(const compiled_rule& rule) const;
    [[nodiscard]] route_decision make_match_decision(
        const compiled_rule& rule, const std::string& match_type, const std::string& match_value) const;
    [[nodiscard]] route_decision make_no_route_decision(const std::string& match_type, const std::string& match_value) const;
    static void log_loaded_rule(const config::route_rule_t& rule, const compiled_rule& compiled);
    void log_route_match(
        const char* target_field, const std::string& target_value, const route_decision& decision) const;
    void log_no_route(const char* target_field, const std::string& target_value, const route_decision& decision) const;

   private:
    std::string inbound_tag_;
    std::shared_ptr<const shared_state> shared_state_;
};

}    // namespace relay

#endif
