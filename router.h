#ifndef ROUTER_H
#define ROUTER_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
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
    router(const config& cfg, std::string inbound_tag);
    ~router() = default;

    router(const router&) = delete;
    router& operator=(const router&) = delete;

    [[nodiscard]] bool load();

    [[nodiscard]] boost::asio::awaitable<route_type> decide_ip(const boost::asio::ip::address& addr) const;
    [[nodiscard]] boost::asio::awaitable<route_type> decide_domain(const std::string& host) const;
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_ip_detail(const boost::asio::ip::address& addr) const;
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_domain_detail(const std::string& host) const;

   private:
    struct compiled_rule;

    [[nodiscard]] route_decision make_no_route_decision(const std::string& match_type, const std::string& match_value) const;

   private:
    const config& cfg_;
    std::string inbound_tag_;
    std::vector<std::shared_ptr<compiled_rule>> rules_;
};

}    // namespace relay

#endif
