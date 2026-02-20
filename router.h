#ifndef ROUTER_H
#define ROUTER_H

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <memory>
#include <string>
#include <cstdint>

#include "ip_matcher.h"
#include "log_context.h"
#include "domain_matcher.h"

namespace mux
{

enum class route_type : std::uint8_t
{
    kDirect,
    kProxy,
    kBlock
};

class router
{
   public:
    router() = default;
    virtual ~router() = default;

   public:
    virtual bool load();
    [[nodiscard]] boost::asio::awaitable<route_type> decide(const connection_context& ctx, const std::string& host) const;

    [[nodiscard]] boost::asio::awaitable<route_type> decide_ip(const connection_context& ctx,
                                                        const std::string& host,
                                                        const boost::asio::ip::address& addr) const;
    [[nodiscard]] boost::asio::awaitable<route_type> decide_domain(const connection_context& ctx, const std::string& host) const;

   protected:
    std::shared_ptr<ip_matcher>& block_ip_matcher() { return block_ip_matcher_; }
    std::shared_ptr<ip_matcher>& direct_ip_matcher() { return direct_ip_matcher_; }
    std::shared_ptr<domain_matcher>& proxy_domain_matcher() { return proxy_domain_matcher_; }
    std::shared_ptr<domain_matcher>& block_domain_matcher() { return block_domain_matcher_; }
    std::shared_ptr<domain_matcher>& direct_domain_matcher() { return direct_domain_matcher_; }

   private:
    std::shared_ptr<ip_matcher> block_ip_matcher_;
    std::shared_ptr<ip_matcher> direct_ip_matcher_;
    std::shared_ptr<domain_matcher> proxy_domain_matcher_;
    std::shared_ptr<domain_matcher> block_domain_matcher_;
    std::shared_ptr<domain_matcher> direct_domain_matcher_;
};

}    // namespace mux

#endif
