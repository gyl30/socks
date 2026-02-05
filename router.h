#ifndef ROUTER_H
#define ROUTER_H

#include <memory>
#include <string>
#include <cstdint>

#include <asio.hpp>

#include "ip_matcher.h"
#include "log_context.h"
#include "domain_matcher.h"

namespace mux
{

enum class route_type : std::uint8_t
{
    direct,
    proxy,
    block
};

class router
{
   public:
    router() = default;

   public:
    bool load();
    [[nodiscard]] asio::awaitable<route_type> decide(const connection_context& ctx, const std::string& host, const asio::any_io_executor& ex) const;

    [[nodiscard]] asio::awaitable<route_type> decide_ip(const connection_context& ctx,
                                                        const std::string& host,
                                                        const asio::ip::address& addr,
                                                        const asio::any_io_executor& ex) const;
    [[nodiscard]] asio::awaitable<route_type> decide_domain(const connection_context& ctx,
                                                            const std::string& host,
                                                            const asio::any_io_executor& ex) const;

   protected:
    std::shared_ptr<ip_matcher> block_ip_matcher_;
    std::shared_ptr<ip_matcher> direct_ip_matcher_;
    std::shared_ptr<domain_matcher> proxy_domain_matcher_;
    std::shared_ptr<domain_matcher> block_domain_matcher_;
    std::shared_ptr<domain_matcher> direct_domain_matcher_;
};

}    // namespace mux

#endif
