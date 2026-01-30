#ifndef ROUTER_H
#define ROUTER_H

#include <memory>
#include <string>
#include <asio.hpp>
#include "log.h"
#include "log_context.h"
#include "ip_matcher.h"
#include "domain_matcher.h"

namespace mux
{

enum class route_type : uint8_t
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
    bool load()
    {
        block_ip_matcher_ = std::make_shared<ip_matcher>();
        if (!block_ip_matcher_->load("block_ip.txt"))
        {
            LOG_WARN("load block ip rule failed");
        }
        direct_ip_matcher_ = std::make_shared<ip_matcher>();
        if (!direct_ip_matcher_->load("direct_ip.txt"))
        {
            LOG_WARN("load direct ip rule failed");
        }
        proxy_domain_matcher_ = std::make_shared<domain_matcher>();
        if (!proxy_domain_matcher_->load("proxy_domain.txt"))
        {
            LOG_WARN("load proxy domain rule failed");
        }
        block_domain_matcher_ = std::make_shared<domain_matcher>();
        if (!block_domain_matcher_->load("block_domain.txt"))
        {
            LOG_WARN("load block domain rule failed");
        }

        direct_domain_matcher_ = std::make_shared<domain_matcher>();
        if (!direct_domain_matcher_->load("direct_domain.txt"))
        {
            LOG_WARN("load direct domain rule failed");
        }
        return true;
    }
    [[nodiscard]] asio::awaitable<route_type> decide(const connection_context &ctx, const std::string& host, const asio::any_io_executor& ex) const
    {
        std::error_code ec;
        auto addr = asio::ip::make_address(host, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx, "{} parse host failed {}", log_event::ROUTE, ec.message());
            co_return co_await decide_domain(ctx, host, ex);
        }
        co_return co_await decide_ip(ctx, host, addr, ex);
    }

    [[nodiscard]] asio::awaitable<route_type> decide_ip(const connection_context &ctx, const std::string& host, asio::ip::address& addr, const asio::any_io_executor& ex) const
    {
        // step 1 检查是否是 block
        // step 2 检查是否是 direct
        // step 3 检查是否是 proxy (未实现)
        // step 4 全部是不是返回 block
        if (block_ip_matcher_->match(addr))
        {
            LOG_CTX_DEBUG(ctx, "{} matched ip rule block", log_event::ROUTE);
            co_return route_type::block;
        }
        if (direct_ip_matcher_->match(addr))
        {
            LOG_CTX_DEBUG(ctx, "{} matched ip rule direct", log_event::ROUTE);
            co_return route_type::direct;
        }
        LOG_CTX_DEBUG(ctx, "{} ip rule not found default proxy", log_event::ROUTE);
        co_return route_type::proxy;
    }
    [[nodiscard]] asio::awaitable<route_type> decide_domain(const connection_context &ctx, const std::string& host, const asio::any_io_executor& ex) const
    {
        if (block_domain_matcher_->match(host))
        {
            LOG_CTX_DEBUG(ctx, "{} matched domain rule block", log_event::ROUTE);
            co_return route_type::block;
        }
        if (direct_domain_matcher_->match(host))
        {
            LOG_CTX_DEBUG(ctx, "{} matched domain rule direct", log_event::ROUTE);
            co_return route_type::direct;
        }
        if (proxy_domain_matcher_->match(host))
        {
            LOG_CTX_DEBUG(ctx, "{} matched domain rule proxy", log_event::ROUTE);
            co_return route_type::proxy;
        }
        LOG_CTX_DEBUG(ctx, "{} domain rule not found default direct", log_event::ROUTE);
        co_return route_type::direct;
    }

   private:
    std::shared_ptr<ip_matcher> block_ip_matcher_;
    std::shared_ptr<ip_matcher> direct_ip_matcher_;
    std::shared_ptr<domain_matcher> proxy_domain_matcher_;
    std::shared_ptr<domain_matcher> block_domain_matcher_;
    std::shared_ptr<domain_matcher> direct_domain_matcher_;
};

}    // namespace mux

#endif
