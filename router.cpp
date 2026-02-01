#include "router.h"

namespace mux
{

bool router::load()
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

asio::awaitable<route_type> router::decide(const connection_context& ctx, const std::string& host, const asio::any_io_executor& ex) const
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

asio::awaitable<route_type> router::decide_ip(const connection_context& ctx,
                                              const std::string& host,
                                              asio::ip::address& addr,
                                              const asio::any_io_executor& ex) const
{
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

asio::awaitable<route_type> router::decide_domain(const connection_context& ctx, const std::string& host, const asio::any_io_executor& ex) const
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

}    // namespace mux
