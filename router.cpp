#include <memory>
#include <string>
#include <vector>
#include <cstdlib>
#include <optional>
#include <filesystem>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include "log.h"
#include "router.h"
#include "ip_matcher.h"
#include "log_context.h"
#include "domain_matcher.h"

namespace mux
{

namespace
{

std::vector<std::string> rule_search_dirs()
{
    std::vector<std::string> dirs;
    if (const char* env_dir = std::getenv("SOCKS_CONFIG_DIR"); env_dir != nullptr && env_dir[0] != '\0')
    {
        dirs.emplace_back(env_dir);
    }
    dirs.emplace_back("config");
    dirs.emplace_back("../config");
    dirs.emplace_back("../../config");
    dirs.emplace_back(".");
    return dirs;
}

std::optional<std::string> resolve_rule_path(const std::string& filename)
{
    namespace fs = std::filesystem;
    for (const auto& dir : rule_search_dirs())
    {
        const fs::path path = (dir == ".") ? fs::path(filename) : fs::path(dir) / filename;
        if (fs::exists(path) && fs::is_regular_file(path))
        {
            return path.string();
        }
    }
    return std::nullopt;
}

bool load_ip_rule(const std::shared_ptr<ip_matcher>& matcher, const std::string& filename, const char* rule_name)
{
    const auto path = resolve_rule_path(filename);
    if (!path.has_value())
    {
        LOG_WARN("load {} rule failed file not found {}", rule_name, filename);
        return false;
    }
    if (!matcher->load(*path))
    {
        LOG_WARN("load {} rule failed {}", rule_name, *path);
        return false;
    }
    return true;
}

bool load_domain_rule(const std::shared_ptr<domain_matcher>& matcher, const std::string& filename, const char* rule_name)
{
    const auto path = resolve_rule_path(filename);
    if (!path.has_value())
    {
        LOG_WARN("load {} rule failed file not found {}", rule_name, filename);
        return false;
    }
    if (!matcher->load(*path))
    {
        LOG_WARN("load {} rule failed {}", rule_name, *path);
        return false;
    }
    return true;
}

boost::asio::ip::address normalize_route_address(const boost::asio::ip::address& addr)
{
    if (!addr.is_v6())
    {
        return addr;
    }
    const auto v6 = addr.to_v6();
    if (!v6.is_v4_mapped())
    {
        return addr;
    }
    return boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, v6);
}

}    // namespace

bool router::load()
{
    bool load_ok = true;

    block_ip_matcher_ = std::make_shared<ip_matcher>();
    load_ok = load_ip_rule(block_ip_matcher_, "block_ip.txt", "block ip") && load_ok;

    direct_ip_matcher_ = std::make_shared<ip_matcher>();
    load_ok = load_ip_rule(direct_ip_matcher_, "direct_ip.txt", "direct ip") && load_ok;

    proxy_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_domain_rule(proxy_domain_matcher_, "proxy_domain.txt", "proxy domain") && load_ok;

    block_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_domain_rule(block_domain_matcher_, "block_domain.txt", "block domain") && load_ok;

    direct_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_domain_rule(direct_domain_matcher_, "direct_domain.txt", "direct domain") && load_ok;

    return load_ok;
}

boost::asio::awaitable<route_type> router::decide(const connection_context& ctx, const std::string& host) const
{
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} parse host failed {}", log_event::kRoute, ec.message());
        co_return co_await decide_domain(ctx, host);
    }
    co_return co_await decide_ip(ctx, host, addr);
}

boost::asio::awaitable<route_type> router::decide_ip(const connection_context& ctx,
                                                     const std::string& host,
                                                     const boost::asio::ip::address& addr) const
{
    (void)host;
    const auto normalized_addr = normalize_route_address(addr);
    if (block_ip_matcher_->match(normalized_addr))
    {
        LOG_CTX_DEBUG(ctx, "{} matched ip rule block", log_event::kRoute);
        co_return route_type::kBlock;
    }
    if (direct_ip_matcher_->match(normalized_addr))
    {
        LOG_CTX_DEBUG(ctx, "{} matched ip rule direct", log_event::kRoute);
        co_return route_type::kDirect;
    }
    LOG_CTX_DEBUG(ctx, "{} ip rule not found default proxy", log_event::kRoute);
    co_return route_type::kProxy;
}

boost::asio::awaitable<route_type> router::decide_domain(const connection_context& ctx, const std::string& host) const
{
    if (block_domain_matcher_->match(host))
    {
        LOG_CTX_DEBUG(ctx, "{} matched domain rule block", log_event::kRoute);
        co_return route_type::kBlock;
    }
    if (direct_domain_matcher_->match(host))
    {
        LOG_CTX_DEBUG(ctx, "{} matched domain rule direct", log_event::kRoute);
        co_return route_type::kDirect;
    }
    if (proxy_domain_matcher_->match(host))
    {
        LOG_CTX_DEBUG(ctx, "{} matched domain rule proxy", log_event::kRoute);
        co_return route_type::kProxy;
    }
    LOG_CTX_DEBUG(ctx, "{} domain rule not found default direct", log_event::kRoute);
    co_return route_type::kDirect;
}

}    // namespace mux
