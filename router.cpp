#include <memory>
#include <string>
#include <vector>
#include <cstdlib>
#include <optional>
#include <filesystem>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include "log.h"
#include "router.h"
#include "constants.h"
#include "ip_matcher.h"
#include "domain_matcher.h"

namespace mux
{

std::string to_string(const route_type& t)
{
    if (t == route_type::kDirect)
    {
        return "direct";
    }
    if (t == route_type::kProxy)
    {
        return "proxy";
    }
    if (t == route_type::kBlock)
    {
        return "block";
    }
    return "unknown";
}
static std::vector<std::string> rule_search_dirs()
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

static std::optional<std::string> resolve_rule_path(const std::string& filename)
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

template <typename Matcher>
static bool load_rule(const std::shared_ptr<Matcher>& matcher, const std::string& filename, const char* rule_name)
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

bool router::load()
{
    bool load_ok = true;

    block_ip_matcher_ = std::make_shared<ip_matcher>();
    load_ok = load_rule(block_ip_matcher_, "block_ip.txt", "block ip") && load_ok;

    direct_ip_matcher_ = std::make_shared<ip_matcher>();
    load_ok = load_rule(direct_ip_matcher_, "direct_ip.txt", "direct ip") && load_ok;

    proxy_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_rule(proxy_domain_matcher_, "proxy_domain.txt", "proxy domain") && load_ok;

    block_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_rule(block_domain_matcher_, "block_domain.txt", "block domain") && load_ok;

    direct_domain_matcher_ = std::make_shared<domain_matcher>();
    load_ok = load_rule(direct_domain_matcher_, "direct_domain.txt", "direct domain") && load_ok;

    return load_ok;
}

boost::asio::awaitable<route_type> router::decide_ip(const boost::asio::ip::address& addr) const
{
    if (block_ip_matcher_ == nullptr || direct_ip_matcher_ == nullptr)
    {
        LOG_WARN("{} ip matcher unavailable fallback default proxy", log_event::kRoute);
    }
    if (block_ip_matcher_ != nullptr && block_ip_matcher_->match(addr))
    {
        LOG_DEBUG("{} matched ip rule block", log_event::kRoute);
        co_return route_type::kBlock;
    }
    if (direct_ip_matcher_ != nullptr && direct_ip_matcher_->match(addr))
    {
        LOG_DEBUG("{} matched ip rule direct", log_event::kRoute);
        co_return route_type::kDirect;
    }
    LOG_DEBUG("{} ip rule not found default proxy", log_event::kRoute);
    co_return route_type::kProxy;
}

boost::asio::awaitable<route_type> router::decide_domain(const std::string& host) const
{
    if (block_domain_matcher_ == nullptr || direct_domain_matcher_ == nullptr || proxy_domain_matcher_ == nullptr)
    {
        LOG_WARN("{} domain matcher unavailable fallback default direct", log_event::kRoute);
    }
    if (block_domain_matcher_ != nullptr && block_domain_matcher_->match(host))
    {
        LOG_DEBUG("{} matched domain rule block", log_event::kRoute);
        co_return route_type::kBlock;
    }
    if (direct_domain_matcher_ != nullptr && direct_domain_matcher_->match(host))
    {
        LOG_DEBUG("{} matched domain rule direct", log_event::kRoute);
        co_return route_type::kDirect;
    }
    if (proxy_domain_matcher_ != nullptr && proxy_domain_matcher_->match(host))
    {
        LOG_DEBUG("{} matched domain rule proxy", log_event::kRoute);
        co_return route_type::kProxy;
    }
    LOG_DEBUG("{} domain rule not found default direct", log_event::kRoute);
    co_return route_type::kDirect;
}

}    // namespace mux
