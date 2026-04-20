#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>

#include "config.h"

namespace
{

relay::config make_marked_config()
{
    relay::config cfg;
    cfg.workers = 1;
    cfg.log.file = "socket-mark-regression.log";

    relay::config::inbound_entry_t inbound;
    inbound.type = "socks";
    inbound.tag = "socks-in";
    inbound.mark = 17;
    inbound.socks = relay::config::socks_t{};
    cfg.inbounds.push_back(inbound);

    relay::config::outbound_entry_t direct_outbound;
    direct_outbound.type = "direct";
    direct_outbound.tag = "direct";
    direct_outbound.mark = 23;
    cfg.outbounds.push_back(direct_outbound);

    relay::config::outbound_entry_t block_outbound;
    block_outbound.type = "block";
    block_outbound.tag = "block";
    cfg.outbounds.push_back(block_outbound);

    relay::config::route_rule_t route;
    route.type = "inbound";
    route.values = {"socks-in"};
    route.out = "direct";
    cfg.routing.push_back(std::move(route));

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

}    // namespace

int main()
{
    const relay::config cfg = make_marked_config();
    const std::string dumped = relay::dump_config(cfg);
    const auto dump_path =
        std::filesystem::temp_directory_path() /
        ("socket-mark-regression-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");

    {
        std::ofstream out(dump_path);
        if (!require(out.is_open(), "failed to open temporary config file"))
        {
            return 1;
        }
        out << dumped;
    }

    const auto cleanup = [&dump_path]() {
        std::error_code ec;
        std::filesystem::remove(dump_path, ec);
    };

    const auto parsed = relay::parse_config(dump_path.string());
    if (!require(parsed.has_value(), "parse_config failed for dumped config"))
    {
        cleanup();
        return 1;
    }

    const auto* inbound = relay::find_inbound_entry(*parsed, "socks-in");
    const auto* direct_outbound = relay::find_outbound_entry(*parsed, "direct");
    const auto* block_outbound = relay::find_outbound_entry(*parsed, "block");

    const bool ok =
        require(inbound != nullptr, "missing inbound socks-in") &&
        require(direct_outbound != nullptr, "missing outbound direct") &&
        require(block_outbound != nullptr, "missing outbound block") &&
        require(inbound->mark == 17, "inbound mark not preserved") &&
        require(direct_outbound->mark == 23, "outbound mark not preserved") &&
        require(block_outbound->mark == 0, "unexpected block outbound mark") &&
        require(relay::resolve_socket_mark(*parsed, "socks-in", "direct") == 23, "outbound mark should take precedence") &&
        require(relay::resolve_socket_mark(*parsed, "socks-in", "block") == 17, "inbound mark should be used as fallback") &&
        require(relay::resolve_socket_mark(*parsed, "socks-in", "missing-outbound") == 17, "missing outbound should fall back to inbound") &&
        require(relay::resolve_socket_mark(*parsed, "missing-inbound", "direct") == 23, "existing outbound mark should be resolved independently") &&
        require(relay::resolve_socket_mark(*parsed, "missing-inbound", "block") == 0, "missing inbound and zero outbound mark should resolve to zero");

    cleanup();
    return ok ? 0 : 1;
}
