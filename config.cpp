#include <cstdio>
#include <string>
#include <optional>

#include "config.h"
#include "reflect.h"

namespace reflect
{

REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::fallback_entry, sni, host, port);
REFLECT_STRUCT(mux::config::timeout_t, read, write, idle);
REFLECT_STRUCT(mux::config::reality_t, sni, private_key, public_key, short_id, verify_public_key);
REFLECT_STRUCT(mux::config::limits_t, max_connections, max_buffer);
REFLECT_STRUCT(mux::config::heartbeat_t, enabled, min_interval, max_interval, min_padding, max_padding);
REFLECT_STRUCT(mux::config::monitor_t, enabled, port);
REFLECT_STRUCT(mux::config, mode, log, inbound, outbound, socks, fallbacks, timeout, reality, limits, heartbeat, monitor);

}    // namespace reflect

namespace mux
{

static std::optional<std::string> read_file(const std::string& filename)
{
    char buf[256 * 1024] = {0};
    std::string result;
    FILE* f = fopen(filename.c_str(), "rb");
    if (f == nullptr)
    {
        return {};
    }
    for (;;)
    {
        const std::size_t n = fread(buf, 1, sizeof buf, f);
        if (n > 0)
        {
            result.append(buf, n);
        }
        if (n < sizeof buf)
        {
            if (ferror(f) != 0)
            {
                fclose(f);
                return {};
            }
            break;
        }
    }
    fclose(f);
    return result;
}

std::optional<config> parse_config(const std::string& filename)
{
    const auto file_content = read_file(filename);
    if (!file_content.has_value())
    {
        return {};
    }
    config cfg;
    if (!reflect::deserialize_struct(cfg, file_content.value()))
    {
        return {};
    }
    return cfg;
}

std::string dump_config(const config& cfg) { return reflect::serialize_struct(cfg); }

std::string dump_default_config()
{
    config cfg;
    cfg.fallbacks.push_back({});
    return dump_config(cfg);
}

}    // namespace mux
