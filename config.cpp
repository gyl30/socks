#include "config.h"
#include "reflect.h"

namespace reflect
{
REFLECT_STRUCT(config::log_t, level, file);
REFLECT_STRUCT(config::inbound_t, host, port);
REFLECT_STRUCT(config::outbound_t, host, port);
REFLECT_STRUCT(config::socks_t, host, port, auth, username, password);
REFLECT_STRUCT(config::fallback_entry, sni, host, port);
REFLECT_STRUCT(config::timeout_t, read, write, idle);
REFLECT_STRUCT(config::reality_t, sni, private_key, public_key);
REFLECT_STRUCT(config::limits_t, max_connections, max_buffer);
REFLECT_STRUCT(config, mode, log, inbound, outbound, socks, fallbacks, timeout, reality, limits);

}    // namespace reflect

static std::optional<std::string> read_file(const std::string& filename)
{
    char buf[256 * 1024] = {0};
    std::string result;
    FILE* f = fopen(filename.c_str(), "rb");
    if (f == nullptr)
    {
        return {};
    }
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
    {
        result.append(buf, n);
    }
    fclose(f);
    return result;
}
std::optional<config> parse_config(const std::string& filename)
{
    auto file_content = read_file(filename);
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
