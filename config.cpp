#include <cstdio>
#include <string>
#include <optional>

#include "config.h"
#include "reflect.h"
#include "crypto_util.h"
#include "mux_protocol.h"

namespace reflect
{

REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, enabled, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::tproxy_t, enabled, listen_host, tcp_port, udp_port, mark);
REFLECT_STRUCT(mux::config::fallback_entry, sni, host, port);
REFLECT_STRUCT(mux::config::timeout_t, read, write, idle);
REFLECT_STRUCT(mux::config::reality_t::fallback_guard_t, enabled, rate_per_sec, burst, circuit_fail_threshold, circuit_open_sec, state_ttl_sec);
REFLECT_STRUCT(
    mux::config::reality_t,
    fallback_guard,
    sni,
    fingerprint,
    dest,
    type,
    strict_cert_verify,
    replay_cache_max_entries,
    private_key,
    public_key,
    short_id);
REFLECT_STRUCT(mux::config::limits_t, max_connections, max_connections_per_source, source_prefix_v4, source_prefix_v6, max_buffer, max_streams);
REFLECT_STRUCT(mux::config::heartbeat_t, enabled, idle_timeout, min_interval, max_interval, min_padding, max_padding);
REFLECT_STRUCT(mux::config::monitor_t, enabled, port, token, min_interval_ms);
REFLECT_STRUCT(mux::config, mode, workers, log, inbound, outbound, socks, tproxy, fallbacks, timeout, reality, limits, heartbeat, monitor);

}    // namespace reflect

namespace mux
{

namespace
{

[[nodiscard]] bool validate_heartbeat_config(const config::heartbeat_t& heartbeat)
{
    if (heartbeat.min_interval == 0 || heartbeat.max_interval == 0)
    {
        return false;
    }
    if (heartbeat.min_interval > heartbeat.max_interval)
    {
        return false;
    }
    if (heartbeat.min_padding > heartbeat.max_padding)
    {
        return false;
    }
    if (heartbeat.max_padding > kMaxPayload)
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool validate_limits_config(const config::limits_t& limits)
{
    if (limits.max_buffer == 0)
    {
        return false;
    }
    return true;
}

[[nodiscard]] bool has_enabled_client_inbound(const config& cfg)
{
#ifdef __linux__
    return cfg.socks.enabled || cfg.tproxy.enabled;
#else
    return cfg.socks.enabled;
#endif
}

[[nodiscard]] bool validate_config(const config& cfg)
{
    if (!validate_limits_config(cfg.limits))
    {
        return false;
    }
    if (!validate_heartbeat_config(cfg.heartbeat))
    {
        return false;
    }
    if (cfg.mode == "client" && !has_enabled_client_inbound(cfg))
    {
        return false;
    }
    return true;
}

}    // namespace

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
    cfg.limits.max_connections = normalize_max_connections(cfg.limits.max_connections);
    if (!validate_config(cfg))
    {
        return {};
    }
    return cfg;
}

std::string dump_config(const config& cfg) { return reflect::serialize_struct(cfg); }

std::string dump_default_config()
{
    config cfg;
    std::uint8_t public_key[32] = {0};
    std::uint8_t private_key[32] = {0};
    if (reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        cfg.reality.private_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(private_key, private_key + 32));
        cfg.reality.public_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32));
    }
    cfg.fallbacks.push_back({});
    return dump_config(cfg);
}

}    // namespace mux
