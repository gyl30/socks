#include <cstdint>
#include <cstdio>
#include <cerrno>
#include <cstring>
#include <string>
#include <optional>
#include <expected>
#include <utility>
#include <vector>

#include <openssl/crypto.h>

#include "config.h"
#include "rapidjson/error/error.h"
#include "reflect.h"
#include "crypto_util.h"
#include "mux_protocol.h"

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"

namespace reflect
{

REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, enabled, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::tproxy_t, enabled, listen_host, tcp_port, udp_port, mark);
REFLECT_STRUCT(mux::config::fallback_entry, sni, host, port);
REFLECT_STRUCT(mux::config::timeout_t, read, write, idle);
REFLECT_STRUCT(mux::config::queues_t, udp_session_recv_channel_capacity, tproxy_udp_dispatch_queue_capacity);
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
REFLECT_STRUCT(mux::config::monitor_t, enabled, port);
REFLECT_STRUCT(mux::config, mode, workers, log, inbound, outbound, socks, tproxy, fallbacks, timeout, queues, reality, limits, heartbeat, monitor);

}    // namespace reflect

namespace mux
{

namespace
{

constexpr std::uint32_t kQueueCapacityMin = 1;
constexpr std::uint32_t kQueueCapacityMax = 65535;

[[nodiscard]] config_error make_config_error(std::string path, std::string reason)
{
    config_error error;
    error.path = std::move(path);
    error.reason = std::move(reason);
    return error;
}

[[nodiscard]] std::expected<void, config_error> validate_heartbeat_config(const config::heartbeat_t& heartbeat)
{
    if (heartbeat.min_interval == 0)
    {
        return std::unexpected(make_config_error("/heartbeat/min_interval", "must be greater than 0"));
    }
    if (heartbeat.max_interval == 0)
    {
        return std::unexpected(make_config_error("/heartbeat/max_interval", "must be greater than 0"));
    }
    if (heartbeat.min_interval > heartbeat.max_interval)
    {
        return std::unexpected(make_config_error("/heartbeat/min_interval", "must be less than or equal to max_interval"));
    }
    if (heartbeat.min_padding > heartbeat.max_padding)
    {
        return std::unexpected(make_config_error("/heartbeat/min_padding", "must be less than or equal to max_padding"));
    }
    if (heartbeat.max_padding > kMaxPayload)
    {
        return std::unexpected(make_config_error("/heartbeat/max_padding", "must be less than or equal to max payload"));
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_limits_config(const config::limits_t& limits)
{
    if (limits.max_buffer == 0)
    {
        return std::unexpected(make_config_error("/limits/max_buffer", "must be greater than 0"));
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_queues_config(const config::queues_t& queues)
{
    if (queues.udp_session_recv_channel_capacity < kQueueCapacityMin || queues.udp_session_recv_channel_capacity > kQueueCapacityMax)
    {
        return std::unexpected(
            make_config_error("/queues/udp_session_recv_channel_capacity", "must be between 1 and 65535"));
    }
    if (queues.tproxy_udp_dispatch_queue_capacity < kQueueCapacityMin || queues.tproxy_udp_dispatch_queue_capacity > kQueueCapacityMax)
    {
        return std::unexpected(
            make_config_error("/queues/tproxy_udp_dispatch_queue_capacity", "must be between 1 and 65535"));
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_socks_config(const config::socks_t& socks)
{
    if (!socks.enabled || !socks.auth)
    {
        return {};
    }
    if (socks.username.empty())
    {
        return std::unexpected(make_config_error("/socks/username", "must be non-empty when auth is enabled"));
    }
    if (socks.password.empty())
    {
        return std::unexpected(make_config_error("/socks/password", "must be non-empty when auth is enabled"));
    }
    return {};
}

[[nodiscard]] bool has_enabled_client_inbound(const config& cfg)
{
#ifdef __linux__
    return cfg.socks.enabled || cfg.tproxy.enabled;
#else
    return cfg.socks.enabled;
#endif
}

[[nodiscard]] std::expected<void, config_error> validate_config(const config& cfg)
{
    if (const auto limits_result = validate_limits_config(cfg.limits); !limits_result)
    {
        return std::unexpected(limits_result.error());
    }
    if (const auto heartbeat_result = validate_heartbeat_config(cfg.heartbeat); !heartbeat_result)
    {
        return std::unexpected(heartbeat_result.error());
    }
    if (const auto queues_result = validate_queues_config(cfg.queues); !queues_result)
    {
        return std::unexpected(queues_result.error());
    }
    if (const auto socks_result = validate_socks_config(cfg.socks); !socks_result)
    {
        return std::unexpected(socks_result.error());
    }
    if (cfg.mode == "client" && !has_enabled_client_inbound(cfg))
    {
        return std::unexpected(make_config_error("/mode", "client mode requires socks or tproxy inbound"));
    }
    return {};
}

[[nodiscard]] std::expected<std::string, config_error> read_file(const std::string& filename)
{
    char buf[256 * 1024] = {0};
    std::string result;
    FILE* f = fopen(filename.c_str(), "rb");
    if (f == nullptr)
    {
        return std::unexpected(make_config_error("/", std::string("open file failed: ") + std::strerror(errno)));
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
                return std::unexpected(make_config_error("/", std::string("read file failed: ") + std::strerror(errno)));
            }
            break;
        }
    }
    fclose(f);
    return result;
}

[[nodiscard]] std::expected<config, config_error> deserialize_config_with_error(const std::string& text)
{
    rapidjson::Document reader;
    const rapidjson::ParseResult parse_result = reader.Parse(text.c_str());
    if (parse_result.IsError())
    {
        return std::unexpected(
            make_config_error("/", "json parse error at offset " + std::to_string(parse_result.Offset()) + ": " + rapidjson::GetParseError_En(parse_result.Code())));
    }

    config cfg;
    reflect::JsonReader json_reader{&reader};
    reflect::reflect(json_reader, cfg);
    if (!json_reader.ok())
    {
        return std::unexpected(make_config_error(json_reader.getPath(), "invalid type or value"));
    }

    cfg.limits.max_connections = normalize_max_connections(cfg.limits.max_connections);
    if (const auto validate_result = validate_config(cfg); !validate_result)
    {
        return std::unexpected(validate_result.error());
    }
    return cfg;
}

}    // namespace

std::expected<config, config_error> parse_config_with_error(const std::string& filename)
{
    const auto file_content = read_file(filename);
    if (!file_content)
    {
        return std::unexpected(file_content.error());
    }
    return deserialize_config_with_error(*file_content);
}

std::optional<config> parse_config(const std::string& filename)
{
    const auto parsed = parse_config_with_error(filename);
    if (!parsed)
    {
        return std::nullopt;
    }
    return *parsed;
}

std::string dump_config(const config& cfg) { return reflect::serialize_struct(cfg); }

std::string dump_default_config()
{
    config cfg;
    std::uint8_t public_key[32] = {0};
    std::uint8_t private_key[32] = {0};
    const auto wipe_keys = [&]()
    {
        OPENSSL_cleanse(private_key, sizeof(private_key));
        OPENSSL_cleanse(public_key, sizeof(public_key));
    };
    if (reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        cfg.reality.private_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(private_key, private_key + 32));
        cfg.reality.public_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32));
    }
    wipe_keys();
    cfg.fallbacks.push_back({});
    return dump_config(cfg);
}

}    // namespace mux
