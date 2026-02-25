#include <cerrno>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <array>
#include <expected>
#include <optional>
#include <algorithm>
#include <cctype>
#include <charconv>

#include <boost/asio/ip/address.hpp>
#include <openssl/crypto.h>

#include "config.h"
#include "reflect.h"
#include "crypto_util.h"
#include "mux_protocol.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/error/error.h"

namespace reflect
{

REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, enabled, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::tproxy_t, enabled, listen_host, tcp_port, udp_port, mark);
REFLECT_STRUCT(mux::config::fallback_entry, sni, host, port);
REFLECT_STRUCT(mux::config::timeout_t, read, write, connect, idle);
REFLECT_STRUCT(mux::config::queues_t, udp_session_recv_channel_capacity, tproxy_udp_dispatch_queue_capacity);
REFLECT_STRUCT(mux::config::reality_t::fallback_guard_t, enabled, rate_per_sec, burst, key_mode, circuit_fail_threshold, circuit_open_sec, state_ttl_sec);
REFLECT_STRUCT(mux::config::reality_t,
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
    if (heartbeat.max_padding > mux::kMaxPayloadPerRecord)
    {
        return std::unexpected(make_config_error("/heartbeat/max_padding", "must be less than or equal to max mux single record payload"));
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
        return std::unexpected(make_config_error("/queues/udp_session_recv_channel_capacity", "must be between 1 and 65535"));
    }
    if (queues.tproxy_udp_dispatch_queue_capacity < kQueueCapacityMin || queues.tproxy_udp_dispatch_queue_capacity > kQueueCapacityMax)
    {
        return std::unexpected(make_config_error("/queues/tproxy_udp_dispatch_queue_capacity", "must be between 1 and 65535"));
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_socks_config(const config::socks_t& socks)
{
    constexpr std::size_t kSocksAuthFieldMaxLen = 255;
    if (!socks.enabled)
    {
        return {};
    }
    if (socks.host.empty())
    {
        return std::unexpected(make_config_error("/socks/host", "must be non-empty ip address when socks is enabled"));
    }
    boost::system::error_code ec;
    (void)boost::asio::ip::make_address(socks.host, ec);
    if (ec)
    {
        return std::unexpected(make_config_error("/socks/host", "must be valid ip address when socks is enabled"));
    }
    if (socks.username.find('\0') != std::string::npos)
    {
        return std::unexpected(make_config_error("/socks/username", "must not contain nul"));
    }
    if (socks.password.find('\0') != std::string::npos)
    {
        return std::unexpected(make_config_error("/socks/password", "must not contain nul"));
    }
    if (!socks.auth)
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
    if (socks.username.size() > kSocksAuthFieldMaxLen)
    {
        return std::unexpected(make_config_error("/socks/username", "must be at most 255 bytes when auth is enabled"));
    }
    if (socks.password.size() > kSocksAuthFieldMaxLen)
    {
        return std::unexpected(make_config_error("/socks/password", "must be at most 255 bytes when auth is enabled"));
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_tproxy_config(const config::tproxy_t& tproxy)
{
    if (!tproxy.enabled)
    {
        return {};
    }
    if (tproxy.listen_host.empty())
    {
        return std::unexpected(make_config_error("/tproxy/listen_host", "must be non-empty ip address when tproxy is enabled"));
    }
    boost::system::error_code ec;
    (void)boost::asio::ip::make_address(tproxy.listen_host, ec);
    if (ec)
    {
        return std::unexpected(make_config_error("/tproxy/listen_host", "must be valid ip address when tproxy is enabled"));
    }
    if (tproxy.tcp_port == 0)
    {
        return std::unexpected(make_config_error("/tproxy/tcp_port", "must be non-zero when tproxy is enabled"));
    }
    return {};
}

[[nodiscard]] std::expected<std::vector<std::uint8_t>, config_error> decode_optional_hex_field(const std::string& hex, const std::string& path)
{
    if (hex.empty())
    {
        return std::vector<std::uint8_t>{};
    }
    if (hex.size() % 2 != 0)
    {
        return std::unexpected(make_config_error(path, "must be even-length hex when provided"));
    }
    auto bytes = reality::crypto_util::hex_to_bytes(hex);
    if (bytes.empty())
    {
        return std::unexpected(make_config_error(path, "must be valid hex when provided"));
    }
    return bytes;
}

[[nodiscard]] bool parse_bracket_dest_target(const std::string& text, std::string& host, std::string& port)
{
    const auto end = text.find(']');
    if (end == std::string::npos)
    {
        return false;
    }
    host = text.substr(1, end - 1);
    if (end + 1 >= text.size() || text[end + 1] != ':')
    {
        return false;
    }
    port = text.substr(end + 2);
    return true;
}

[[nodiscard]] bool parse_plain_dest_target(const std::string& text, std::string& host, std::string& port)
{
    const auto pos = text.rfind(':');
    if (pos == std::string::npos)
    {
        return false;
    }
    host = text.substr(0, pos);
    port = text.substr(pos + 1);
    return true;
}

[[nodiscard]] bool valid_port_text(const std::string& text)
{
    if (text.empty())
    {
        return false;
    }
    std::uint32_t parsed_port = 0;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto [parse_end, parse_ec] = std::from_chars(begin, end, parsed_port);
    if (parse_ec != std::errc() || parse_end != end)
    {
        return false;
    }
    return parsed_port > 0 && parsed_port <= 65535;
}

[[nodiscard]] std::string normalize_sni_key(std::string_view sni)
{
    std::string normalized;
    normalized.reserve(sni.size());
    for (const char ch : sni)
    {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    while (!normalized.empty() && normalized.back() == '.')
    {
        normalized.pop_back();
    }
    return normalized;
}

[[nodiscard]] std::expected<void, config_error> validate_fallbacks_config(const std::vector<config::fallback_entry>& fallbacks)
{
    for (std::size_t i = 0; i < fallbacks.size(); ++i)
    {
        const auto& entry = fallbacks[i];
        const auto index_path = "/fallbacks/" + std::to_string(i);
        if (entry.host.empty())
        {
            return std::unexpected(make_config_error(index_path + "/host", "must be non-empty"));
        }
        if (entry.host.find('\0') != std::string::npos)
        {
            return std::unexpected(make_config_error(index_path + "/host", "must not contain nul"));
        }
        if (!valid_port_text(entry.port))
        {
            return std::unexpected(make_config_error(index_path + "/port", "must be in 1-65535"));
        }
        if (entry.sni.find('\0') != std::string::npos)
        {
            return std::unexpected(make_config_error(index_path + "/sni", "must not contain nul"));
        }
        if (!entry.sni.empty() && entry.sni != "*" && normalize_sni_key(entry.sni).empty())
        {
            return std::unexpected(make_config_error(index_path + "/sni", "must be non-empty after normalization when provided"));
        }
    }
    return {};
}

[[nodiscard]] bool is_valid_reality_dest(const std::string& input)
{
    if (input.empty())
    {
        return false;
    }
    std::string host;
    std::string port;
    const bool bracketed = input.front() == '[';
    const bool parsed = bracketed ? parse_bracket_dest_target(input, host, port) : parse_plain_dest_target(input, host, port);
    if (!parsed || host.empty() || !valid_port_text(port))
    {
        return false;
    }
    if (!bracketed && host.find(':') != std::string::npos)
    {
        return false;
    }
    return true;
}

[[nodiscard]] std::string normalize_fallback_guard_key_mode(const std::string& key_mode)
{
    std::string normalized;
    normalized.reserve(key_mode.size());
    for (const char ch : key_mode)
    {
        if (ch == '-' || ch == ' ')
        {
            normalized.push_back('_');
            continue;
        }
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized;
}

[[nodiscard]] std::expected<void, config_error> validate_reality_config(const config::reality_t& reality)
{
    constexpr std::size_t kRealityKeyLen = 32;
    constexpr std::size_t kRealityShortIdMaxLen = 8;

    const auto private_key_bytes = decode_optional_hex_field(reality.private_key, "/reality/private_key");
    if (!private_key_bytes)
    {
        return std::unexpected(private_key_bytes.error());
    }
    if (!private_key_bytes->empty() && private_key_bytes->size() != kRealityKeyLen)
    {
        return std::unexpected(make_config_error("/reality/private_key", "must be 32-byte hex when provided"));
    }

    const auto public_key_bytes = decode_optional_hex_field(reality.public_key, "/reality/public_key");
    if (!public_key_bytes)
    {
        return std::unexpected(public_key_bytes.error());
    }
    if (!public_key_bytes->empty() && public_key_bytes->size() != kRealityKeyLen)
    {
        return std::unexpected(make_config_error("/reality/public_key", "must be 32-byte hex when provided"));
    }

    const auto short_id_bytes = decode_optional_hex_field(reality.short_id, "/reality/short_id");
    if (!short_id_bytes)
    {
        return std::unexpected(short_id_bytes.error());
    }
    if (short_id_bytes->size() > kRealityShortIdMaxLen)
    {
        return std::unexpected(make_config_error("/reality/short_id", "must be at most 8 bytes when provided"));
    }
    if (reality.dest.find('\0') != std::string::npos)
    {
        return std::unexpected(make_config_error("/reality/dest", "must not contain nul when provided"));
    }
    if (!reality.dest.empty() && !is_valid_reality_dest(reality.dest))
    {
        return std::unexpected(make_config_error("/reality/dest", "must be host:port or [ipv6]:port with port in 1-65535 when provided"));
    }
    if (!reality.type.empty() && reality.type != "tcp")
    {
        return std::unexpected(make_config_error("/reality/type", "must be tcp when provided"));
    }
    if (reality.fallback_guard.enabled)
    {
        if (reality.fallback_guard.rate_per_sec == 0)
        {
            return std::unexpected(make_config_error("/reality/fallback_guard/rate_per_sec", "must be greater than 0 when fallback guard is enabled"));
        }
        if (reality.fallback_guard.burst == 0)
        {
            return std::unexpected(make_config_error("/reality/fallback_guard/burst", "must be greater than 0 when fallback guard is enabled"));
        }
        const auto key_mode = normalize_fallback_guard_key_mode(reality.fallback_guard.key_mode);
        if (key_mode.empty() || (key_mode != "ip" && key_mode != "ip_sni"))
        {
            return std::unexpected(make_config_error("/reality/fallback_guard/key_mode", "must be ip or ip_sni when fallback guard is enabled"));
        }
        if (reality.fallback_guard.state_ttl_sec == 0)
        {
            return std::unexpected(make_config_error("/reality/fallback_guard/state_ttl_sec", "must be greater than 0 when fallback guard is enabled"));
        }
        if (reality.fallback_guard.circuit_fail_threshold > 0 && reality.fallback_guard.circuit_open_sec == 0)
        {
            return std::unexpected(
                make_config_error("/reality/fallback_guard/circuit_open_sec", "must be greater than 0 when circuit fail threshold is enabled"));
        }
    }

    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_mode_reality_dependencies(const config& cfg)
{
    if (cfg.mode == "client" && cfg.outbound.host.empty())
    {
        return std::unexpected(make_config_error("/outbound/host", "must be non-empty in client mode"));
    }
    if (cfg.mode == "client" && cfg.outbound.port == 0)
    {
        return std::unexpected(make_config_error("/outbound/port", "must be non-zero in client mode"));
    }
    if (cfg.mode == "client" && cfg.reality.public_key.empty())
    {
        return std::unexpected(make_config_error("/reality/public_key", "must be non-empty in client mode"));
    }
    if (cfg.mode == "server" && cfg.reality.private_key.empty())
    {
        return std::unexpected(make_config_error("/reality/private_key", "must be non-empty in server mode"));
    }
    if (cfg.mode == "client")
    {
        std::string normalized_fingerprint;
        normalized_fingerprint.reserve(cfg.reality.fingerprint.size());
        for (const char ch : cfg.reality.fingerprint)
        {
            if (ch == '-' || ch == ' ')
            {
                normalized_fingerprint.push_back('_');
                continue;
            }
            normalized_fingerprint.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
        static constexpr std::array<const char*, 8> kSupportedFingerprints = {
            "chrome",
            "chrome_120",
            "firefox",
            "firefox_120",
            "ios",
            "ios_14",
            "android",
            "android_11_okhttp"};
        if (!normalized_fingerprint.empty() && normalized_fingerprint != "random" &&
            std::find(kSupportedFingerprints.begin(), kSupportedFingerprints.end(), normalized_fingerprint) == kSupportedFingerprints.end())
        {
            return std::unexpected(make_config_error("/reality/fingerprint", "must be random/chrome/firefox/ios/android (or version aliases) in client mode"));
        }
    }
    return {};
}

[[nodiscard]] std::expected<void, config_error> validate_inbound_config(const config::inbound_t& inbound)
{
    if (inbound.host.empty())
    {
        return std::unexpected(make_config_error("/inbound/host", "must be non-empty ip address"));
    }
    boost::system::error_code ec;
    (void)boost::asio::ip::make_address(inbound.host, ec);
    if (ec)
    {
        return std::unexpected(make_config_error("/inbound/host", "must be valid ip address"));
    }
    return {};
}

[[nodiscard]] bool is_supported_mode(const std::string& mode) { return mode == "client" || mode == "server"; }

[[nodiscard]] bool has_enabled_client_inbound(const config& cfg)
{
#if SOCKS_HAS_TPROXY
    return cfg.socks.enabled || cfg.tproxy.enabled;
#else
    return cfg.socks.enabled;
#endif
}

[[nodiscard]] std::expected<void, config_error> validate_config(const config& cfg)
{
    if (!is_supported_mode(cfg.mode))
    {
        return std::unexpected(make_config_error("/mode", "must be client or server"));
    }
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
    if (const auto reality_result = validate_reality_config(cfg.reality); !reality_result)
    {
        return std::unexpected(reality_result.error());
    }
    if (const auto fallback_result = validate_fallbacks_config(cfg.fallbacks); !fallback_result)
    {
        return std::unexpected(fallback_result.error());
    }
    if (cfg.mode == "server")
    {
        if (const auto inbound_result = validate_inbound_config(cfg.inbound); !inbound_result)
        {
            return std::unexpected(inbound_result.error());
        }
    }
#if !SOCKS_HAS_TPROXY
    if (cfg.tproxy.enabled)
    {
        return std::unexpected(make_config_error("/tproxy/enabled", "tproxy inbound is only supported on linux"));
    }
#endif
    if (const auto tproxy_result = validate_tproxy_config(cfg.tproxy); !tproxy_result)
    {
        return std::unexpected(tproxy_result.error());
    }
    if (cfg.mode == "client" && !has_enabled_client_inbound(cfg))
    {
#if SOCKS_HAS_TPROXY
        return std::unexpected(make_config_error("/mode", "client mode requires socks or tproxy inbound"));
#else
        return std::unexpected(make_config_error("/mode", "client mode requires socks inbound"));
#endif
    }
    if (const auto mode_reality_result = validate_mode_reality_dependencies(cfg); !mode_reality_result)
    {
        return std::unexpected(mode_reality_result.error());
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
    if (const auto nul_pos = text.find('\0'); nul_pos != std::string::npos)
    {
        return std::unexpected(make_config_error("/", "json parse error at offset " + std::to_string(nul_pos) + ": embedded nul byte"));
    }
    rapidjson::Document reader;
    const rapidjson::ParseResult parse_result = reader.Parse(text.data(), text.size());
    if (parse_result.IsError())
    {
        return std::unexpected(make_config_error(
            "/", "json parse error at offset " + std::to_string(parse_result.Offset()) + ": " + rapidjson::GetParseError_En(parse_result.Code())));
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
