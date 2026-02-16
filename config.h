#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <expected>

namespace mux
{

struct config
{
    std::string mode = "server";
    std::uint32_t workers = 0;

    struct log_t
    {
        std::string level = "info";
        std::string file = "app.log";
    } log;

    struct inbound_t
    {
        std::string host = "0.0.0.0";
        std::uint16_t port = 8844;
    } inbound;

    struct outbound_t
    {
        std::string host = "0.0.0.0";
        std::uint16_t port = 8844;
    } outbound;

    struct socks_t
    {
        bool enabled = true;
        std::string host = "127.0.0.1";
        std::uint16_t port = 1080;
        bool auth = false;
        std::string username;
        std::string password;
    } socks;

    struct tproxy_t
    {
        bool enabled = false;
        std::string listen_host = "::";
        std::uint16_t tcp_port = 1081;
        std::uint16_t udp_port = 0;
        std::uint32_t mark = 0x11;
    } tproxy;

    struct fallback_entry
    {
        std::string sni = "www.apple.com";
        std::string host = "www.apple.com";
        std::string port = "443";
    };
    std::vector<fallback_entry> fallbacks;

    struct timeout_t
    {
        std::uint32_t read = 100;
        std::uint32_t write = 100;
        std::uint32_t idle = 300;
    } timeout;

    struct limits_t
    {
        std::uint32_t max_connections = 5;
        std::uint32_t max_connections_per_source = 0;
        std::uint8_t source_prefix_v4 = 32;
        std::uint8_t source_prefix_v6 = 128;
        std::uint64_t max_buffer = 10L * 1024 * 1024;
        std::uint32_t max_streams = 1024;
    } limits;

    struct heartbeat_t
    {
        bool enabled = true;
        std::uint32_t idle_timeout = 10;
        std::uint32_t min_interval = 15;
        std::uint32_t max_interval = 45;
        std::uint32_t min_padding = 32;
        std::uint32_t max_padding = 1024;
    } heartbeat;

    struct monitor_t
    {
        bool enabled = false;
        std::uint16_t port = 9090;
        std::string token;
        std::uint32_t min_interval_ms = 50;
    } monitor;

    struct reality_t
    {
        struct fallback_guard_t
        {
            bool enabled = true;
            std::uint32_t rate_per_sec = 2;
            std::uint32_t burst = 10;
            std::uint32_t circuit_fail_threshold = 5;
            std::uint32_t circuit_open_sec = 30;
            std::uint32_t state_ttl_sec = 600;
        } fallback_guard;

        std::string sni = "www.apple.com";
        std::string fingerprint = "random";
        std::string dest;
        std::string type = "tcp";
        bool strict_cert_verify = false;
        std::uint32_t replay_cache_max_entries = 100000;
        std::string private_key;
        std::string public_key;
        std::string short_id;
    } reality;
};

struct config_error
{
    std::string path = "/";
    std::string reason;
};

[[nodiscard]] constexpr std::uint32_t normalize_max_connections(const std::uint32_t max_connections)
{
    return (max_connections == 0) ? 1U : max_connections;
}

[[nodiscard]] std::expected<config, config_error> parse_config_with_error(const std::string& filename);
[[nodiscard]] std::optional<config> parse_config(const std::string& filename);
[[nodiscard]] std::string dump_config(const config& cfg);
[[nodiscard]] std::string dump_default_config();

}    // namespace mux

#endif
