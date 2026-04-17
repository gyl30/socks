#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace relay
{

struct config
{
    struct log_t
    {
        std::string level = "info";
        std::string file = "app.log";
    };

    struct socks_t
    {
        bool enabled = true;
        std::string host = "127.0.0.1";
        uint16_t port = 1080;
        bool auth = false;
        std::string username;
        std::string password;
    };

    struct tproxy_t
    {
        bool enabled = false;
        std::string listen_host = "::";
        uint16_t tcp_port = 1081;
        uint16_t udp_port = 0;
        uint32_t mark = 0x11;
    };

    struct tun_t
    {
        bool enabled = false;
        std::string name = "socks-tun";
        uint32_t mtu = 1500;
        std::string ipv4 = "198.18.0.1";
        uint8_t ipv4_prefix = 32;
        std::string ipv6 = "fd00::1";
        uint8_t ipv6_prefix = 128;
    };

    struct timeout_t
    {
        uint32_t read = 100;
        uint32_t write = 100;
        uint32_t connect = 10;
        uint32_t idle = 300;
    };

    struct web_t
    {
        bool enabled = false;
        std::string host = "127.0.0.1";
        uint16_t port = 18080;
    };

    struct reality_inbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 443;
        std::string sni = "www.apple.com";
        uint16_t site_port = 443;
        std::string private_key;
        std::string public_key;
        std::string short_id;
        uint32_t replay_cache_max_entries = 100000;
    };

    struct reality_outbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 443;
        std::string sni = "www.apple.com";
        std::string fingerprint = "random";
        std::string public_key;
        std::string short_id;
        uint32_t max_handshake_records = 256;
    };

    struct inbound_entry_t
    {
        std::string type;
        std::string tag;
        std::optional<socks_t> socks;
        std::optional<tproxy_t> tproxy;
        std::optional<tun_t> tun;
        std::optional<reality_inbound_t> reality;
    };

    struct outbound_entry_t
    {
        std::string type;
        std::string tag;
        std::optional<reality_outbound_t> reality;
        std::optional<socks_t> socks;
    };

    struct route_rule_t
    {
        std::string type;
        std::vector<std::string> values;
        std::string file;
        std::vector<std::string> file_values;
        std::string out;
    };

    uint32_t workers = 0;
    log_t log;
    timeout_t timeout;
    web_t web;
    std::vector<inbound_entry_t> inbounds;
    std::vector<outbound_entry_t> outbounds;
    std::vector<route_rule_t> routing;
};

[[nodiscard]] const config::inbound_entry_t* find_inbound_entry(const config& cfg, std::string_view tag);
[[nodiscard]] const config::outbound_entry_t* find_outbound_entry(const config& cfg, std::string_view tag);
[[nodiscard]] const config::socks_t* find_socks_outbound_settings(const config& cfg, std::string_view tag);
[[nodiscard]] const config::reality_outbound_t* find_reality_outbound_settings(const config& cfg, std::string_view tag);
[[nodiscard]] uint32_t resolve_socket_mark(const config& cfg);

[[nodiscard]] std::optional<config> parse_config(const std::string& filename);
[[nodiscard]] std::string dump_config(const config& cfg);
[[nodiscard]] std::string dump_default_config();

}    // namespace relay

#endif
