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

    struct inbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8844;
    };

    struct outbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8844;
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

    struct reality_t
    {
        std::string sni = "www.apple.com";
        std::string fingerprint = "random";
        uint32_t replay_cache_max_entries = 100000;
        uint32_t max_handshake_records = 256;
        std::string private_key;
        std::string public_key;
        std::string short_id;
    };

    struct reality_inbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 443;
        std::string sni = "www.apple.com";
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
    std::vector<inbound_entry_t> inbounds;
    std::vector<outbound_entry_t> outbounds;
    std::vector<route_rule_t> routing;

    std::string active_inbound_tag;
    inbound_t inbound;
    outbound_t outbound;
    socks_t socks;
    tproxy_t tproxy;
    tun_t tun;
    reality_t reality;
};

[[nodiscard]] const config::inbound_entry_t* find_inbound_entry(const config& cfg, std::string_view tag);
[[nodiscard]] const config::outbound_entry_t* find_outbound_entry(const config& cfg, std::string_view tag);
[[nodiscard]] const config::inbound_entry_t* find_first_inbound_entry(const config& cfg, std::string_view type);
[[nodiscard]] const config::outbound_entry_t* find_first_outbound_entry(const config& cfg, std::string_view type);
[[nodiscard]] config make_runtime_config(const config& cfg, const config::inbound_entry_t& inbound);

[[nodiscard]] std::optional<config> parse_config(const std::string& filename);
[[nodiscard]] std::string dump_config(const config& cfg);
[[nodiscard]] std::string dump_default_config();

}    // namespace relay

#endif
