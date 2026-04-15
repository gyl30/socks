#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <cstdint>
#include <optional>

namespace relay
{

struct config
{
    std::string mode = "server";
    uint32_t workers = 0;

    struct log_t
    {
        std::string level = "info";
        std::string file = "app.log";
    } log;

    struct inbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8844;
    } inbound;

    struct outbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8844;
    } outbound;

    struct socks_t
    {
        bool enabled = true;
        std::string host = "127.0.0.1";
        uint16_t port = 1080;
        bool auth = false;
        std::string username;
        std::string password;
    } socks;

    struct tproxy_t
    {
        bool enabled = false;
        std::string listen_host = "::";
        uint16_t tcp_port = 1081;
        uint16_t udp_port = 0;
        uint32_t mark = 0x11;
    } tproxy;

    struct tun_t
    {
        bool enabled = false;
        std::string name = "socks-tun";
        uint32_t mtu = 1500;
        std::string ipv4 = "198.18.0.1";
        uint8_t ipv4_prefix = 32;
        std::string ipv6 = "fd00::1";
        uint8_t ipv6_prefix = 128;
    } tun;

    struct timeout_t
    {
        uint32_t read = 100;
        uint32_t write = 100;
        uint32_t connect = 10;
        uint32_t idle = 300;
    } timeout;

    struct reality_t
    {
        std::string sni = "www.apple.com";
        std::string fingerprint = "random";
        uint32_t replay_cache_max_entries = 100000;
        uint32_t max_handshake_records = 256;
        std::string private_key;
        std::string public_key;
        std::string short_id;
    } reality;
};

[[nodiscard]] std::optional<config> parse_config(const std::string& filename);
[[nodiscard]] std::string dump_config(const config& cfg);
[[nodiscard]] std::string dump_default_config();

}    // namespace relay

#endif
