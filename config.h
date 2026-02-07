#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace mux
{

struct config
{
    std::string mode = "server";

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
        std::string host = "127.0.0.1";
        std::uint16_t port = 1080;
        bool auth = false;
        std::string username;
        std::string password;
    } socks;

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
        std::uint64_t max_buffer = 10L * 1024 * 1024;
    } limits;

    struct heartbeat_t
    {
        bool enabled = true;
        std::uint32_t min_interval = 15;
        std::uint32_t max_interval = 45;
        std::uint32_t min_padding = 32;
        std::uint32_t max_padding = 1024;
    } heartbeat;

    struct reality_t
    {
        std::string sni = "www.apple.com";

        std::string private_key = "b0c338c6353fab820a0e5d16b6fcf41ee4166940795f89d0cde8902675ce9456";
        std::string public_key = "8d4e6ddf1479f2305b6645f045e02f9f5e400005884a8f1663ee9c51915bcc6d";
        std::string short_id;
        std::string verify_public_key;
    } reality;
};

[[nodiscard]] std::optional<config> parse_config(const std::string& filename);
[[nodiscard]] std::string dump_config(const config& cfg);
[[nodiscard]] std::string dump_default_config();

}    // namespace mux

#endif
