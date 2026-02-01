#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

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
        uint16_t port = 8844;
    } inbound;

    struct outbound_t
    {
        std::string host = "0.0.0.0";
        uint16_t port = 8844;
    } outbound;

    struct socks_t
    {
        std::string host = "127.0.0.1";
        uint16_t port = 1080;
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
        uint32_t read = 100;
        uint32_t write = 100;
        uint32_t idle = 300;
    } timeout;

    struct reality_t
    {
        std::string sni = "www.apple.com";
        // 警告：这是用于演示/开发的默认私钥。
        // 在生产环境中，任何硬编码的私钥都是安全风险。
        // 请生成一个新的密钥并从环境变量或安全保管库加载它。
        std::string private_key = "b0c338c6353fab820a0e5d16b6fcf41ee4166940795f89d0cde8902675ce9456";
        std::string public_key = "8d4e6ddf1479f2305b6645f045e02f9f5e400005884a8f1663ee9c51915bcc6d";
    } reality;
};

std::optional<config> parse_config(const std::string& filename);
std::string dump_config(const config& cfg);
std::string dump_default_config();

#endif
