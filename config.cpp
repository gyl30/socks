#include "config.h"
#include "reflect.h"
#include "mux_protocol.h"
#include "tls/crypto_util.h"

#include <openssl/rand.h>

namespace reflect
{

REFLECT_STRUCT(mux::config::log_t, level, file);
REFLECT_STRUCT(mux::config::inbound_t, host, port);
REFLECT_STRUCT(mux::config::outbound_t, host, port);
REFLECT_STRUCT(mux::config::socks_t, enabled, host, port, auth, username, password);
REFLECT_STRUCT(mux::config::tproxy_t, enabled, listen_host, tcp_port, udp_port, mark);
REFLECT_STRUCT(mux::config::timeout_t, read, write, connect, idle);
REFLECT_STRUCT(mux::config::reality_t, sni, fingerprint, replay_cache_max_entries, private_key, public_key, short_id);
REFLECT_STRUCT(mux::config::limits_t, max_connections, tunnel_connections, max_buffer, max_streams, max_handshake_records);
REFLECT_STRUCT(mux::config::heartbeat_t, enabled, min_interval, max_interval, min_padding, max_padding);
REFLECT_STRUCT(mux::config, mode, workers, log, inbound, outbound, socks, tproxy, timeout, reality, limits, heartbeat);

}    // namespace reflect

namespace mux
{

static std::string read_file_to_string(const char* filename, std::size_t read_size)
{
    std::string content;
    FILE* fp = ::fopen(filename, "rb");
    if (fp == nullptr)
    {
        return content;
    }

    char buf[8192] = {0};
    while (true)
    {
        // 文件末尾
        if (feof(fp) != 0)
        {
            break;
        }
        // 错误
        if (ferror(fp) != 0)
        {
            break;
        }
        auto read_bytes = ::fread(buf, 1, sizeof buf, fp);
        if (read_bytes == 0)
        {
            break;
        }

        content.append(buf, read_bytes);

        if (content.size() >= read_size)
        {
            break;
        }
    }
    ::fclose(fp);
    return content;
}
std::optional<config> parse_config(const std::string& filename)
{
    const auto file_content = read_file_to_string(filename.c_str(), 1024UL * 1024);
    config cfg;
    if (!reflect::deserialize_struct(cfg, file_content))
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
    std::uint8_t short_id[8] = {0};
    const auto wipe_keys = [&]()
    {
        OPENSSL_cleanse(private_key, sizeof(private_key));
        OPENSSL_cleanse(public_key, sizeof(public_key));
        OPENSSL_cleanse(short_id, sizeof(short_id));
    };
    if (::tls::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        cfg.reality.private_key = ::tls::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(private_key, private_key + 32));
        cfg.reality.public_key = ::tls::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32));
    }
    if (RAND_bytes(short_id, sizeof(short_id)) != 1)
    {
        std::memcpy(short_id, private_key, sizeof(short_id));
    }
    cfg.reality.short_id = ::tls::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(short_id, short_id + sizeof(short_id)));
    wipe_keys();
    return dump_config(cfg);
}

}    // namespace mux
