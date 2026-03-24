#ifndef SITE_MATERIAL_H
#define SITE_MATERIAL_H

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace reality
{

struct server_fingerprint
{
    std::uint16_t cipher_suite = 0;
    std::string alpn;
};

struct site_material
{
    std::vector<std::uint8_t> certificate_message;
    std::vector<std::vector<std::uint8_t>> certificate_chain;
    server_fingerprint fingerprint;
    std::vector<std::uint16_t> key_share_groups;
    std::vector<std::uint16_t> server_hello_extension_types;
    std::vector<std::uint16_t> encrypted_extension_types;
    std::optional<std::uint16_t> encrypted_extensions_padding_len;
    bool sends_change_cipher_spec = false;
    std::vector<std::uint16_t> encrypted_handshake_record_sizes;
    std::uint64_t fetched_at_unix_seconds = 0;
};

struct site_material_snapshot
{
    std::string target_host;
    std::string target_sni;
    std::uint16_t port = 0;
    bool fetch_in_progress = false;
    std::uint64_t last_attempt_at_unix_seconds = 0;
    std::uint64_t last_success_at_unix_seconds = 0;
    std::uint64_t next_refresh_at_unix_seconds = 0;
    std::string last_error;
    std::optional<site_material> material;
};

}    // namespace reality

#endif
