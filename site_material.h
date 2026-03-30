#ifndef SITE_MATERIAL_H
#define SITE_MATERIAL_H

#include <string>
#include <vector>
#include <optional>

namespace reality
{

struct server_fingerprint
{
    uint16_t cipher_suite = 0;
    std::string alpn;
};

struct site_material
{
    std::vector<uint8_t> certificate_message;
    std::vector<std::vector<uint8_t>> certificate_chain;
    server_fingerprint fingerprint;
    std::vector<uint16_t> key_share_groups;
    std::vector<uint16_t> server_hello_extension_types;
    std::vector<uint16_t> encrypted_extension_types;
    std::optional<uint16_t> encrypted_extensions_padding_len;
    bool sends_change_cipher_spec = false;
    std::vector<uint16_t> encrypted_handshake_record_sizes;
    uint64_t fetched_at_unix_seconds = 0;
};

}    // namespace reality

#endif
