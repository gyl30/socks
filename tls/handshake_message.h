#ifndef TLS_HANDSHAKE_MESSAGE_H
#define TLS_HANDSHAKE_MESSAGE_H

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace tls
{

struct handshake_extension_layout
{
    std::vector<std::uint16_t> types;
    std::optional<std::uint16_t> padding_len;
};

struct server_key_share_info
{
    std::uint16_t group = 0;
    std::vector<std::uint8_t> data;
};

struct server_hello_info
{
    std::uint16_t legacy_version = 0;
    std::vector<std::uint8_t> session_id;
    std::uint16_t cipher_suite = 0;
    std::uint8_t compression_method = 0xff;
    std::uint16_t supported_version = 0;
    bool has_supported_version = false;
    bool has_key_share = false;
    bool has_forbidden_tls13_extension = false;
    bool is_hello_retry_request = false;
    server_key_share_info key_share;
};

struct encrypted_extensions_info
{
    bool has_alpn = false;
    std::string alpn;
};

struct certificate_verify_info
{
    std::uint16_t scheme = 0;
    std::vector<std::uint8_t> signature;
};

[[nodiscard]] bool extract_handshake_message(std::span<const std::uint8_t> data, std::vector<std::uint8_t>& message);

[[nodiscard]] bool parse_server_hello_extension_layout(std::span<const std::uint8_t> server_hello, handshake_extension_layout& layout);

[[nodiscard]] bool parse_encrypted_extensions_layout(std::span<const std::uint8_t> encrypted_extensions, handshake_extension_layout& layout);

[[nodiscard]] bool parse_certificate_chain(std::span<const std::uint8_t> certificate_message,
                                           std::vector<std::vector<std::uint8_t>>& certificate_chain);

[[nodiscard]] bool extract_first_certificate(std::span<const std::uint8_t> certificate_message, std::vector<std::uint8_t>& certificate);

std::optional<server_hello_info> parse_server_hello(std::span<const std::uint8_t> server_hello);

std::optional<std::uint16_t> extract_cipher_suite_from_server_hello(std::span<const std::uint8_t> server_hello);

std::optional<server_key_share_info> extract_server_key_share(std::span<const std::uint8_t> server_hello);

std::vector<std::uint8_t> extract_server_public_key(std::span<const std::uint8_t> server_hello);

std::optional<encrypted_extensions_info> parse_encrypted_extensions(std::span<const std::uint8_t> encrypted_extensions);

std::optional<std::string> extract_alpn_from_encrypted_extensions(std::span<const std::uint8_t> encrypted_extensions);

std::optional<certificate_verify_info> parse_certificate_verify(std::span<const std::uint8_t> message);

[[nodiscard]] bool is_supported_certificate_verify_scheme(std::uint16_t scheme);

[[nodiscard]] const char* named_group_name(std::uint16_t group);

}    // namespace tls

#endif
