#ifndef TLS_HANDSHAKE_BUILDER_H
#define TLS_HANDSHAKE_BUILDER_H

#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

extern "C"
{
#include <openssl/types.h>
}

namespace tls
{

std::vector<std::uint8_t> write_record_header(std::uint8_t record_type, std::uint16_t length);

std::vector<std::uint8_t> construct_server_hello(const std::vector<std::uint8_t>& server_random,
                                                 const std::vector<std::uint8_t>& session_id,
                                                 std::uint16_t cipher_suite,
                                                 std::uint16_t key_share_group,
                                                 const std::vector<std::uint8_t>& key_share_data,
                                                 std::span<const std::uint16_t> extension_order = {});

std::vector<std::uint8_t> construct_encrypted_extensions(const std::string& alpn,
                                                         std::span<const std::uint16_t> extension_order = {},
                                                         bool include_padding = true,
                                                         std::optional<std::uint16_t> padding_len = std::nullopt);

std::vector<std::uint8_t> construct_certificate(std::span<const std::vector<std::uint8_t>> cert_chain);

std::vector<std::uint8_t> construct_certificate(const std::vector<std::uint8_t>& cert_der);

std::vector<std::uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<std::uint8_t>& handshake_hash);

std::vector<std::uint8_t> construct_finished(const std::vector<std::uint8_t>& verify_data);

}    // namespace tls

#endif
