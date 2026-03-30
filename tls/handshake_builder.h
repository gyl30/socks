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

std::vector<uint8_t> write_record_header(uint8_t record_type, uint16_t length);

std::vector<uint8_t> construct_server_hello(const std::vector<uint8_t>& server_random,
                                            const std::vector<uint8_t>& session_id,
                                            uint16_t cipher_suite,
                                            uint16_t key_share_group,
                                            const std::vector<uint8_t>& key_share_data,
                                            std::span<const uint16_t> extension_order = {});

std::vector<uint8_t> construct_encrypted_extensions(const std::string& alpn,
                                                    std::span<const uint16_t> extension_order = {},
                                                    bool include_padding = true,
                                                    std::optional<uint16_t> padding_len = std::nullopt);

std::vector<uint8_t> construct_certificate(std::span<const std::vector<uint8_t>> cert_chain);

std::vector<uint8_t> construct_certificate(const std::vector<uint8_t>& cert_der);

std::vector<uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<uint8_t>& handshake_hash);

std::vector<uint8_t> construct_finished(const std::vector<uint8_t>& verify_data);

}    // namespace tls

#endif
