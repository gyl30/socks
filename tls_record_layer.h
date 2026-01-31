#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <vector>
#include <cstring>
#include <span>
#include <array>

#include "crypto_util.h"

namespace reality
{
class tls_record_layer
{
   public:
    static void encrypt_record_append(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      uint64_t seq,
                                      const std::vector<uint8_t>& plaintext,
                                      uint8_t content_type,
                                      std::vector<uint8_t>& output_buffer,
                                      std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> encrypt_record(const EVP_CIPHER* cipher,
                                                             const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
                                                             const std::vector<uint8_t>& plaintext,
                                                             uint8_t content_type,
                                                             std::error_code& ec);

    static size_t decrypt_record(const cipher_context& ctx,
                                 const EVP_CIPHER* cipher,
                                 const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& iv,
                                 uint64_t seq,
                                 std::span<const uint8_t> record_data,
                                 std::span<uint8_t> output_buffer,
                                 uint8_t& out_content_type,
                                 std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> decrypt_record(const EVP_CIPHER* cipher,
                                                             const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
                                                             const std::vector<uint8_t>& ciphertext_with_header,
                                                             uint8_t& out_content_type,
                                                             std::error_code& ec);
};

}    // namespace reality

#endif
