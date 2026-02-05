#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <system_error>
#include <vector>

#include "crypto_util.h"

namespace reality
{

class tls_record_layer
{
   public:
    static void encrypt_record_append(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const std::vector<std::uint8_t>& key,
                                      const std::vector<std::uint8_t>& iv,
                                      std::uint64_t seq,
                                      const std::vector<std::uint8_t>& plaintext,
                                      std::uint8_t content_type,
                                      std::vector<std::uint8_t>& output_buffer,
                                      std::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> encrypt_record(const EVP_CIPHER* cipher,
                                                                  const std::vector<std::uint8_t>& key,
                                                                  const std::vector<std::uint8_t>& iv,
                                                                  std::uint64_t seq,
                                                                  const std::vector<std::uint8_t>& plaintext,
                                                                  std::uint8_t content_type,
                                                                  std::error_code& ec);

    static std::size_t decrypt_record(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const std::vector<std::uint8_t>& key,
                                      const std::vector<std::uint8_t>& iv,
                                      std::uint64_t seq,
                                      std::span<const std::uint8_t> record_data,
                                      std::span<std::uint8_t> output_buffer,
                                      std::uint8_t& out_content_type,
                                      std::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> decrypt_record(const EVP_CIPHER* cipher,
                                                                  const std::vector<std::uint8_t>& key,
                                                                  const std::vector<std::uint8_t>& iv,
                                                                  std::uint64_t seq,
                                                                  const std::vector<std::uint8_t>& ciphertext_with_header,
                                                                  std::uint8_t& out_content_type,
                                                                  std::error_code& ec);
};

}    // namespace reality

#endif