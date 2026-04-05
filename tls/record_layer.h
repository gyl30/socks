#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C"
{
#include <openssl/types.h>
}
#include <boost/system/detail/error_code.hpp>

#include "reality/types.h"
#include "tls/cipher_context.h"

namespace tls
{

namespace record_layer
{
void encrypt_tls_record(const cipher_context& ctx,
                        const EVP_CIPHER* cipher,
                        const reality::traffic_key_material& key_material,
                        uint64_t seq,
                        const std::vector<uint8_t>& plaintext,
                        uint8_t content_type,
                        std::vector<uint8_t>& output_buffer,
                        boost::system::error_code& ec);

[[nodiscard]] std::size_t decrypt_tls_record(const cipher_context& ctx,
                                             const EVP_CIPHER* cipher,
                                             const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& iv,
                                             uint64_t seq,
                                             std::span<const uint8_t> record_data,
                                             std::span<uint8_t> output_buffer,
                                             uint8_t& out_content_type,
                                             boost::system::error_code& ec);

[[nodiscard]] std::vector<uint8_t> decrypt_record(const EVP_CIPHER* cipher,
                                                  const std::vector<uint8_t>& key,
                                                  const std::vector<uint8_t>& iv,
                                                  uint64_t seq,
                                                  const std::vector<uint8_t>& ciphertext_with_header,
                                                  uint8_t& out_content_type,
                                                  boost::system::error_code& ec);

}    // namespace record_layer

}    // namespace tls

#endif
