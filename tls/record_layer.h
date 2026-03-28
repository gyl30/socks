#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <boost/system/detail/error_code.hpp>

extern "C"
{
#include <openssl/types.h>
}

#include "tls/cipher_context.h"

namespace reality
{

struct traffic_key_material;

}    // namespace reality

namespace tls
{

class record_layer
{
   public:
    static void encrypt_record_append(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const reality::traffic_key_material& key_material,
                                      std::uint64_t seq,
                                      const std::vector<std::uint8_t>& plaintext,
                                      std::uint8_t content_type,
                                      std::vector<std::uint8_t>& output_buffer,
                                      boost::system::error_code& ec);

    [[nodiscard]] static std::size_t decrypt_tls_record(const cipher_context& ctx,
                                                    const EVP_CIPHER* cipher,
                                                    const std::vector<std::uint8_t>& key,
                                                    const std::vector<std::uint8_t>& iv,
                                                    std::uint64_t seq,
                                                    std::span<const std::uint8_t> record_data,
                                                    std::span<std::uint8_t> output_buffer,
                                                    std::uint8_t& out_content_type,
                                                    boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> decrypt_record(const EVP_CIPHER* cipher,
                                                                  const std::vector<std::uint8_t>& key,
                                                                  const std::vector<std::uint8_t>& iv,
                                                                  std::uint64_t seq,
                                                                  const std::vector<std::uint8_t>& ciphertext_with_header,
                                                                  std::uint8_t& out_content_type,
                                                                  boost::system::error_code& ec);
};

}    // namespace tls

#endif
