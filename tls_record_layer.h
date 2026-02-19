#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>

#include <boost/system/error_code.hpp>

#include "crypto_util.h"

namespace reality
{

class tls_record_layer
{
   public:
    [[nodiscard]] static std::expected<void, boost::system::error_code> encrypt_record_append(const cipher_context& ctx,
                                                                                                const EVP_CIPHER* cipher,
                                                                                                const std::vector<std::uint8_t>& key,
                                                                                                const std::vector<std::uint8_t>& iv,
                                                                                                std::uint64_t seq,
                                                                                                const std::vector<std::uint8_t>& plaintext,
                                                                                                std::uint8_t content_type,
                                                                                                std::vector<std::uint8_t>& output_buffer);

    [[nodiscard]] static std::expected<std::vector<std::uint8_t>, boost::system::error_code> encrypt_record(
        const EVP_CIPHER* cipher,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& iv,
        std::uint64_t seq,
        const std::vector<std::uint8_t>& plaintext,
        std::uint8_t content_type);

    [[nodiscard]] static std::expected<std::size_t, boost::system::error_code> decrypt_record(const cipher_context& ctx,
                                                                                                const EVP_CIPHER* cipher,
                                                                                                const std::vector<std::uint8_t>& key,
                                                                                                const std::vector<std::uint8_t>& iv,
                                                                                                std::uint64_t seq,
                                                                                                std::span<const std::uint8_t> record_data,
                                                                                                std::span<std::uint8_t> output_buffer,
                                                                                                std::uint8_t& out_content_type);

    [[nodiscard]] static std::expected<std::vector<std::uint8_t>, boost::system::error_code> decrypt_record(
        const EVP_CIPHER* cipher,
        const std::vector<std::uint8_t>& key,
        const std::vector<std::uint8_t>& iv,
        std::uint64_t seq,
        const std::vector<std::uint8_t>& ciphertext_with_header,
        std::uint8_t& out_content_type);
};

}    // namespace reality

#endif
