#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <system_error>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "reality_core.h"
#include "cipher_context.h"

namespace reality
{

class crypto_util
{
   public:
    [[nodiscard]] static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);

    [[nodiscard]] static std::vector<uint8_t> hex_to_bytes(const std::string& hex);

    [[nodiscard]] static uint16_t get_random_grease();

    [[nodiscard]] static bool generate_x25519_keypair(uint8_t out_public[32], uint8_t out_private[32]);

    [[nodiscard]] static std::vector<uint8_t> extract_public_key(const std::vector<uint8_t>& private_key, std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> extract_ed25519_public_key(const std::vector<uint8_t>& private_key, std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> x25519_derive(const std::vector<uint8_t>& private_key,
                                                            const std::vector<uint8_t>& peer_public_key,
                                                            std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                                           const std::vector<uint8_t>& ikm,
                                                           const EVP_MD* md,
                                                           std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> hkdf_expand(
        const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t len, const EVP_MD* md, std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                                                const std::string& label,
                                                                const std::vector<uint8_t>& context,
                                                                size_t length,
                                                                const EVP_MD* md,
                                                                std::error_code& ec);

    static size_t aead_decrypt(const cipher_context& ctx,
                               const EVP_CIPHER* cipher,
                               const std::vector<uint8_t>& key,
                               std::span<const uint8_t> nonce,
                               std::span<const uint8_t> ciphertext,
                               std::span<const uint8_t> aad,
                               std::span<uint8_t> output_buffer,
                               std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> aead_decrypt(const EVP_CIPHER* cipher,
                                                           const std::vector<uint8_t>& key,
                                                           const std::vector<uint8_t>& nonce,
                                                           const std::vector<uint8_t>& ciphertext,
                                                           const std::vector<uint8_t>& aad,
                                                           std::error_code& ec);

    static void aead_encrypt_append(const cipher_context& ctx,
                                    const EVP_CIPHER* cipher,
                                    const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& nonce,
                                    const std::vector<uint8_t>& plaintext,
                                    std::span<const uint8_t> aad,
                                    std::vector<uint8_t>& output_buffer,
                                    std::error_code& ec);

    [[nodiscard]] static std::vector<uint8_t> aead_encrypt(const EVP_CIPHER* cipher,
                                                           const std::vector<uint8_t>& key,
                                                           const std::vector<uint8_t>& nonce,
                                                           const std::vector<uint8_t>& plaintext,
                                                           const std::vector<uint8_t>& aad,
                                                           std::error_code& ec);

    [[nodiscard]] static openssl_ptrs::evp_pkey_ptr extract_pubkey_from_cert(const std::vector<uint8_t>& cert_der, std::error_code& ec);

    static bool verify_tls13_signature(EVP_PKEY* pub_key,
                                       const std::vector<uint8_t>& transcript_hash,
                                       const std::vector<uint8_t>& signature,
                                       std::error_code& ec);
};
}    // namespace reality
#endif
