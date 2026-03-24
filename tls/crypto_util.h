#ifndef TLS_CRYPTO_UTIL_H
#define TLS_CRYPTO_UTIL_H

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>

extern "C"
{
#include <openssl/types.h>
}

#include <boost/system/error_code.hpp>

#include "tls/core.h"
#include "tls/cipher_context.h"

namespace tls
{

void ensure_openssl_initialized();

class crypto_util
{
   public:
    [[nodiscard]] static std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes);

    [[nodiscard]] static std::vector<std::uint8_t> hex_to_bytes(const std::string& hex);

    [[nodiscard]] static bool base64_url_decode(const std::string& input, std::vector<std::uint8_t>& out);

    [[nodiscard]] static std::uint16_t random_grease();

    [[nodiscard]] static bool generate_x25519_keypair(std::uint8_t out_public[32], std::uint8_t out_private[32]);

    [[nodiscard]] static bool generate_ed25519_keypair(std::uint8_t out_public[32], std::uint8_t out_private[32]);

    [[nodiscard]] static std::vector<std::uint8_t> extract_public_key(const std::vector<std::uint8_t>& private_key,
                                                                      boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> extract_ed25519_public_key(const std::vector<std::uint8_t>& private_key,
                                                                              boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> x25519_derive(const std::vector<std::uint8_t>& private_key,
                                                                 const std::vector<std::uint8_t>& peer_public_key,
                                                                 boost::system::error_code& ec);

    [[nodiscard]] static bool generate_mlkem768_keypair(std::vector<std::uint8_t>& public_key,
                                                        std::vector<std::uint8_t>& private_key,
                                                        boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> mlkem768_encapsulate(const std::vector<std::uint8_t>& public_key,
                                                                        std::vector<std::uint8_t>& shared_secret,
                                                                        boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> mlkem768_decapsulate(const std::vector<std::uint8_t>& private_key,
                                                                        const std::vector<std::uint8_t>& ciphertext,
                                                                        boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> hkdf_extract(const std::vector<std::uint8_t>& salt,
                                                                const std::vector<std::uint8_t>& ikm,
                                                                const EVP_MD* md,
                                                                boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> hkdf_expand(const std::vector<std::uint8_t>& prk,
                                                               const std::vector<std::uint8_t>& info,
                                                               std::size_t len,
                                                               const EVP_MD* md,
                                                               boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> hkdf_expand_label(
        const std::vector<std::uint8_t>& secret,
        const std::string& label,
        const std::vector<std::uint8_t>& context,
        std::size_t length,
        const EVP_MD* md,
        boost::system::error_code& ec);

    [[nodiscard]] static std::size_t aead_decrypt(const cipher_context& ctx,
                                                  const EVP_CIPHER* cipher,
                                                  const std::vector<std::uint8_t>& key,
                                                  std::span<const std::uint8_t> nonce,
                                                  std::span<const std::uint8_t> ciphertext,
                                                  std::span<const std::uint8_t> aad,
                                                  std::span<std::uint8_t> output_buffer,
                                                  boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> aead_decrypt(const EVP_CIPHER* cipher,
                                                                const std::vector<std::uint8_t>& key,
                                                                const std::vector<std::uint8_t>& nonce,
                                                                const std::vector<std::uint8_t>& ciphertext,
                                                                const std::vector<std::uint8_t>& aad,
                                                                boost::system::error_code& ec);

    static void aead_encrypt_append(const cipher_context& ctx,
                                    const EVP_CIPHER* cipher,
                                    const std::vector<std::uint8_t>& key,
                                    const std::vector<std::uint8_t>& nonce,
                                    const std::vector<std::uint8_t>& plaintext,
                                    std::span<const std::uint8_t> aad,
                                    std::vector<std::uint8_t>& output_buffer,
                                    boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> aead_encrypt(const EVP_CIPHER* cipher,
                                                                const std::vector<std::uint8_t>& key,
                                                                const std::vector<std::uint8_t>& nonce,
                                                                const std::vector<std::uint8_t>& plaintext,
                                                                const std::vector<std::uint8_t>& aad,
                                                                boost::system::error_code& ec);

    [[nodiscard]] static openssl_ptrs::evp_pkey_ptr extract_pubkey_from_cert(const std::vector<std::uint8_t>& cert_der,
                                                                             boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> extract_raw_public_key(EVP_PKEY* key, boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> extract_certificate_signature(const std::vector<std::uint8_t>& cert_der,
                                                                                 boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> create_self_signed_ed25519_certificate(const std::vector<std::uint8_t>& private_key,
                                                                                           boost::system::error_code& ec);

    [[nodiscard]] static std::vector<std::uint8_t> hmac_sha512(const std::vector<std::uint8_t>& key,
                                                               const std::vector<std::uint8_t>& data,
                                                               boost::system::error_code& ec);

    static void verify_tls13_signature(EVP_PKEY* pub_key,
                                       std::uint16_t signature_scheme,
                                       const std::vector<std::uint8_t>& transcript_hash,
                                       const std::vector<std::uint8_t>& signature,
                                       boost::system::error_code& ec);
};

}    // namespace tls

#endif
