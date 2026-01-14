#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

#include <vector>
#include <string>
#include <cstring>
#include <span>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <boost/system/error_code.hpp>

#include "cipher_context.h"

namespace reality
{

class crypto_util
{
   public:
    [[nodiscard]] static std::string bytes_to_hex(const std::vector<uint8_t>& bytes)
    {
        std::ostringstream oss;
        for (const uint8_t c : bytes)
        {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return oss.str();
    }

    [[nodiscard]] static std::vector<uint8_t> hex_to_bytes(const std::string& hex)
    {
        int64_t len = 0;
        uint8_t* buf = OPENSSL_hexstr2buf(hex.c_str(), &len);
        if (buf == nullptr)
        {
            return {};
        }
        std::vector<uint8_t> result{buf, buf + len};
        OPENSSL_free(buf);
        return result;
    }

    [[nodiscard]] static uint16_t get_random_grease()
    {
        uint8_t idx;
        RAND_bytes(&idx, 1);
        static std::vector<uint16_t> GREASE_VALUES = {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

        return GREASE_VALUES[idx % GREASE_VALUES.size()];
    }

    static void generate_x25519_keypair(uint8_t out_public[32], uint8_t out_private[32])
    {
        const openssl_ptrs::evp_pkey_ctx_ptr pkey_ctx_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));

        if (pkey_ctx_ptr && EVP_PKEY_keygen_init(pkey_ctx_ptr.get()) > 0)
        {
            EVP_PKEY* raw_pkey = nullptr;
            if (EVP_PKEY_keygen(pkey_ctx_ptr.get(), &raw_pkey) > 0)
            {
                const openssl_ptrs::evp_pkey_ptr pkey(raw_pkey);
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pkey.get(), out_public, &len);
                len = 32;
                EVP_PKEY_get_raw_private_key(pkey.get(), out_private, &len);
                return;
            }
        }

        std::memset(out_public, 0, 32);
        std::memset(out_private, 0, 32);
    }

    [[nodiscard]] static std::vector<uint8_t> extract_public_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
    {
        if (private_key.size() != 32)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
        if (!pkey)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        size_t len = 32;
        std::vector<uint8_t> public_key(32);
        if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &len) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        ec.clear();
        return public_key;
    }

    [[nodiscard]] static std::vector<uint8_t> x25519_derive(const std::vector<uint8_t>& private_key,
                                                            const std::vector<uint8_t>& peer_public_key,
                                                            boost::system::error_code& ec)
    {
        if (private_key.size() != 32 || peer_public_key.size() != 32)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
        const openssl_ptrs::evp_pkey_ptr pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), 32));

        if (!pkey || !pub)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
        if (!ctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return {};
        }

        std::vector<uint8_t> shared(32);
        size_t len = 32;

        if (EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0 ||
            EVP_PKEY_derive(ctx.get(), shared.data(), &len) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        ec.clear();
        return shared;
    }

    [[nodiscard]] static std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                                           const std::vector<uint8_t>& ikm,
                                                           boost::system::error_code& ec)
    {
        std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
        size_t len = EVP_MAX_MD_SIZE;

        const openssl_ptrs::evp_pkey_ctx_ptr evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
        if (!evp_pkey_ctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return {};
        }

        if (EVP_PKEY_derive_init(evp_pkey_ctx.get()) <= 0 || EVP_PKEY_CTX_set_hkdf_md(evp_pkey_ctx.get(), EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(evp_pkey_ctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(evp_pkey_ctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0 ||
            EVP_PKEY_derive(evp_pkey_ctx.get(), prk.data(), &len) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        prk.resize(len);
        ec.clear();
        return prk;
    }

    [[nodiscard]] static std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                                          const std::vector<uint8_t>& info,
                                                          size_t len,
                                                          boost::system::error_code& ec)
    {
        std::vector<uint8_t> okm(len);
        size_t out_len = len;

        const openssl_ptrs::evp_pkey_ctx_ptr evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
        if (!evp_pkey_ctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return {};
        }

        if (EVP_PKEY_derive_init(evp_pkey_ctx.get()) <= 0 || EVP_PKEY_CTX_set_hkdf_md(evp_pkey_ctx.get(), EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_mode(evp_pkey_ctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(evp_pkey_ctx.get(), prk.data(), static_cast<int>(prk.size())) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(evp_pkey_ctx.get(), info.data(), static_cast<int>(info.size())) <= 0 ||
            EVP_PKEY_derive(evp_pkey_ctx.get(), okm.data(), &out_len) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        ec.clear();
        return okm;
    }

    [[nodiscard]] static std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                                                const std::string& label,
                                                                const std::vector<uint8_t>& context,
                                                                size_t length,
                                                                boost::system::error_code& ec)
    {
        std::string full_label = "tls13 " + label;
        std::vector<uint8_t> hkdf_label;
        hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());

        hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
        hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
        hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
        hkdf_label.push_back(static_cast<uint8_t>(context.size()));
        hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

        return hkdf_expand(secret, hkdf_label, length, ec);
    }

    static size_t aes_gcm_decrypt(const cipher_context& ctx,
                                  const std::vector<uint8_t>& key,
                                  std::span<const uint8_t> nonce,
                                  std::span<const uint8_t> ciphertext,
                                  std::span<const uint8_t> aad,
                                  std::span<uint8_t> output_buffer,
                                  boost::system::error_code& ec)
    {
        if (ciphertext.size() < AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return 0;
        }

        const size_t pt_len = ciphertext.size() - AEAD_TAG_SIZE;
        if (output_buffer.size() < pt_len)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::no_buffer_space);
            return 0;
        }

        const EVP_CIPHER* cipher = (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();

        if (!ctx.init(false, cipher, key.data(), nonce.data(), nonce.size()))
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return 0;
        }

        int out_len = 0;
        int len = 0;

        const uint8_t* tag = ciphertext.data() + pt_len;

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AEAD_TAG_SIZE, const_cast<void*>(static_cast<const void*>(tag))) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return 0;
        }

        if (!aad.empty())
        {
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                return 0;
            }
        }

        if (EVP_DecryptUpdate(ctx.get(), output_buffer.data(), &out_len, ciphertext.data(), static_cast<int>(pt_len)) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return 0;
        }

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), output_buffer.data() + out_len, &final_len) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return 0;
        }

        ec.clear();
        return out_len + final_len;
    }

    [[nodiscard]] static std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                                              const std::vector<uint8_t>& nonce,
                                                              const std::vector<uint8_t>& ciphertext,
                                                              const std::vector<uint8_t>& aad,
                                                              boost::system::error_code& ec)
    {
        const cipher_context ctx;
        if (ciphertext.size() < AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }
        std::vector<uint8_t> out(ciphertext.size() - AEAD_TAG_SIZE);
        const size_t n = aes_gcm_decrypt(ctx, key, nonce, ciphertext, aad, out, ec);
        if (ec)
        {
            return {};
        }
        out.resize(n);
        return out;
    }

    static void aes_gcm_encrypt_append(const cipher_context& ctx,
                                       const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce,
                                       const std::vector<uint8_t>& plaintext,
                                       std::span<const uint8_t> aad,
                                       std::vector<uint8_t>& output_buffer,
                                       boost::system::error_code& ec)
    {
        const EVP_CIPHER* cipher = (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();

        if (!ctx.init(true, cipher, key.data(), nonce.data(), nonce.size()))
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return;
        }

        int out_len = 0;
        int len = 0;

        const size_t current_size = output_buffer.size();
        const size_t required_size = current_size + plaintext.size() + AEAD_TAG_SIZE;
        if (output_buffer.capacity() < required_size)
        {
            output_buffer.reserve(std::max(output_buffer.capacity() * 2, required_size));
        }
        output_buffer.resize(required_size);
        uint8_t* out_ptr = output_buffer.data() + current_size;

        if (!aad.empty())
        {
            EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size()));
        }

        EVP_EncryptUpdate(ctx.get(), out_ptr, &out_len, plaintext.data(), static_cast<int>(plaintext.size()));

        int final_len = 0;
        EVP_EncryptFinal_ex(ctx.get(), out_ptr + out_len, &final_len);

        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AEAD_TAG_SIZE, out_ptr + out_len + final_len);

        output_buffer.resize(current_size + out_len + final_len + AEAD_TAG_SIZE);
        ec.clear();
    }

    [[nodiscard]] static std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key,
                                                              const std::vector<uint8_t>& nonce,
                                                              const std::vector<uint8_t>& plaintext,
                                                              const std::vector<uint8_t>& aad,
                                                              boost::system::error_code& ec)
    {
        const cipher_context ctx;
        std::vector<uint8_t> out;
        aes_gcm_encrypt_append(ctx, key, nonce, plaintext, aad, out, ec);
        return out;
    }
};
}    // namespace reality
#endif
