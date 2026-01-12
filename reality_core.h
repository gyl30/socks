#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <span>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <boost/algorithm/hex.hpp>
#include <boost/system/error_code.hpp>
#include "log.h"

namespace reality
{

static constexpr uint8_t K_REALITY_INFO[] = "REALITY";
static constexpr uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
static constexpr uint8_t CONTENT_TYPE_ALERT = 0x15;
static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
static constexpr uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

static constexpr size_t TLS_RECORD_HEADER_SIZE = 5;
static constexpr size_t AEAD_TAG_SIZE = 16;
static constexpr size_t MAX_TLS_PLAINTEXT_LEN = 16384;

namespace tls_consts
{
constexpr uint16_t VER_1_2 = 0x0303;
constexpr uint16_t VER_1_3 = 0x0304;

namespace ext
{
constexpr uint16_t SNI = 0x0000;
constexpr uint16_t STATUS_REQUEST = 0x0005;
constexpr uint16_t SUPPORTED_GROUPS = 0x000a;
constexpr uint16_t EC_POINT_FORMATS = 0x000b;
constexpr uint16_t SIGNATURE_ALGS = 0x000d;
constexpr uint16_t ALPN = 0x0010;
constexpr uint16_t PADDING = 0x0015;
constexpr uint16_t EXT_MASTER_SECRET = 0x0017;
constexpr uint16_t COMPRESS_CERT = 0x001b;
constexpr uint16_t SUPPORTED_VERSIONS = 0x002b;
constexpr uint16_t KEY_SHARE = 0x0033;
constexpr uint16_t PRE_SHARED_KEY = 0x0029;
constexpr uint16_t RENEGOTIATION_INFO = 0xff01;
}    // namespace ext

namespace group
{
constexpr uint16_t X25519 = 0x001d;
}
}    // namespace tls_consts

namespace openssl_ptrs
{
struct evp_pkey_deleter
{
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct evp_pkey_ctx_deleter
{
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct evp_cipher_ctx_deleter
{
    void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
struct evp_md_ctx_deleter
{
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct x509_deleter
{
    void operator()(X509* p) const { X509_free(p); }
};

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;
using evp_cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, evp_cipher_ctx_deleter>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, evp_md_ctx_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;
}    // namespace openssl_ptrs

class crypto_util
{
   public:
    [[nodiscard]] static std::string bytes_to_hex(const std::vector<uint8_t>& bytes)
    {
        std::string result;
        boost::algorithm::hex(bytes, std::back_inserter(result));
        return result;
    }

    [[nodiscard]] static std::vector<uint8_t> hex_to_bytes(const std::string& hex, boost::system::error_code& ec)
    {
        if (hex.size() % 2 != 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        std::vector<uint8_t> result;
        result.reserve(hex.size() / 2);

        for (size_t i = 0; i < hex.size(); i += 2)
        {
            uint8_t byte = 0;
            for (size_t j = 0; j < 2; ++j)
            {
                const char c = hex[i + j];
                uint8_t val = 0;
                if (c >= '0' && c <= '9')
                {
                    val = c - '0';
                }
                else if (c >= 'a' && c <= 'f')
                {
                    val = c - 'a' + 10;
                }
                else if (c >= 'A' && c <= 'F')
                {
                    val = c - 'A' + 10;
                }
                else
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
                    return {};
                }
                byte = (byte << 4) | val;
            }
            result.push_back(byte);
        }

        ec.clear();
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

    static void generate_x25519_keypair(uint8_t out_pub[32], uint8_t out_priv[32])
    {
        const openssl_ptrs::evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));

        if (pctx && EVP_PKEY_keygen_init(pctx.get()) > 0)
        {
            EVP_PKEY* raw_pkey = nullptr;
            if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) > 0)
            {
                const openssl_ptrs::evp_pkey_ptr pkey(raw_pkey);
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pkey.get(), out_pub, &len);
                len = 32;
                EVP_PKEY_get_raw_private_key(pkey.get(), out_priv, &len);
                return;
            }
        }

        std::memset(out_pub, 0, 32);
        std::memset(out_priv, 0, 32);
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

        const openssl_ptrs::evp_pkey_ptr priv(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
        const openssl_ptrs::evp_pkey_ptr pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), 32));

        if (!priv || !pub)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(priv.get(), nullptr));
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

        const openssl_ptrs::evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
        if (!pctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return {};
        }

        if (EVP_PKEY_derive_init(pctx.get()) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0 ||
            EVP_PKEY_derive(pctx.get(), prk.data(), &len) <= 0)
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

        const openssl_ptrs::evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
        if (!pctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return {};
        }

        if (EVP_PKEY_derive_init(pctx.get()) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_hkdf_mode(pctx.get(), EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0 ||
            EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), prk.data(), static_cast<int>(prk.size())) <= 0 ||
            EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), info.data(), static_cast<int>(info.size())) <= 0 ||
            EVP_PKEY_derive(pctx.get(), okm.data(), &out_len) <= 0)
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

    static size_t aes_gcm_decrypt(const std::vector<uint8_t>& key,
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
        const openssl_ptrs::evp_cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());

        if (!ctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return 0;
        }

        int out_len = 0;
        int ret = 1;

        ret &= EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr);
        ret &= EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
        ret &= EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

        int aad_len_dummy;
        if (!aad.empty())
        {
            ret &= EVP_DecryptUpdate(ctx.get(), nullptr, &aad_len_dummy, aad.data(), static_cast<int>(aad.size()));
        }

        const uint8_t* tag = ciphertext.data() + pt_len;
        const uint8_t* ct_data = ciphertext.data();

        ret &= EVP_DecryptUpdate(ctx.get(), output_buffer.data(), &out_len, ct_data, static_cast<int>(pt_len));
        ret &= EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AEAD_TAG_SIZE, const_cast<void*>(static_cast<const void*>(tag)));

        int final_len = 0;
        ret &= EVP_DecryptFinal_ex(ctx.get(), output_buffer.data() + out_len, &final_len);

        if (ret <= 0)
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
        if (ciphertext.size() < AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }
        std::vector<uint8_t> out(ciphertext.size() - AEAD_TAG_SIZE);
        const size_t n = aes_gcm_decrypt(key, nonce, ciphertext, aad, out, ec);
        if (ec)
        {
            return {};
        }
        out.resize(n);
        return out;
    }

    static void aes_gcm_encrypt_append(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& nonce,
                                       const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& aad,
                                       std::vector<uint8_t>& output_buffer,
                                       boost::system::error_code& ec)
    {
        const EVP_CIPHER* cipher = (key.size() == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
        const openssl_ptrs::evp_cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());

        if (!ctx)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
            return;
        }

        int out_len = 0;
        int final_len = 0;
        int ret = 1;

        const size_t current_size = output_buffer.size();
        const size_t required_size = current_size + plaintext.size() + AEAD_TAG_SIZE;
        if (output_buffer.capacity() < required_size)
        {
            output_buffer.reserve(std::max(output_buffer.capacity() * 2, required_size));
        }
        output_buffer.resize(required_size);
        uint8_t* out_ptr = output_buffer.data() + current_size;

        ret &= EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr);
        ret &= EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
        ret &= EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data());

        int aad_len_dummy;
        if (!aad.empty())
        {
            ret &= EVP_EncryptUpdate(ctx.get(), nullptr, &aad_len_dummy, aad.data(), static_cast<int>(aad.size()));
        }

        ret &= EVP_EncryptUpdate(ctx.get(), out_ptr, &out_len, plaintext.data(), static_cast<int>(plaintext.size()));
        ret &= EVP_EncryptFinal_ex(ctx.get(), out_ptr + out_len, &final_len);

        ret &= EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AEAD_TAG_SIZE, out_ptr + out_len + final_len);

        if (ret <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            output_buffer.resize(current_size);
            return;
        }

        output_buffer.resize(current_size + out_len + final_len + AEAD_TAG_SIZE);
        ec.clear();
    }

    [[nodiscard]] static std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key,
                                                              const std::vector<uint8_t>& nonce,
                                                              const std::vector<uint8_t>& plaintext,
                                                              const std::vector<uint8_t>& aad,
                                                              boost::system::error_code& ec)
    {
        std::vector<uint8_t> out;
        aes_gcm_encrypt_append(key, nonce, plaintext, aad, out, ec);
        return out;
    }
};

struct handshake_keys
{
    std::vector<uint8_t> client_handshake_traffic_secret;
    std::vector<uint8_t> server_handshake_traffic_secret;
    std::vector<uint8_t> master_secret;
};

class tls_key_schedule
{
   public:
    [[nodiscard]] static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_traffic_keys(const std::vector<uint8_t>& secret,
                                                                                                   boost::system::error_code& ec,
                                                                                                   size_t key_len = 16,
                                                                                                   size_t iv_len = 12)
    {
        const std::vector<uint8_t> key = crypto_util::hkdf_expand_label(secret, "key", {}, key_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> iv = crypto_util::hkdf_expand_label(secret, "iv", {}, iv_len, ec);
        if (ec)
        {
            return {};
        }
        return {key, iv};
    }

    [[nodiscard]] static handshake_keys derive_handshake_keys(const std::vector<uint8_t>& shared_secret,
                                                              const std::vector<uint8_t>& server_hello_hash,
                                                              boost::system::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> zero_salt(hash_len, 0);
        const std::vector<uint8_t> early_secret = crypto_util::hkdf_extract(zero_salt, zero_salt, ec);
        if (ec)
        {
            return {};
        }

        std::vector<uint8_t> empty_hash(hash_len, 0);
        SHA256(nullptr, 0, empty_hash.data());

        const std::vector<uint8_t> derived_secret = crypto_util::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> handshake_secret = crypto_util::hkdf_extract(derived_secret, shared_secret, ec);
        if (ec)
        {
            return {};
        }

        const std::vector<uint8_t> c_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> s_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }

        const std::vector<uint8_t> derived_secret_2 = crypto_util::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> master_secret = crypto_util::hkdf_extract(derived_secret_2, zero_salt, ec);
        if (ec)
        {
            return {};
        }

        return {.client_handshake_traffic_secret = c_hs_secret, .server_handshake_traffic_secret = s_hs_secret, .master_secret = master_secret};
    }

    [[nodiscard]] static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                                          const std::vector<uint8_t>& handshake_hash,
                                                                                                          boost::system::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> c_app_secret = crypto_util::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> s_app_secret = crypto_util::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        return {c_app_secret, s_app_secret};
    }

    [[nodiscard]] static std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key,
                                                                           const std::vector<uint8_t>& handshake_hash,
                                                                           boost::system::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> finished_key = crypto_util::hkdf_expand_label(base_key, "finished", {}, hash_len, ec);
        if (ec)
        {
            return {};
        }

        uint8_t hmac_out[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;
        HMAC(EVP_sha256(),
             finished_key.data(),
             static_cast<int>(finished_key.size()),
             handshake_hash.data(),
             handshake_hash.size(),
             hmac_out,
             &hmac_len);
        ec.clear();
        return {hmac_out, hmac_out + hmac_len};
    }
};

class tls_record_layer
{
   public:
    static void encrypt_record_append(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      uint64_t seq,
                                      const std::vector<uint8_t>& plaintext,
                                      uint8_t content_type,
                                      std::vector<uint8_t>& output_buffer,
                                      boost::system::error_code& ec)
    {
        std::vector<uint8_t> inner_plaintext;
        inner_plaintext.reserve(plaintext.size() + 1);
        inner_plaintext.insert(inner_plaintext.end(), plaintext.begin(), plaintext.end());
        inner_plaintext.push_back(content_type);

        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
        }

        const auto ciphertext_len = static_cast<uint16_t>(inner_plaintext.size() + AEAD_TAG_SIZE);

        const size_t old_size = output_buffer.size();
        output_buffer.resize(old_size + 5);
        uint8_t* header = output_buffer.data() + old_size;

        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1] = static_cast<uint8_t>((tls_consts::VER_1_2 >> 8) & 0xFF);
        header[2] = static_cast<uint8_t>(tls_consts::VER_1_2 & 0xFF);
        header[3] = static_cast<uint8_t>((ciphertext_len >> 8) & 0xFF);
        header[4] = static_cast<uint8_t>(ciphertext_len & 0xFF);

        crypto_util::aes_gcm_encrypt_append(key, nonce, inner_plaintext, {header, header + 5}, output_buffer, ec);

        if (ec)
        {
            output_buffer.resize(old_size);
        }
    }

    [[nodiscard]] static std::vector<uint8_t> encrypt_record(const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
                                                             const std::vector<uint8_t>& plaintext,
                                                             uint8_t content_type,
                                                             boost::system::error_code& ec)
    {
        std::vector<uint8_t> out;
        encrypt_record_append(key, iv, seq, plaintext, content_type, out, ec);
        return out;
    }
    static size_t decrypt_record(const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& iv,
                                 uint64_t seq,
                                 std::span<const uint8_t> record_data,
                                 std::span<uint8_t> output_buffer,
                                 uint8_t& out_content_type,
                                 boost::system::error_code& ec)
    {
        if (record_data.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return 0;
        }

        const auto aad = record_data.subspan(0, TLS_RECORD_HEADER_SIZE);
        const auto ciphertext = record_data.subspan(TLS_RECORD_HEADER_SIZE);

        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
        }

        size_t written = crypto_util::aes_gcm_decrypt(key, nonce, ciphertext, aad, output_buffer, ec);
        if (ec)
        {
            return 0;
        }

        while (written > 0 && output_buffer[written - 1] == 0)
        {
            written--;
        }

        if (written == 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return 0;
        }

        out_content_type = output_buffer[written - 1];
        written--;

        ec.clear();
        return written;
    }
    [[nodiscard]] static std::vector<uint8_t> decrypt_record(const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
                                                             const std::vector<uint8_t>& ciphertext_with_header,
                                                             uint8_t& out_content_type,
                                                             boost::system::error_code& ec)
    {
        if (ciphertext_with_header.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }
        std::vector<uint8_t> out(ciphertext_with_header.size() - TLS_RECORD_HEADER_SIZE - AEAD_TAG_SIZE);
        const size_t n = decrypt_record(key, iv, seq, ciphertext_with_header, out, out_content_type, ec);
        if (ec)
        {
            return {};
        }
        out.resize(n);
        return out;
    }
};

class cert_manager
{
   public:
    cert_manager()
    {
        const openssl_ptrs::evp_pkey_ctx_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
        if (pctx)
        {
            EVP_PKEY* raw = nullptr;
            if (EVP_PKEY_keygen_init(pctx.get()) > 0 && EVP_PKEY_keygen(pctx.get(), &raw) > 0)
            {
                temp_key_.reset(raw);
            }
            else
            {
                LOG_ERROR("cert manager failed to generate ed25519 key");
            }
        }
    }

    [[nodiscard]] std::vector<uint8_t> generate_reality_cert(const std::vector<uint8_t>& auth_key) const
    {
        if (!temp_key_)
        {
            return {};
        }

        const openssl_ptrs::x509_ptr x509(X509_new());
        if (!x509)
        {
            return {};
        }

        X509_set_version(x509.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 0);
        X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(x509.get()), 315360000L);
        X509_set_pubkey(x509.get(), temp_key_.get());
        X509_sign(x509.get(), temp_key_.get(), nullptr);

        uint8_t pub_raw[32];
        size_t len = 32;
        EVP_PKEY_get_raw_public_key(temp_key_.get(), pub_raw, &len);

        uint8_t hmac_sig[64];
        unsigned int hmac_len;
        HMAC(EVP_sha512(), auth_key.data(), static_cast<int>(auth_key.size()), pub_raw, 32, hmac_sig, &hmac_len);

        const ASN1_BIT_STRING* sig = nullptr;
        const X509_ALGOR* alg = nullptr;
        X509_get0_signature(&sig, &alg, x509.get());
        ASN1_BIT_STRING_set(const_cast<ASN1_BIT_STRING*>(sig), hmac_sig, 64);

        const int len_der = i2d_X509(x509.get(), nullptr);
        std::vector<uint8_t> der(len_der);
        uint8_t* p = der.data();
        i2d_X509(x509.get(), &p);
        return der;
    }

    [[nodiscard]] EVP_PKEY* get_key() const { return temp_key_.get(); }

   private:
    openssl_ptrs::evp_pkey_ptr temp_key_;
};

}    // namespace reality

#endif
