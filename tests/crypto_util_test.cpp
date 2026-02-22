
#include <atomic>
#include <ios>
#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <utility>
#include <iterator>
#include <algorithm>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
}

#include "crypto_util.h"
#include "cipher_context.h"

using reality::crypto_util;

namespace
{

std::atomic<bool> g_fail_hkdf_set_key{false};
std::atomic<bool> g_fail_hkdf_set_salt{false};
std::atomic<bool> g_fail_set_gcm_tag{false};
std::atomic<bool> g_fail_x509_get_pubkey{false};
std::atomic<bool> g_fail_rand_bytes{false};
std::atomic<bool> g_fail_x25519_ctx_new_id{false};
std::atomic<bool> g_fail_x25519_raw_private_key{false};
std::atomic<bool> g_fail_ed25519_raw_private_key{false};
std::atomic<bool> g_fail_hkdf_add_info{false};
std::atomic<bool> g_fail_md_ctx_new{false};
std::atomic<bool> g_fail_pkey_derive{false};
std::atomic<bool> g_fail_get_gcm_tag{false};
std::atomic<bool> g_fail_encrypt_update{false};
std::atomic<bool> g_fail_encrypt_final{false};
std::atomic<bool> g_fail_x25519_get_raw_public_key{false};
std::atomic<bool> g_fail_x25519_get_raw_private_key{false};

void fail_next_hkdf_set_key() { g_fail_hkdf_set_key.store(true, std::memory_order_release); }

void fail_next_hkdf_set_salt() { g_fail_hkdf_set_salt.store(true, std::memory_order_release); }

void fail_next_set_gcm_tag() { g_fail_set_gcm_tag.store(true, std::memory_order_release); }

void fail_next_x509_get_pubkey() { g_fail_x509_get_pubkey.store(true, std::memory_order_release); }

void fail_next_rand_bytes() { g_fail_rand_bytes.store(true, std::memory_order_release); }

void fail_next_x25519_ctx_new_id() { g_fail_x25519_ctx_new_id.store(true, std::memory_order_release); }

void fail_next_x25519_raw_private_key() { g_fail_x25519_raw_private_key.store(true, std::memory_order_release); }

void fail_next_ed25519_raw_private_key() { g_fail_ed25519_raw_private_key.store(true, std::memory_order_release); }

void fail_next_hkdf_add_info() { g_fail_hkdf_add_info.store(true, std::memory_order_release); }

void fail_next_md_ctx_new() { g_fail_md_ctx_new.store(true, std::memory_order_release); }

void fail_next_pkey_derive() { g_fail_pkey_derive.store(true, std::memory_order_release); }

void fail_next_get_gcm_tag() { g_fail_get_gcm_tag.store(true, std::memory_order_release); }

void fail_next_encrypt_update() { g_fail_encrypt_update.store(true, std::memory_order_release); }

void fail_next_encrypt_final() { g_fail_encrypt_final.store(true, std::memory_order_release); }

void fail_next_x25519_get_raw_public_key() { g_fail_x25519_get_raw_public_key.store(true, std::memory_order_release); }

void fail_next_x25519_get_raw_private_key() { g_fail_x25519_get_raw_private_key.store(true, std::memory_order_release); }

std::vector<std::uint8_t> build_self_signed_cert_der()
{
    EVP_PKEY* raw_key = nullptr;
    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (key_ctx == nullptr)
    {
        return {};
    }
    if (EVP_PKEY_keygen_init(key_ctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 1024) != 1 || EVP_PKEY_keygen(key_ctx, &raw_key) != 1 ||
        raw_key == nullptr)
    {
        EVP_PKEY_CTX_free(key_ctx);
        if (raw_key != nullptr)
        {
            EVP_PKEY_free(raw_key);
        }
        return {};
    }
    EVP_PKEY_CTX_free(key_ctx);

    X509* cert = X509_new();
    if (cert == nullptr)
    {
        EVP_PKEY_free(raw_key);
        return {};
    }

    const bool setup_ok = X509_set_version(cert, 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1 &&
                          X509_gmtime_adj(X509_get_notBefore(cert), 0) != nullptr && X509_gmtime_adj(X509_get_notAfter(cert), 60) != nullptr &&
                          X509_set_pubkey(cert, raw_key) == 1;

    X509_NAME* name = X509_get_subject_name(cert);
    const bool name_ok = name != nullptr &&
                         X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("with-key"), -1, -1, 0) == 1 &&
                         X509_set_issuer_name(cert, name) == 1;

    const bool sign_ok = X509_sign(cert, raw_key, EVP_sha256()) > 0;
    EVP_PKEY_free(raw_key);
    if (!setup_ok || !name_ok || !sign_ok)
    {
        X509_free(cert);
        return {};
    }

    const int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0)
    {
        X509_free(cert);
        return {};
    }

    std::vector<std::uint8_t> der(static_cast<std::size_t>(der_len));
    unsigned char* p = der.data();
    const int encoded_len = i2d_X509(cert, &p);
    X509_free(cert);
    if (encoded_len != der_len)
    {
        return {};
    }
    return der;
}

}    // namespace

extern "C" int __real_EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX* ctx, const unsigned char* key, int keylen);    
extern "C" int __real_EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* salt,
                                                  int saltlen);                                  
extern "C" int __real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);    
extern "C" EVP_PKEY* __real_X509_get_pubkey(X509* x);                                            
extern "C" int __real_RAND_bytes(unsigned char* buf, int num);                                   
extern "C" EVP_PKEY_CTX* __real_EVP_PKEY_CTX_new_id(int id, ENGINE* e);                          
extern "C" EVP_PKEY* __real_EVP_PKEY_new_raw_private_key(int type,
                                                         ENGINE* e,
                                                         const unsigned char* key,
                                                         size_t keylen);    
extern "C" int __real_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* info,
                                                  int infolen);                                  
extern "C" EVP_MD_CTX* __real_EVP_MD_CTX_new();                                                  
extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);    
extern "C" int __real_EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx,
                                        unsigned char* out,
                                        int* outl,
                                        const unsigned char* in,
                                        int inl);    
extern "C" int __real_EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl);    
extern "C" int __real_EVP_PKEY_get_raw_public_key(const EVP_PKEY* pkey, unsigned char* pub, size_t* len);    
extern "C" int __real_EVP_PKEY_get_raw_private_key(const EVP_PKEY* pkey, unsigned char* priv, size_t* len);    

extern "C" int __wrap_EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX* ctx, const unsigned char* key, int keylen)    
{
    if (g_fail_hkdf_set_key.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen);    
}

extern "C" int __wrap_EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* salt,
                                                  int saltlen)    
{
    if (g_fail_hkdf_set_salt.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen);    
}

extern "C" int __wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)    
{
    if (type == EVP_CTRL_GCM_SET_TAG && g_fail_set_gcm_tag.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    if (type == EVP_CTRL_GCM_GET_TAG && g_fail_get_gcm_tag.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);    
}

extern "C" EVP_PKEY* __wrap_X509_get_pubkey(X509* x)    
{
    if (g_fail_x509_get_pubkey.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_X509_get_pubkey(x);    
}

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)    
{
    if (g_fail_rand_bytes.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);    
}

extern "C" EVP_PKEY_CTX* __wrap_EVP_PKEY_CTX_new_id(int id, ENGINE* e)    
{
    if (id == EVP_PKEY_X25519 && g_fail_x25519_ctx_new_id.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_EVP_PKEY_CTX_new_id(id, e);    
}

extern "C" EVP_PKEY* __wrap_EVP_PKEY_new_raw_private_key(int type,
                                                         ENGINE* e,
                                                         const unsigned char* key,
                                                         size_t keylen)    
{
    if (type == EVP_PKEY_X25519 && g_fail_x25519_raw_private_key.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    if (type == EVP_PKEY_ED25519 && g_fail_ed25519_raw_private_key.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_EVP_PKEY_new_raw_private_key(type, e, key, keylen);    
}

extern "C" int __wrap_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx,
                                                  const unsigned char* info,
                                                  int infolen)    
{
    if (g_fail_hkdf_add_info.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);    
}

extern "C" EVP_MD_CTX* __wrap_EVP_MD_CTX_new()    
{
    if (g_fail_md_ctx_new.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_EVP_MD_CTX_new();    
}

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)    
{
    if (g_fail_pkey_derive.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);    
}

extern "C" int __wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx,
                                        unsigned char* out,
                                        int* outl,
                                        const unsigned char* in,
                                        int inl)    
{
    if (g_fail_encrypt_update.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_EncryptUpdate(ctx, out, outl, in, inl);    
}

extern "C" int __wrap_EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, unsigned char* outm, int* outl)    
{
    if (g_fail_encrypt_final.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_EncryptFinal_ex(ctx, outm, outl);    
}

extern "C" int __wrap_EVP_PKEY_get_raw_public_key(const EVP_PKEY* pkey, unsigned char* pub, size_t* len)    
{
    if (g_fail_x25519_get_raw_public_key.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_get_raw_public_key(pkey, pub, len);    
}

extern "C" int __wrap_EVP_PKEY_get_raw_private_key(const EVP_PKEY* pkey, unsigned char* priv, size_t* len)    
{
    if (g_fail_x25519_get_raw_private_key.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_get_raw_private_key(pkey, priv, len);    
}

TEST(CryptoUtilTest, HexConversion)
{
    const std::vector<uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    const std::string hex = crypto_util::bytes_to_hex(bytes);
    EXPECT_EQ(hex, "deadbeef");

    const std::vector<uint8_t> back = crypto_util::hex_to_bytes(hex);
    EXPECT_EQ(back, bytes);

    EXPECT_EQ(crypto_util::bytes_to_hex({}), "");
    EXPECT_EQ(crypto_util::hex_to_bytes(""), std::vector<uint8_t>{});
}

TEST(CryptoUtilTest, Base64UrlDecode)
{
    std::vector<uint8_t> out;
    EXPECT_TRUE(crypto_util::base64_url_decode("", out));
    EXPECT_TRUE(out.empty());

    EXPECT_TRUE(crypto_util::base64_url_decode("Zg", out));
    EXPECT_EQ(out, std::vector<uint8_t>({'f'}));

    EXPECT_TRUE(crypto_util::base64_url_decode("aGVsbG8", out));
    EXPECT_EQ(out, std::vector<uint8_t>({'h', 'e', 'l', 'l', 'o'}));

    EXPECT_TRUE(crypto_util::base64_url_decode("_w", out));
    EXPECT_EQ(out, std::vector<uint8_t>({0xff}));

    EXPECT_TRUE(crypto_util::base64_url_decode("-w", out));
    EXPECT_EQ(out, std::vector<uint8_t>({0xfb}));

    EXPECT_FALSE(crypto_util::base64_url_decode("Zg@", out));
}

TEST(CryptoUtilTest, HKDFRFC5869Test1)
{
    const std::vector<uint8_t> ikm(22, 0x0b);
    const std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    const size_t l_val = 42;

    const auto prk = crypto_util::hkdf_extract(salt, ikm, EVP_sha256());
    ASSERT_TRUE(prk.has_value());

    const std::vector<uint8_t> expected_prk = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                                               0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    EXPECT_EQ(*prk, expected_prk);

    const auto okm = crypto_util::hkdf_expand(*prk, info, l_val, EVP_sha256());
    ASSERT_TRUE(okm.has_value());

    const std::vector<uint8_t> expected_okm = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                                               0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                                               0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    EXPECT_EQ(*okm, expected_okm);
}

TEST(CryptoUtilTest, AEADAESGCMRoundTrip)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());
    ASSERT_FALSE(ciphertext->empty());

    EXPECT_EQ(ciphertext->size(), plaintext.size() + 16);

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, *ciphertext, aad);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST(CryptoUtilTest, AEADDecryptFailBadTag)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};

    auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());

    ciphertext->back() ^= 0xFF;

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, *ciphertext, aad);

    EXPECT_FALSE(decrypted.has_value());
}

TEST(CryptoUtilTest, X25519KeyExchange)
{
    uint8_t alice_pub[32];
    uint8_t alice_priv[32];
    uint8_t bob_pub[32];
    uint8_t bob_priv[32];

    ASSERT_TRUE(crypto_util::generate_x25519_keypair(alice_pub, alice_priv));
    ASSERT_TRUE(crypto_util::generate_x25519_keypair(bob_pub, bob_priv));

    const std::vector<uint8_t> v_alice_priv(alice_priv, alice_priv + 32);
    const std::vector<uint8_t> v_alice_pub(alice_pub, alice_pub + 32);
    const std::vector<uint8_t> v_bob_priv(bob_priv, bob_priv + 32);
    const std::vector<uint8_t> v_bob_pub(bob_pub, bob_pub + 32);

    const auto alice_shared = crypto_util::x25519_derive(v_alice_priv, v_bob_pub);
    ASSERT_TRUE(alice_shared.has_value());

    const auto bob_shared = crypto_util::x25519_derive(v_bob_priv, v_alice_pub);
    ASSERT_TRUE(bob_shared.has_value());

    ASSERT_FALSE(alice_shared->empty());
    EXPECT_EQ(*alice_shared, *bob_shared);
}

TEST(CryptoUtilTest, AEADDecryptFailBadNonce)
{
    const std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());

    nonce[0] ^= 0x01;
    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, *ciphertext, aad);
    EXPECT_FALSE(decrypted.has_value());
}

TEST(CryptoUtilTest, AEADDecryptFailBadAAD)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0xAA, 0xBB};
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());

    aad[0] ^= 0x01;
    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, *ciphertext, aad);
    EXPECT_FALSE(decrypted.has_value());
}

TEST(CryptoUtilTest, HKDFEmptySalt)
{
    const std::vector<uint8_t> ikm(22, 0x0b);
    const std::vector<uint8_t> salt;
    const auto prk = crypto_util::hkdf_extract(salt, ikm, EVP_sha256());
    ASSERT_TRUE(prk.has_value());
    ASSERT_FALSE(prk->empty());
}

TEST(CryptoUtilTest, InvalidKeyLength)
{
    const std::vector<uint8_t> short_key(16, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad;
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), short_key, nonce, plaintext, aad);

    EXPECT_FALSE(ciphertext.has_value());
}

TEST(CryptoUtilTest, ZeroLengthPlaintext)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext;
    const std::vector<uint8_t> aad;
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());

    EXPECT_EQ(ciphertext->size(), 16);

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, *ciphertext, aad);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_TRUE(decrypted->empty());
}

TEST(CryptoUtilTest, ExtractPublicKey)
{
    uint8_t pub[32];
    uint8_t priv[32];
    ASSERT_TRUE(crypto_util::generate_x25519_keypair(pub, priv));
    const std::vector<uint8_t> v_priv(priv, priv + 32);
    const std::vector<uint8_t> v_pub(pub, pub + 32);

    const auto extracted_pub = crypto_util::extract_public_key(v_priv);
    ASSERT_TRUE(extracted_pub.has_value());
    EXPECT_EQ(*extracted_pub, v_pub);
}

TEST(CryptoUtilTest, GetRandomGrease)
{
    for (int i = 0; i < 100; ++i)
    {
        const uint16_t g = crypto_util::random_grease();
        EXPECT_NE(g, 0);
    }
}

TEST(CryptoUtilTest, HKDFExpandLabel)
{
    const std::vector<uint8_t> secret(32, 0x01);
    const std::vector<uint8_t> context = {0x0a, 0x0b};
    const std::string label = "test";
    const auto out = crypto_util::hkdf_expand_label(secret, label, context, 16, EVP_sha256());
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->size(), 16);
}

TEST(CryptoUtilTest, HKDFExpandLabelRejectsOversizedFields)
{
    const std::vector<std::uint8_t> secret(32, 0x01);
    const auto oversized_label =
        crypto_util::hkdf_expand_label(secret, std::string(300, 'a'), std::vector<std::uint8_t>{0x01}, 16, EVP_sha256());
    EXPECT_FALSE(oversized_label.has_value());
    EXPECT_EQ(oversized_label.error(), std::make_error_code(std::errc::invalid_argument));

    const auto oversized_context =
        crypto_util::hkdf_expand_label(secret, "ok", std::vector<std::uint8_t>(300, 0x02), 16, EVP_sha256());
    EXPECT_FALSE(oversized_context.has_value());
    EXPECT_EQ(oversized_context.error(), std::make_error_code(std::errc::invalid_argument));

    const auto oversized_length = crypto_util::hkdf_expand_label(secret, "ok", std::vector<std::uint8_t>{0x01}, 70000, EVP_sha256());
    EXPECT_FALSE(oversized_length.has_value());
    EXPECT_EQ(oversized_length.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(CryptoUtilTest, InvalidInputs)
{
    auto result1 = crypto_util::extract_public_key(std::vector<uint8_t>(31));
    EXPECT_FALSE(result1.has_value());

    auto result2 = crypto_util::x25519_derive(std::vector<uint8_t>(32), std::vector<uint8_t>(31));
    EXPECT_FALSE(result2.has_value());

    const std::vector<uint8_t> key(32, 0);
    const std::vector<uint8_t> nonce(12, 0);
    auto result3 = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, std::vector<uint8_t>(15), {});
    EXPECT_FALSE(result3.has_value());

    const auto invalid_hex = crypto_util::hex_to_bytes("invalid hex");
    EXPECT_TRUE(invalid_hex.empty());
}

TEST(CryptoUtilTest, ED25519PublicKey)
{
    const std::vector<uint8_t> priv(32, 0x42);
    const auto pub = crypto_util::extract_ed25519_public_key(priv);
    ASSERT_TRUE(pub.has_value());
    EXPECT_EQ(pub->size(), 32);

    auto result = crypto_util::extract_ed25519_public_key(std::vector<uint8_t>(31));
    EXPECT_FALSE(result.has_value());
}

TEST(CryptoUtilTest, AEADAppendAndBuffer)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    const std::vector<uint8_t> aad = {0xAA};
    const reality::cipher_context ctx;
    std::vector<uint8_t> ciphertext;
    auto enc_result = crypto_util::aead_encrypt_append(ctx, EVP_aes_256_gcm(), key, nonce, plaintext, aad, ciphertext);
    ASSERT_TRUE(enc_result.has_value());
    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16);

    std::vector<uint8_t> decrypted(plaintext.size());
    const auto n = crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, ciphertext, aad, decrypted);
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(*n, plaintext.size());
    EXPECT_EQ(decrypted, plaintext);

    std::vector<uint8_t> small_buffer(plaintext.size() - 1);
    auto small_result = crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, ciphertext, aad, small_buffer);
    EXPECT_FALSE(small_result.has_value());
    EXPECT_EQ(small_result.error(), std::make_error_code(std::errc::no_buffer_space));
}

TEST(CryptoUtilTest, TLS13SignatureVerification)
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    const std::vector<uint8_t> transcript_hash(32, 0x55);
    std::vector<uint8_t> to_sign(64, 0x20);
    const std::string context_str = "TLS 1.3, server CertificateVerify";
    to_sign.insert(to_sign.end(), context_str.begin(), context_str.end());
    to_sign.push_back(0x00);
    to_sign.insert(to_sign.end(), transcript_hash.begin(), transcript_hash.end());

    size_t sig_len = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, pkey);
    EVP_DigestSign(mctx, nullptr, &sig_len, to_sign.data(), to_sign.size());
    std::vector<uint8_t> signature(sig_len);
    EVP_DigestSign(mctx, signature.data(), &sig_len, to_sign.data(), to_sign.size());
    EVP_MD_CTX_free(mctx);

    auto verify_result = crypto_util::verify_tls13_signature(pkey, transcript_hash, signature);
    EXPECT_TRUE(verify_result.has_value());

    signature[0] ^= 0xFF;
    verify_result = crypto_util::verify_tls13_signature(pkey, transcript_hash, signature);
    EXPECT_FALSE(verify_result.has_value());

    EVP_PKEY_free(pkey);
}

TEST(CryptoUtilTest, ExtractPubkeyFromCertInvalid)
{
    auto pkey = crypto_util::extract_pubkey_from_cert({0x01, 0x02, 0x03});
    EXPECT_FALSE(pkey.has_value());
}

TEST(CryptoUtilTest, ExtractPubkeyFromCertValid)
{
    const char* gen_cmd = "openssl req -x509 -newkey rsa:2048 -keyout key_tmp.pem -out cert_tmp.pem -days 1 -nodes -subj '/CN=test' 2>/dev/null";
    const char* der_cmd = "openssl x509 -in cert_tmp.pem -outform DER -out cert_tmp.der";

    if (std::system(gen_cmd) == 0 && std::system(der_cmd) == 0)
    {
        std::ifstream file("cert_tmp.der", std::ios::binary);
        std::vector<uint8_t> const cert_der((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (!cert_der.empty())
        {
            auto pkey = crypto_util::extract_pubkey_from_cert(cert_der);
            EXPECT_TRUE(pkey.has_value());
            EXPECT_NE(pkey->get(), nullptr);
        }
    }
    (void)std::system("rm -f key_tmp.pem cert_tmp.pem cert_tmp.der");
}

TEST(CryptoUtilTest, AEADInvalidArguments)
{
    const std::vector<uint8_t> key(32, 0);
    const std::vector<uint8_t> nonce(12, 0);

    auto r1 = crypto_util::aead_decrypt(EVP_aes_256_gcm(), {}, nonce, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {});
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), std::make_error_code(std::errc::invalid_argument));

    auto r2 = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, {}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {});
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), std::make_error_code(std::errc::invalid_argument));

    auto r3 = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, std::vector<uint8_t>(11, 0), {1}, {});
    EXPECT_FALSE(r3.has_value());
    EXPECT_EQ(r3.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(CryptoUtilTest, AEADNullCipherRejected)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);

    const auto enc = crypto_util::aead_encrypt(nullptr, key, nonce, std::vector<uint8_t>{0x01}, {});
    EXPECT_FALSE(enc.has_value());
    EXPECT_EQ(enc.error(), std::make_error_code(std::errc::invalid_argument));

    const auto dec = crypto_util::aead_decrypt(nullptr, key, nonce, std::vector<uint8_t>(17, 0x00), {});
    EXPECT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error(), std::make_error_code(std::errc::invalid_argument));
}

TEST(CryptoUtilTest, HKDFInvalidArguments)
{
    const std::vector<uint8_t> salt(1, 0x01);
    const auto prk = crypto_util::hkdf_extract(salt, {0x02}, EVP_sha256());
    ASSERT_TRUE(prk.has_value());

    auto r1 = crypto_util::hkdf_extract(salt, {}, EVP_sha256());
    EXPECT_FALSE(r1.has_value());
    EXPECT_EQ(r1.error(), std::make_error_code(std::errc::invalid_argument));

    auto r2 = crypto_util::hkdf_expand({}, {0x01}, 16, EVP_sha256());
    EXPECT_FALSE(r2.has_value());
    EXPECT_EQ(r2.error(), std::make_error_code(std::errc::invalid_argument));

    const auto okm_empty = crypto_util::hkdf_expand(*prk, {0x01}, 0, EVP_sha256());
    ASSERT_TRUE(okm_empty.has_value());
    EXPECT_TRUE(okm_empty->empty());
}

TEST(CryptoUtilTest, NonGCMCipherContext)
{
    const std::vector<uint8_t> key(16, 0x11);
    const std::vector<uint8_t> iv(16, 0x22);
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};

    const reality::cipher_context ctx;

    ASSERT_TRUE(ctx.init(true, EVP_aes_128_cbc(), key.data(), iv.data(), 16));

    std::vector<uint8_t> ciphertext(32);
    int out_len = 0;
    ASSERT_EQ(EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())), 1);

    int final_len = 0;
    ASSERT_EQ(EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len), 1);
    ASSERT_GE(out_len, 0);
    ASSERT_GE(final_len, 0);
    ciphertext.resize(static_cast<std::size_t>(out_len) + static_cast<std::size_t>(final_len));

    const reality::cipher_context ctx_dec;
    ASSERT_TRUE(ctx_dec.init(false, EVP_aes_128_cbc(), key.data(), iv.data(), 16));

    std::vector<uint8_t> decrypted(32);
    ASSERT_EQ(EVP_DecryptUpdate(ctx_dec.get(), decrypted.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())), 1);
    ASSERT_EQ(EVP_DecryptFinal_ex(ctx_dec.get(), decrypted.data() + out_len, &final_len), 1);
    ASSERT_GE(out_len, 0);
    ASSERT_GE(final_len, 0);
    decrypted.resize(static_cast<std::size_t>(out_len) + static_cast<std::size_t>(final_len));

    EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoUtilTest, CipherContextMovedFromBecomesInvalid)
{
    reality::cipher_context source_ctx;
    reality::cipher_context const moved_ctx(std::move(source_ctx));
    EXPECT_TRUE(moved_ctx.valid());

    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> iv(12, 0x22);
    reality::cipher_context const invalid_ctx(nullptr);
    EXPECT_FALSE(invalid_ctx.valid());
    EXPECT_FALSE(invalid_ctx.init(true, EVP_aes_256_gcm(), key.data(), iv.data(), iv.size()));
}

TEST(CryptoUtilTest, CipherContextRejectsInvalidGcmIvLength)
{
    reality::cipher_context const ctx;
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> iv(12, 0x22);

    const auto huge_iv_len = std::numeric_limits<std::size_t>::max();
    EXPECT_FALSE(ctx.init(true, EVP_aes_256_gcm(), key.data(), iv.data(), huge_iv_len));
}

TEST(CryptoUtilTest, HKDFNullDigestFails)
{
    const auto prk = crypto_util::hkdf_extract({0x01}, {0x02}, nullptr);
    EXPECT_FALSE(prk.has_value());

    const auto okm = crypto_util::hkdf_expand({0x01}, {0x02}, 16, nullptr);
    EXPECT_FALSE(okm.has_value());
}

TEST(CryptoUtilTest, AEADDecryptLowLevelFailureBranches)
{
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> nonce(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, {});
    ASSERT_TRUE(ciphertext.has_value());

    reality::cipher_context const invalid_ctx(nullptr);
    ASSERT_FALSE(invalid_ctx.valid());
    std::vector<std::uint8_t> out(plaintext.size());
    const auto n1 = crypto_util::aead_decrypt(invalid_ctx, EVP_aes_256_gcm(), key, nonce, *ciphertext, {}, out);
    EXPECT_FALSE(n1.has_value());
    EXPECT_EQ(n1.error(), std::make_error_code(std::errc::protocol_error));

    reality::cipher_context const cbc_ctx;
    const std::vector<std::uint8_t> long_nonce(16, 0x33);
    const std::vector<std::uint8_t> fake_ciphertext(32, 0x44);
    out.assign(32, 0);
    const auto n2 = crypto_util::aead_decrypt(
        cbc_ctx, EVP_aes_256_cbc(), key, std::span<const std::uint8_t>(long_nonce.data(), 12), fake_ciphertext, std::vector<std::uint8_t>{0xaa}, out);
    EXPECT_FALSE(n2.has_value());
    EXPECT_EQ(n2.error(), std::make_error_code(std::errc::bad_message));
}

TEST(CryptoUtilTest, AEADEncryptAppendMovedFromContextFails)
{
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> nonce(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};

    reality::cipher_context const invalid_ctx(nullptr);
    ASSERT_FALSE(invalid_ctx.valid());

    std::vector<std::uint8_t> out;
    auto enc_result = crypto_util::aead_encrypt_append(invalid_ctx, EVP_aes_256_gcm(), key, nonce, plaintext, {}, out);
    EXPECT_FALSE(enc_result.has_value());
    EXPECT_EQ(enc_result.error(), std::make_error_code(std::errc::protocol_error));
    EXPECT_TRUE(out.empty());
}

TEST(CryptoUtilTest, AEADEncryptAppendLowLevelFailureBranches)
{
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> nonce(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x01, 0x02, 0x03};
    const reality::cipher_context ctx;

    std::vector<std::uint8_t> out = {0xAA};
    fail_next_encrypt_update();
    auto result = crypto_util::aead_encrypt_append(ctx, EVP_aes_256_gcm(), key, nonce, plaintext, {}, out);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::protocol_error));
    EXPECT_EQ(out, std::vector<std::uint8_t>({0xAA}));

    out = {0xBB};
    fail_next_encrypt_final();
    result = crypto_util::aead_encrypt_append(ctx, EVP_aes_256_gcm(), key, nonce, plaintext, {}, out);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::protocol_error));
    EXPECT_EQ(out, std::vector<std::uint8_t>({0xBB}));

    out = {0xCC};
    fail_next_get_gcm_tag();
    result = crypto_util::aead_encrypt_append(ctx, EVP_aes_256_gcm(), key, nonce, plaintext, {}, out);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::protocol_error));
    EXPECT_EQ(out, std::vector<std::uint8_t>({0xCC}));
}

TEST(CryptoUtilTest, VerifySignatureNullKeyFails)
{
    const auto result = crypto_util::verify_tls13_signature(nullptr, std::vector<std::uint8_t>(32, 0x55), std::vector<std::uint8_t>(64, 0x11));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::protocol_error));
}

TEST(CryptoUtilTest, AEADDecryptLowLevelRejectsTooShortCiphertext)
{
    reality::cipher_context const ctx;
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> nonce(12, 0x22);
    std::vector<std::uint8_t> out(16, 0);

    const auto n = crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, std::vector<std::uint8_t>(15, 0), {}, out);
    EXPECT_FALSE(n.has_value());
    EXPECT_EQ(n.error(), std::make_error_code(std::errc::message_size));
}

TEST(CryptoUtilTest, HKDFExpandOversizedOutputRejected)
{
    const auto okm = crypto_util::hkdf_expand(std::vector<std::uint8_t>(32, 0x01), std::vector<std::uint8_t>{0x02}, 9000, EVP_sha256());
    EXPECT_FALSE(okm.has_value());
}

TEST(CryptoUtilTest, ExtractPubkeyFromCertWithoutPublicKeyInfo)
{
    const auto der = build_self_signed_cert_der();
    ASSERT_FALSE(der.empty());

    fail_next_x509_get_pubkey();
    auto pub = crypto_util::extract_pubkey_from_cert(der);
    EXPECT_FALSE(pub.has_value());
}

TEST(CryptoUtilTest, HKDFExtractSetSaltFailureBranch)
{
    fail_next_hkdf_set_salt();
    const auto prk = crypto_util::hkdf_extract(std::vector<std::uint8_t>{0x01}, std::vector<std::uint8_t>{0x02}, EVP_sha256());
    EXPECT_FALSE(prk.has_value());
    EXPECT_EQ(prk.error(), std::make_error_code(std::errc::protocol_error));
}

TEST(CryptoUtilTest, HKDFExpandSetKeyFailureBranch)
{
    fail_next_hkdf_set_key();
    const auto okm = crypto_util::hkdf_expand(std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>{0x01}, 16, EVP_sha256());
    EXPECT_FALSE(okm.has_value());
    EXPECT_EQ(okm.error(), std::make_error_code(std::errc::protocol_error));
}

TEST(CryptoUtilTest, AEADDecryptSetTagFailureBranch)
{
    const std::vector<std::uint8_t> key(32, 0x11);
    const std::vector<std::uint8_t> nonce(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x41, 0x42, 0x43, 0x44};
    const std::vector<std::uint8_t> aad = {0x01, 0x02};

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad);
    ASSERT_TRUE(ciphertext.has_value());
    ASSERT_EQ(ciphertext->size(), plaintext.size() + 16);

    reality::cipher_context const ctx;
    std::vector<std::uint8_t> out(plaintext.size(), 0);
    fail_next_set_gcm_tag();
    const auto n = crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, *ciphertext, aad, out);
    EXPECT_FALSE(n.has_value());
    EXPECT_EQ(n.error(), std::make_error_code(std::errc::bad_message));
}

TEST(CryptoUtilTest, RandomGreaseFallsBackWhenRandFails)
{
    fail_next_rand_bytes();
    EXPECT_EQ(crypto_util::random_grease(), 0x0a0a);
}

TEST(CryptoUtilTest, GenerateX25519KeypairFailureCleansesOutput)
{
    std::uint8_t pub[32];
    std::uint8_t priv[32];
    std::fill_n(pub, 32, 0xAA);
    std::fill_n(priv, 32, 0xBB);

    fail_next_x25519_ctx_new_id();
    EXPECT_FALSE(crypto_util::generate_x25519_keypair(pub, priv));
    for (std::size_t i = 0; i < 32; ++i)
    {
        EXPECT_EQ(pub[i], 0U);
        EXPECT_EQ(priv[i], 0U);
    }
}

TEST(CryptoUtilTest, GenerateX25519KeypairRawExportFailureCleansesOutput)
{
    std::uint8_t pub[32];
    std::uint8_t priv[32];
    std::fill_n(pub, 32, 0xAA);
    std::fill_n(priv, 32, 0xBB);

    fail_next_x25519_get_raw_public_key();
    EXPECT_FALSE(crypto_util::generate_x25519_keypair(pub, priv));
    for (std::size_t i = 0; i < 32; ++i)
    {
        EXPECT_EQ(pub[i], 0U);
        EXPECT_EQ(priv[i], 0U);
    }

    std::fill_n(pub, 32, 0xAA);
    std::fill_n(priv, 32, 0xBB);
    fail_next_x25519_get_raw_private_key();
    EXPECT_FALSE(crypto_util::generate_x25519_keypair(pub, priv));
    for (std::size_t i = 0; i < 32; ++i)
    {
        EXPECT_EQ(pub[i], 0U);
        EXPECT_EQ(priv[i], 0U);
    }
}

TEST(CryptoUtilTest, ExtractPublicKeyLowLevelPrivateKeyCreationFailure)
{
    const std::vector<std::uint8_t> raw_private(32, 0x11);

    fail_next_x25519_raw_private_key();
    const auto x25519_pub = crypto_util::extract_public_key(raw_private);
    EXPECT_FALSE(x25519_pub.has_value());

    fail_next_ed25519_raw_private_key();
    const auto ed25519_pub = crypto_util::extract_ed25519_public_key(raw_private);
    EXPECT_FALSE(ed25519_pub.has_value());
}

TEST(CryptoUtilTest, X25519DerivePropagatesKeyObjectCreationFailure)
{
    const std::vector<std::uint8_t> private_key(32, 0x21);
    const std::vector<std::uint8_t> peer_public_key(32, 0x42);

    fail_next_x25519_raw_private_key();
    const auto shared = crypto_util::x25519_derive(private_key, peer_public_key);
    EXPECT_FALSE(shared.has_value());
}

TEST(CryptoUtilTest, HkdfLowLevelFailureBranches)
{
    fail_next_pkey_derive();
    const auto prk = crypto_util::hkdf_extract(std::vector<std::uint8_t>{0x01}, std::vector<std::uint8_t>{0x02}, EVP_sha256());
    EXPECT_FALSE(prk.has_value());
    EXPECT_EQ(prk.error(), std::make_error_code(std::errc::protocol_error));

    fail_next_hkdf_add_info();
    const auto okm = crypto_util::hkdf_expand(std::vector<std::uint8_t>(32, 0x03), std::vector<std::uint8_t>{0x04}, 16, EVP_sha256());
    EXPECT_FALSE(okm.has_value());
    EXPECT_EQ(okm.error(), std::make_error_code(std::errc::protocol_error));
}

TEST(CryptoUtilTest, VerifyTls13SignatureHandlesMdCtxCreationFailure)
{
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    ASSERT_NE(keygen_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_keygen_init(keygen_ctx), 1);
    ASSERT_EQ(EVP_PKEY_keygen(keygen_ctx, &pkey), 1);
    EVP_PKEY_CTX_free(keygen_ctx);
    ASSERT_NE(pkey, nullptr);

    fail_next_md_ctx_new();
    const auto result = crypto_util::verify_tls13_signature(pkey, std::vector<std::uint8_t>(32, 0x77), std::vector<std::uint8_t>(64, 0x88));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_enough_memory));

    EVP_PKEY_free(pkey);
}
