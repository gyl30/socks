#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include "crypto_util.h"

using namespace reality;

TEST(CryptoUtilTest, HexConversion)
{
    std::vector<uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    std::string hex = crypto_util::bytes_to_hex(bytes);
    EXPECT_EQ(hex, "deadbeef");

    std::vector<uint8_t> back = crypto_util::hex_to_bytes(hex);
    EXPECT_EQ(back, bytes);

    EXPECT_EQ(crypto_util::bytes_to_hex({}), "");
    EXPECT_EQ(crypto_util::hex_to_bytes(""), std::vector<uint8_t>{});
}

TEST(CryptoUtilTest, HKDF_RFC5869_Test1)
{
    std::vector<uint8_t> ikm(22, 0x0b);
    std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    size_t L = 42;

    std::error_code ec;
    auto prk = crypto_util::hkdf_extract(salt, ikm, EVP_sha256(), ec);
    ASSERT_FALSE(ec);

    std::vector<uint8_t> expected_prk = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                                         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    EXPECT_EQ(prk, expected_prk);

    auto okm = crypto_util::hkdf_expand(prk, info, L, EVP_sha256(), ec);
    ASSERT_FALSE(ec);

    std::vector<uint8_t> expected_okm = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                                         0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                                         0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    EXPECT_EQ(okm, expected_okm);
}

TEST(CryptoUtilTest, AEAD_AES_GCM_RoundTrip)
{
    std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> nonce(12, 0x22);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0xAA, 0xBB};

    std::error_code ec;
    auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(ciphertext.empty());

    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16);

    auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoUtilTest, AEAD_Decrypt_Fail_BadTag)
{
    std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> nonce(12, 0x22);
    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0xAA, 0xBB};

    std::error_code ec;
    auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);

    ciphertext.back() ^= 0xFF;

    auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);

    EXPECT_TRUE(ec);
}

TEST(CryptoUtilTest, X25519_KeyExchange)
{
    uint8_t alice_pub[32], alice_priv[32];
    uint8_t bob_pub[32], bob_priv[32];

    ASSERT_TRUE(crypto_util::generate_x25519_keypair(alice_pub, alice_priv));
    ASSERT_TRUE(crypto_util::generate_x25519_keypair(bob_pub, bob_priv));

    std::vector<uint8_t> v_alice_priv(alice_priv, alice_priv + 32);
    std::vector<uint8_t> v_alice_pub(alice_pub, alice_pub + 32);
    std::vector<uint8_t> v_bob_priv(bob_priv, bob_priv + 32);
    std::vector<uint8_t> v_bob_pub(bob_pub, bob_pub + 32);

    std::error_code ec;

    auto alice_shared = crypto_util::x25519_derive(v_alice_priv, v_bob_pub, ec);
    ASSERT_FALSE(ec);

    auto bob_shared = crypto_util::x25519_derive(v_bob_priv, v_alice_pub, ec);
    ASSERT_FALSE(ec);

    ASSERT_FALSE(alice_shared.empty());
    EXPECT_EQ(alice_shared, bob_shared);
}
