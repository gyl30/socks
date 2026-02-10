#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <system_error>

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "crypto_util.h"

using reality::crypto_util;

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

    std::error_code ec;
    const auto prk = crypto_util::hkdf_extract(salt, ikm, EVP_sha256(), ec);
    ASSERT_FALSE(ec);

    const std::vector<uint8_t> expected_prk = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                                               0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    EXPECT_EQ(prk, expected_prk);

    const auto okm = crypto_util::hkdf_expand(prk, info, l_val, EVP_sha256(), ec);
    ASSERT_FALSE(ec);

    const std::vector<uint8_t> expected_okm = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                                               0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                                               0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};
    EXPECT_EQ(okm, expected_okm);
}

TEST(CryptoUtilTest, AEADAESGCMRoundTrip)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};

    std::error_code ec;
    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(ciphertext.empty());

    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16);

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(decrypted, plaintext);
}

TEST(CryptoUtilTest, AEADDecryptFailBadTag)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};

    std::error_code ec;
    auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);

    ciphertext.back() ^= 0xFF;

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);

    EXPECT_TRUE(ec);
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

    std::error_code ec;

    const auto alice_shared = crypto_util::x25519_derive(v_alice_priv, v_bob_pub, ec);
    ASSERT_FALSE(ec);

    const auto bob_shared = crypto_util::x25519_derive(v_bob_priv, v_alice_pub, ec);
    ASSERT_FALSE(ec);

    ASSERT_FALSE(alice_shared.empty());
    EXPECT_EQ(alice_shared, bob_shared);
}

TEST(CryptoUtilTest, AEADDecryptFailBadNonce)
{
    const std::vector<uint8_t> key(32, 0x11);
    std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad = {0xAA, 0xBB};
    std::error_code ec;

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);

    nonce[0] ^= 0x01;
    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);
    EXPECT_TRUE(ec);
}

TEST(CryptoUtilTest, AEADDecryptFailBadAAD)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::vector<uint8_t> aad = {0xAA, 0xBB};
    std::error_code ec;

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);

    aad[0] ^= 0x01;
    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);
    EXPECT_TRUE(ec);
}

TEST(CryptoUtilTest, HKDFEmptySalt)
{
    const std::vector<uint8_t> ikm(22, 0x0b);
    const std::vector<uint8_t> salt;
    std::error_code ec;
    const auto prk = crypto_util::hkdf_extract(salt, ikm, EVP_sha256(), ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(prk.empty());
}

TEST(CryptoUtilTest, InvalidKeyLength)
{
    const std::vector<uint8_t> short_key(16, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    const std::vector<uint8_t> aad;
    std::error_code ec;

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), short_key, nonce, plaintext, aad, ec);

    EXPECT_TRUE(ec);
}

TEST(CryptoUtilTest, ZeroLengthPlaintext)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext;
    const std::vector<uint8_t> aad;
    std::error_code ec;

    const auto ciphertext = crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, nonce, plaintext, aad, ec);
    ASSERT_FALSE(ec);

    EXPECT_EQ(ciphertext.size(), 16);

    const auto decrypted = crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, ciphertext, aad, ec);
    ASSERT_FALSE(ec);
    EXPECT_TRUE(decrypted.empty());
}

TEST(CryptoUtilTest, ExtractPublicKey)
{
    uint8_t pub[32];
    uint8_t priv[32];
    ASSERT_TRUE(crypto_util::generate_x25519_keypair(pub, priv));
    const std::vector<uint8_t> v_priv(priv, priv + 32);
    const std::vector<uint8_t> v_pub(pub, pub + 32);

    std::error_code ec;
    const auto extracted_pub = crypto_util::extract_public_key(v_priv, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(extracted_pub, v_pub);
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
    std::error_code ec;

    const auto out = crypto_util::hkdf_expand_label(secret, label, context, 16, EVP_sha256(), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(out.size(), 16);
}

TEST(CryptoUtilTest, InvalidInputs)
{
    std::error_code ec;
    (void)crypto_util::extract_public_key(std::vector<uint8_t>(31), ec);
    EXPECT_TRUE(ec);

    (void)crypto_util::x25519_derive(std::vector<uint8_t>(32), std::vector<uint8_t>(31), ec);
    EXPECT_TRUE(ec);

    const std::vector<uint8_t> key(32, 0);
    const std::vector<uint8_t> nonce(12, 0);
    (void)crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, nonce, std::vector<uint8_t>(15), {}, ec);
    EXPECT_TRUE(ec);

    const auto invalid_hex = crypto_util::hex_to_bytes("invalid hex");
    EXPECT_TRUE(invalid_hex.empty());
}

TEST(CryptoUtilTest, ED25519PublicKey)
{
    const std::vector<uint8_t> priv(32, 0x42);
    std::error_code ec;
    const auto pub = crypto_util::extract_ed25519_public_key(priv, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(pub.size(), 32);

    (void)crypto_util::extract_ed25519_public_key(std::vector<uint8_t>(31), ec);
    EXPECT_TRUE(ec);
}

TEST(CryptoUtilTest, AEADAppendAndBuffer)
{
    const std::vector<uint8_t> key(32, 0x11);
    const std::vector<uint8_t> nonce(12, 0x22);
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04};
    const std::vector<uint8_t> aad = {0xAA};
    std::error_code ec;

    const reality::cipher_context ctx;
    std::vector<uint8_t> ciphertext;
    crypto_util::aead_encrypt_append(ctx, EVP_aes_256_gcm(), key, nonce, plaintext, aad, ciphertext, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16);

    std::vector<uint8_t> decrypted(plaintext.size());
    const size_t n = crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, ciphertext, aad, decrypted, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(n, plaintext.size());
    EXPECT_EQ(decrypted, plaintext);

    std::vector<uint8_t> small_buffer(plaintext.size() - 1);
    (void)crypto_util::aead_decrypt(ctx, EVP_aes_256_gcm(), key, nonce, ciphertext, aad, small_buffer, ec);
    EXPECT_EQ(ec, std::errc::no_buffer_space);
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

    std::error_code ec;
    bool ok = crypto_util::verify_tls13_signature(pkey, transcript_hash, signature, ec);
    EXPECT_TRUE(ok);
    EXPECT_FALSE(ec);

    signature[0] ^= 0xFF;
    ok = crypto_util::verify_tls13_signature(pkey, transcript_hash, signature, ec);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(ec);

    EVP_PKEY_free(pkey);
}

TEST(CryptoUtilTest, ExtractPubkeyFromCertInvalid)
{
    std::error_code ec;
    auto pkey = crypto_util::extract_pubkey_from_cert({0x01, 0x02, 0x03}, ec);
    EXPECT_TRUE(ec);
    EXPECT_EQ(pkey.get(), nullptr);
}

TEST(CryptoUtilTest, ExtractPubkeyFromCertValid)
{
    const char* gen_cmd = "openssl req -x509 -newkey rsa:2048 -keyout key_tmp.pem -out cert_tmp.pem -days 1 -nodes -subj '/CN=test' 2>/dev/null";
    const char* der_cmd = "openssl x509 -in cert_tmp.pem -outform DER -out cert_tmp.der";

    if (std::system(gen_cmd) == 0 && std::system(der_cmd) == 0)
    {
        std::ifstream file("cert_tmp.der", std::ios::binary);
        std::vector<uint8_t> cert_der((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (!cert_der.empty())
        {
            std::error_code ec;
            auto pkey = crypto_util::extract_pubkey_from_cert(cert_der, ec);
            EXPECT_FALSE(ec);
            EXPECT_NE(pkey.get(), nullptr);
        }
    }
    (void)std::system("rm -f key_tmp.pem cert_tmp.pem cert_tmp.der");
}

TEST(CryptoUtilTest, AEADInvalidArguments)
{
    std::error_code ec;
    const std::vector<uint8_t> key(32, 0);
    const std::vector<uint8_t> nonce(12, 0);

    (void)crypto_util::aead_decrypt(EVP_aes_256_gcm(), {}, nonce, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {}, ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);

    (void)crypto_util::aead_decrypt(EVP_aes_256_gcm(), key, {}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {}, ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);

    (void)crypto_util::aead_encrypt(EVP_aes_256_gcm(), key, std::vector<uint8_t>(11, 0), {1}, {}, ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);
}

TEST(CryptoUtilTest, HKDFInvalidInputs)
{
    std::error_code ec;
    const std::vector<uint8_t> ikm(22, 0x0b);
    const std::vector<uint8_t> salt = {0x00, 0x01};
    const std::vector<uint8_t> prk(32, 0x01);

    (void)crypto_util::hkdf_extract(salt, {}, EVP_sha256(), ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);

    (void)crypto_util::hkdf_expand({}, {0x01}, 16, EVP_sha256(), ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);

    const auto okm_empty = crypto_util::hkdf_expand(prk, {0x01}, 0, EVP_sha256(), ec);
    EXPECT_FALSE(ec);
    EXPECT_TRUE(okm_empty.empty());
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
    ciphertext.resize(out_len + final_len);

    const reality::cipher_context ctx_dec;
    ASSERT_TRUE(ctx_dec.init(false, EVP_aes_128_cbc(), key.data(), iv.data(), 16));

    std::vector<uint8_t> decrypted(32);
    ASSERT_EQ(EVP_DecryptUpdate(ctx_dec.get(), decrypted.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())), 1);
    ASSERT_EQ(EVP_DecryptFinal_ex(ctx_dec.get(), decrypted.data() + out_len, &final_len), 1);
    decrypted.resize(out_len + final_len);

    EXPECT_EQ(decrypted, plaintext);
}
