#include <vector>
#include <cstdint>
#include <system_error>

#include <openssl/evp.h>
#include <gtest/gtest.h>

#include "tls_record_layer.h"

using reality::tls_record_layer;

class TLSRecordLayerTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        key_.resize(32, 0x11);
        iv_.resize(12, 0x22);
    }

    const std::vector<uint8_t>& key() const { return key_; }
    const std::vector<uint8_t>& iv() const { return iv_; }
    const EVP_CIPHER* cipher() const { return cipher_; }

   private:
    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
    const EVP_CIPHER* cipher_ = EVP_aes_256_gcm();
};

TEST_F(TLSRecordLayerTest, RoundTrip)
{
    const std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint64_t seq = 1;
    const uint8_t type = 0x17;
    std::error_code ec;

    const auto encrypted = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, type, ec);
    ASSERT_FALSE(ec);
    ASSERT_GT(encrypted.size(), plaintext.size() + 16);

    uint8_t out_type = 0;
    const auto decrypted = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, encrypted, out_type, ec);

    ASSERT_FALSE(ec);
    EXPECT_EQ(out_type, type);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(TLSRecordLayerTest, SequenceNumberMatters)
{
    const std::vector<uint8_t> plaintext = {0x12, 0x34};
    std::error_code ec;

    const auto enc1 = tls_record_layer::encrypt_record(cipher(), key(), iv(), 100, plaintext, 0x17, ec);
    ASSERT_FALSE(ec);

    uint8_t out_type = 0;

    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), 101, enc1, out_type, ec);

    EXPECT_TRUE(ec);
    EXPECT_TRUE(dec.empty());
}

TEST_F(TLSRecordLayerTest, TamperedCiphertext)
{
    const std::vector<uint8_t> plaintext = {0x00, 0x01};
    const uint64_t seq = 50;
    std::error_code ec;

    auto enc = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, 0x17, ec);
    ASSERT_FALSE(ec);

    enc.back() ^= 0xFF;

    uint8_t out_type = 0;
    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, enc, out_type, ec);

    EXPECT_TRUE(ec);
}

TEST_F(TLSRecordLayerTest, DecryptAllZeros)
{
    // Record where the whole decrypted content is zeros
    // (This would be an invalid record in TLS 1.3 because it must end with a content type)
    std::vector<uint8_t> zeros(20, 0);
    const uint64_t seq = 0;
    std::error_code ec;

    // We manually encrypt it to bypass the padding logic in encrypt_record
    const std::vector<uint8_t> aad = {0x17, 0x03, 0x03, 0x00, static_cast<uint8_t>(zeros.size() + 16)};
    auto encrypted = reality::crypto_util::aead_encrypt(cipher(), key(), iv(), zeros, aad, ec);
    ASSERT_FALSE(ec);

    std::vector<uint8_t> record;
    record.insert(record.end(), aad.begin(), aad.end());
    record.insert(record.end(), encrypted.begin(), encrypted.end());

    uint8_t out_type = 0;
    (void)tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, record, out_type, ec);

    EXPECT_EQ(ec, std::errc::bad_message);
}

TEST_F(TLSRecordLayerTest, EncryptAppDataWithPadding)
{
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
    const uint64_t seq = 10;
    const uint8_t type = reality::kContentTypeApplicationData;
    std::error_code ec;

    const auto encrypted = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, type, ec);
    ASSERT_FALSE(ec);

    uint8_t out_type = 0;
    const auto decrypted = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, encrypted, out_type, ec);

    ASSERT_FALSE(ec);
    EXPECT_EQ(out_type, type);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(TLSRecordLayerTest, ShortMessage)
{
    const std::vector<uint8_t> short_msg(10, 0x00);
    uint8_t out_type = 0;
    std::error_code ec;

    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), 0, short_msg, out_type, ec);

    EXPECT_EQ(ec, std::errc::message_size);
}
