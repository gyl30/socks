#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include "tls_record_layer.h"
#include "reality_core.h"

using namespace reality;

class TLSRecordLayerTest : public ::testing::Test {
protected:
    void SetUp() override {
        key.resize(32, 0x11);
        iv.resize(12, 0x22);
    }

    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
};

TEST_F(TLSRecordLayerTest, RoundTrip) {
    std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    uint64_t seq = 1;
    uint8_t type = 0x17; // Application Data
    std::error_code ec;

    auto encrypted = tls_record_layer::encrypt_record(cipher, key, iv, seq, plaintext, type, ec);
    ASSERT_FALSE(ec);
    ASSERT_GT(encrypted.size(), plaintext.size() + 16); // Header + Tag + Padding + etc

    uint8_t out_type = 0;
    auto decrypted = tls_record_layer::decrypt_record(cipher, key, iv, seq, encrypted, out_type, ec);
    
    ASSERT_FALSE(ec);
    EXPECT_EQ(out_type, type);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(TLSRecordLayerTest, SequenceNumberMatters) {
    std::vector<uint8_t> plaintext = {0x12, 0x34};
    std::error_code ec;
    
    auto enc1 = tls_record_layer::encrypt_record(cipher, key, iv, 100, plaintext, 0x17, ec);
    ASSERT_FALSE(ec);
    
    uint8_t out_type;
    // Decrypt with wrong sequence number
    auto dec = tls_record_layer::decrypt_record(cipher, key, iv, 101, enc1, out_type, ec);
    
    // Should fail (Bad Tag)
    EXPECT_TRUE(ec);
    EXPECT_TRUE(dec.empty());
}

TEST_F(TLSRecordLayerTest, TamperedCiphertext) {
    std::vector<uint8_t> plaintext = {0x00, 0x01};
    uint64_t seq = 50;
    std::error_code ec;
    
    auto enc = tls_record_layer::encrypt_record(cipher, key, iv, seq, plaintext, 0x17, ec);
    ASSERT_FALSE(ec);
    
    // Corrupt last byte (Tag)
    enc.back() ^= 0xFF;
    
    uint8_t out_type;
    auto dec = tls_record_layer::decrypt_record(cipher, key, iv, seq, enc, out_type, ec);
    
    EXPECT_TRUE(ec);
}

TEST_F(TLSRecordLayerTest, ShortMessage) {
    // Message too short to contain header + tag
    std::vector<uint8_t> short_msg(10, 0x00);
    uint8_t out_type;
    std::error_code ec;
    
    auto dec = tls_record_layer::decrypt_record(cipher, key, iv, 0, short_msg, out_type, ec);
    
    EXPECT_EQ(ec, std::errc::message_size);
}
