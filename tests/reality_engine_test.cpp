#include <span>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "reality_engine.h"
#include "tls_record_layer.h"

namespace mux
{

class RealityEngineTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        cipher_ = EVP_aes_128_gcm();

        read_key_.resize(16, 0x01);
        read_iv_.resize(12, 0x02);
        write_key_.resize(16, 0x03);
        write_iv_.resize(12, 0x04);
    }

    const EVP_CIPHER* cipher_ = nullptr;
    std::vector<std::uint8_t> read_key_;
    std::vector<std::uint8_t> read_iv_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_iv_;
};

TEST_F(RealityEngineTest, EncryptEmptyData)
{
    reality_engine engine(read_key_, read_iv_, write_key_, write_iv_, cipher_);

    std::error_code ec;
    auto result = engine.encrypt({}, ec);

    EXPECT_FALSE(ec);
    EXPECT_TRUE(result.empty());
}

TEST_F(RealityEngineTest, EncryptProducesOutput)
{
    reality_engine engine(read_key_, read_iv_, write_key_, write_iv_, cipher_);

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::error_code ec;
    auto result = engine.encrypt(plaintext, ec);

    EXPECT_FALSE(ec);
    EXPECT_FALSE(result.empty());

    EXPECT_GE(result.size(), plaintext.size() + 5 + 16 + 1);
}

TEST_F(RealityEngineTest, DecryptInsufficientData)
{
    reality_engine engine(read_key_, read_iv_, write_key_, write_iv_, cipher_);

    auto buf = engine.read_buffer(3);
    std::uint8_t small_data[] = {0x17, 0x03, 0x03};
    std::memcpy(buf.data(), small_data, 3);
    engine.commit_read(3);

    std::error_code ec;
    bool called = false;
    engine.process_available_records(ec, [&called](std::uint8_t, std::span<const std::uint8_t>) { called = true; });

    EXPECT_FALSE(ec);
    EXPECT_FALSE(called);
}

TEST_F(RealityEngineTest, EncryptDecryptRoundTrip)
{
    reality_engine encrypt_engine(write_key_, write_iv_, read_key_, read_iv_, cipher_);
    reality_engine decrypt_engine(read_key_, read_iv_, write_key_, write_iv_, cipher_);

    std::vector<std::uint8_t> plaintext = {'T', 'e', 's', 't', ' ', 'D', 'a', 't', 'a'};

    std::error_code ec;
    auto encrypted = encrypt_engine.encrypt(plaintext, ec);
    ASSERT_FALSE(ec);
    ASSERT_FALSE(encrypted.empty());

    auto buf = decrypt_engine.read_buffer(encrypted.size());
    std::memcpy(buf.data(), encrypted.data(), encrypted.size());
    decrypt_engine.commit_read(encrypted.size());

    std::vector<std::uint8_t> decrypted;
    decrypt_engine.process_available_records(ec,
                                             [&decrypted](std::uint8_t content_type, std::span<const std::uint8_t> data)
                                             {
                                                 EXPECT_EQ(content_type, reality::kContentTypeApplicationData);
                                                 decrypted.assign(data.begin(), data.end());
                                             });

    EXPECT_FALSE(ec);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(RealityEngineTest, MultipleEncryptions)
{
    reality_engine engine(read_key_, read_iv_, write_key_, write_iv_, cipher_);

    std::vector<std::uint8_t> data1 = {'A', 'B', 'C'};
    std::vector<std::uint8_t> data2 = {'D', 'E', 'F'};

    std::error_code ec;
    auto result1 = engine.encrypt(data1, ec);
    EXPECT_FALSE(ec);
    EXPECT_FALSE(result1.empty());

    std::vector<std::uint8_t> encrypted1(result1.begin(), result1.end());

    auto result2 = engine.encrypt(data2, ec);
    EXPECT_FALSE(ec);
    EXPECT_FALSE(result2.empty());

    std::vector<std::uint8_t> encrypted2(result2.begin(), result2.end());

    EXPECT_NE(encrypted1, encrypted2);
}

}    // namespace mux
