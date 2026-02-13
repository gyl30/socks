#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
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

class reality_engine_test : public ::testing::Test
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

    [[nodiscard]] const EVP_CIPHER* cipher() const { return cipher_; }
    [[nodiscard]] const std::vector<std::uint8_t>& read_key() const { return read_key_; }
    [[nodiscard]] const std::vector<std::uint8_t>& read_iv() const { return read_iv_; }
    [[nodiscard]] const std::vector<std::uint8_t>& write_key() const { return write_key_; }
    [[nodiscard]] const std::vector<std::uint8_t>& write_iv() const { return write_iv_; }

   private:
    const EVP_CIPHER* cipher_ = nullptr;
    std::vector<std::uint8_t> read_key_;
    std::vector<std::uint8_t> read_iv_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_iv_;
};

TEST_F(reality_engine_test, EncryptEmptyData)
{
    reality_engine engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    std::error_code ec;
    auto result = engine.encrypt({}, ec);

    EXPECT_FALSE(ec);
    EXPECT_TRUE(result.empty());
}

TEST_F(reality_engine_test, EncryptProducesOutput)
{
    reality_engine engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::error_code ec;
    auto result = engine.encrypt(plaintext, ec);

    EXPECT_FALSE(ec);
    EXPECT_FALSE(result.empty());

    EXPECT_GE(result.size(), plaintext.size() + 5 + 16 + 1);
}

TEST_F(reality_engine_test, EncryptReturnsErrorOnInvalidWriteKeyLength)
{
    reality_engine engine(read_key(), read_iv(), std::vector<std::uint8_t>{0x01}, write_iv(), cipher());
    std::error_code ec;

    const std::vector<std::uint8_t> plaintext = {'x'};
    const auto result = engine.encrypt(plaintext, ec);
    EXPECT_TRUE(ec);
    EXPECT_TRUE(result.empty());
}

TEST_F(reality_engine_test, DecryptInsufficientData)
{
    reality_engine engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

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

TEST_F(reality_engine_test, DecryptWaitsForCompleteFrame)
{
    reality_engine engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    auto buf = engine.read_buffer(5);
    const std::uint8_t header_only[] = {0x17, 0x03, 0x03, 0x00, 0x10};
    std::memcpy(buf.data(), header_only, sizeof(header_only));
    engine.commit_read(sizeof(header_only));

    std::error_code ec;
    bool called = false;
    engine.process_available_records(ec, [&called](std::uint8_t, std::span<const std::uint8_t>) { called = true; });

    EXPECT_FALSE(ec);
    EXPECT_FALSE(called);
}

TEST_F(reality_engine_test, EncryptDecryptRoundTrip)
{
    reality_engine encrypt_engine(write_key(), write_iv(), read_key(), read_iv(), cipher());
    reality_engine decrypt_engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

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

TEST_F(reality_engine_test, MultipleEncryptions)
{
    reality_engine engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

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

TEST_F(reality_engine_test, AlertContentType)
{
    reality_engine decrypt_engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    std::error_code ec;

    std::vector<uint8_t> alert_plaintext = {0x02, 0x32};
    auto alert_rec = reality::tls_record_layer::encrypt_record(cipher(), read_key(), read_iv(), 0, alert_plaintext, reality::kContentTypeAlert, ec);
    ASSERT_FALSE(ec);

    auto buf = decrypt_engine.read_buffer(alert_rec.size());
    std::memcpy(buf.data(), alert_rec.data(), alert_rec.size());
    decrypt_engine.commit_read(alert_rec.size());

    bool called = false;
    decrypt_engine.process_available_records(ec,
                                             [&called](std::uint8_t type, std::span<const std::uint8_t>)
                                             {
                                                 if (type == reality::kContentTypeAlert)
                                                 {
                                                     called = true;
                                                 }
                                             });

    EXPECT_EQ(ec, asio::error::eof);
    EXPECT_TRUE(called);
}

TEST_F(reality_engine_test, DecryptError)
{
    reality_engine decrypt_engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    std::error_code ec;
    std::vector<uint8_t> data = {0x01, 0x02};
    auto rec = reality::tls_record_layer::encrypt_record(cipher(), read_key(), read_iv(), 0, data, reality::kContentTypeApplicationData, ec);
    ASSERT_FALSE(ec);

    rec.back() ^= 0xFF;

    auto buf = decrypt_engine.read_buffer(rec.size());
    std::memcpy(buf.data(), rec.data(), rec.size());
    decrypt_engine.commit_read(rec.size());

    bool called = false;
    decrypt_engine.process_available_records(ec, [&called](std::uint8_t, std::span<const std::uint8_t>) { called = true; });

    EXPECT_TRUE(ec);
    EXPECT_FALSE(called);
}

TEST_F(reality_engine_test, ProcessAvailableRecordsStopsWhenCallbackSetsError)
{
    reality_engine decrypt_engine(read_key(), read_iv(), write_key(), write_iv(), cipher());

    std::error_code ec;
    const std::vector<std::uint8_t> payload = {0x10, 0x20, 0x30};
    const auto rec =
        reality::tls_record_layer::encrypt_record(cipher(), read_key(), read_iv(), 0, payload, reality::kContentTypeApplicationData, ec);
    ASSERT_FALSE(ec);

    auto buf = decrypt_engine.read_buffer(rec.size());
    std::memcpy(buf.data(), rec.data(), rec.size());
    decrypt_engine.commit_read(rec.size());

    std::size_t callback_calls = 0;
    decrypt_engine.process_available_records(
        ec,
        [&ec, &callback_calls](std::uint8_t, std::span<const std::uint8_t>)
        {
            ++callback_calls;
            ec = asio::error::operation_aborted;
        });

    EXPECT_EQ(callback_calls, 1u);
    EXPECT_EQ(ec, asio::error::operation_aborted);
}

}    // namespace mux
