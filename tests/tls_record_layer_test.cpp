// NOLINTBEGIN(modernize-use-nodiscard)
// NOLINTBEGIN(misc-include-cleaner)
#include <array>
#include <atomic>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "tls_record_layer.h"
#include "crypto_util.h"

using reality::tls_record_layer;

extern "C" int __real_RAND_bytes(unsigned char* buf, int num);  // NOLINT(bugprone-reserved-identifier)

namespace
{

std::atomic<bool> g_force_rand_bytes_fail_once{false};

void fail_rand_bytes_once() { g_force_rand_bytes_fail_once.store(true, std::memory_order_release); }

void reset_rand_bytes_hook() { g_force_rand_bytes_fail_once.store(false, std::memory_order_release); }

}    // namespace

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_force_rand_bytes_fail_once.exchange(false, std::memory_order_acq_rel))
    {
        (void)buf;
        (void)num;
        return 0;
    }
    return __real_RAND_bytes(buf, num);  // NOLINT(bugprone-reserved-identifier)
}

class TlsRecordLayerTest : public ::testing::Test
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

TEST_F(TlsRecordLayerTest, RoundTrip)
{
    const std::vector<uint8_t> plaintext = {0xAA, 0xBB, 0xCC, 0xDD};
    const uint64_t seq = 1;
    const uint8_t type = 0x17;
    const auto encrypted = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, type);
    ASSERT_TRUE(encrypted.has_value());
    ASSERT_GT(encrypted->size(), plaintext.size() + 16);

    uint8_t out_type = 0;
    const auto decrypted = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, *encrypted, out_type);

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(out_type, type);
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(TlsRecordLayerTest, SequenceNumberMatters)
{
    const std::vector<uint8_t> plaintext = {0x12, 0x34};
    const auto enc1 = tls_record_layer::encrypt_record(cipher(), key(), iv(), 100, plaintext, 0x17);
    ASSERT_TRUE(enc1.has_value());

    uint8_t out_type = 0;

    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), 101, *enc1, out_type);

    EXPECT_FALSE(dec.has_value());
}

TEST_F(TlsRecordLayerTest, TamperedCiphertext)
{
    const std::vector<uint8_t> plaintext = {0x00, 0x01};
    const uint64_t seq = 50;
    auto enc = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, 0x17);
    ASSERT_TRUE(enc.has_value());

    enc->back() ^= 0xFF;

    uint8_t out_type = 0;
    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, *enc, out_type);

    EXPECT_FALSE(dec.has_value());
}

TEST_F(TlsRecordLayerTest, DecryptAllZeros)
{
    std::vector<uint8_t> const zeros(20, 0);
    const uint64_t seq = 0;

    const std::vector<uint8_t> aad = {0x17, 0x03, 0x03, 0x00, static_cast<uint8_t>(zeros.size() + 16)};
    auto encrypted = reality::crypto_util::aead_encrypt(cipher(), key(), iv(), zeros, aad);
    ASSERT_TRUE(encrypted.has_value());

    std::vector<uint8_t> record;
    record.insert(record.end(), aad.begin(), aad.end());
    record.insert(record.end(), encrypted->begin(), encrypted->end());

    uint8_t out_type = 0;
    auto dec_result = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, record, out_type);

    EXPECT_FALSE(dec_result.has_value());
    EXPECT_EQ(dec_result.error(), std::make_error_code(std::errc::bad_message));
}

TEST_F(TlsRecordLayerTest, EncryptAppDataWithPadding)
{
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};
    const uint64_t seq = 10;
    const uint8_t type = reality::kContentTypeApplicationData;
    const auto encrypted = tls_record_layer::encrypt_record(cipher(), key(), iv(), seq, plaintext, type);
    ASSERT_TRUE(encrypted.has_value());

    uint8_t out_type = 0;
    const auto decrypted = tls_record_layer::decrypt_record(cipher(), key(), iv(), seq, *encrypted, out_type);

    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(out_type, type);
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(TlsRecordLayerTest, EncryptAppDataRandFailure)
{
    fail_rand_bytes_once();
    const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};

    const auto encrypted = tls_record_layer::encrypt_record(
        cipher(), key(), iv(), 10, plaintext, reality::kContentTypeApplicationData);
    EXPECT_FALSE(encrypted.has_value());

    reset_rand_bytes_hook();
}

TEST_F(TlsRecordLayerTest, DecryptSpanShortRecordRejected)
{
    const reality::cipher_context ctx;
    std::array<uint8_t, 10> short_record{};
    std::array<uint8_t, 32> output{};
    std::uint8_t out_type = 0;
    const auto n = tls_record_layer::decrypt_record(
        ctx, cipher(), key(), iv(), 0, std::span<const uint8_t>(short_record), std::span<uint8_t>(output), out_type);
    EXPECT_FALSE(n.has_value());
    EXPECT_EQ(n.error(), std::make_error_code(std::errc::message_size));
}

TEST_F(TlsRecordLayerTest, ShortMessage)
{
    const std::vector<uint8_t> short_msg(10, 0x00);
    uint8_t out_type = 0;

    const auto dec = tls_record_layer::decrypt_record(cipher(), key(), iv(), 0, short_msg, out_type);

    EXPECT_FALSE(dec.has_value());
    EXPECT_EQ(dec.error(), std::make_error_code(std::errc::message_size));
}
// NOLINTEND(misc-include-cleaner)
// NOLINTEND(modernize-use-nodiscard)
