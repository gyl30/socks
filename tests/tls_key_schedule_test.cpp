#include <vector>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "tls_key_schedule.h"

using namespace reality;

TEST(TlsKeyScheduleTest, DeriveTrafficKeysInvalidSecret)
{
    std::error_code ec;
    auto keys = tls_key_schedule::derive_traffic_keys({}, ec);
    EXPECT_TRUE(ec);
    EXPECT_TRUE(keys.first.empty());
    EXPECT_TRUE(keys.second.empty());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysInvalidSecret)
{
    std::error_code ec;

    auto keys = tls_key_schedule::derive_handshake_keys(std::vector<uint8_t>(32, 0), {}, EVP_sha256(), ec);

    keys = tls_key_schedule::derive_handshake_keys({}, std::vector<uint8_t>(32, 0), EVP_sha256(), ec);
    EXPECT_TRUE(ec);
}

TEST(TlsKeyScheduleTest, ComputeFinishedVerifyDataInvalidBaseKey)
{
    std::error_code ec;
    auto data = tls_key_schedule::compute_finished_verify_data({}, std::vector<uint8_t>(32, 0), EVP_sha256(), ec);
    EXPECT_TRUE(ec);
    EXPECT_TRUE(data.empty());
}

TEST(TlsKeyScheduleTest, DeriveTrafficKeysIvLengthTooLarge)
{
    std::error_code ec;
    const std::vector<std::uint8_t> secret(32, 0x11);
    auto keys = tls_key_schedule::derive_traffic_keys(secret, ec, 16, 9000, EVP_sha256());
    EXPECT_TRUE(ec);
    EXPECT_TRUE(keys.first.empty());
    EXPECT_TRUE(keys.second.empty());
}

TEST(TlsKeyScheduleTest, DeriveTrafficKeysSuccess)
{
    std::error_code ec;
    const std::vector<std::uint8_t> secret(32, 0x42);

    const auto keys = tls_key_schedule::derive_traffic_keys(secret, ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(keys.first.size(), 16u);
    EXPECT_EQ(keys.second.size(), 12u);
}

TEST(TlsKeyScheduleTest, DeriveHandshakeAndApplicationSecretsSuccess)
{
    std::error_code ec;
    const std::vector<std::uint8_t> shared_secret(32, 0x21);
    const std::vector<std::uint8_t> server_hello_hash(32, 0x43);

    const auto hs = tls_key_schedule::derive_handshake_keys(shared_secret, server_hello_hash, EVP_sha256(), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(hs.client_handshake_traffic_secret.size(), 32u);
    EXPECT_EQ(hs.server_handshake_traffic_secret.size(), 32u);
    EXPECT_EQ(hs.master_secret.size(), 32u);

    const auto app = tls_key_schedule::derive_application_secrets(hs.master_secret, server_hello_hash, EVP_sha256(), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(app.first.size(), 32u);
    EXPECT_EQ(app.second.size(), 32u);
}

TEST(TlsKeyScheduleTest, ComputeFinishedVerifyDataSuccess)
{
    std::error_code ec;
    const std::vector<std::uint8_t> base_key(32, 0x55);
    const std::vector<std::uint8_t> handshake_hash(32, 0x66);

    const auto verify = tls_key_schedule::compute_finished_verify_data(base_key, handshake_hash, EVP_sha256(), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(verify.size(), 32u);
}
