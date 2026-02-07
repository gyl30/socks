#include <vector>
#include <system_error>

#include <openssl/evp.h>
#include <gtest/gtest.h>

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
    // Shared secret should not be empty for HKDF extract
    auto keys = tls_key_schedule::derive_handshake_keys(std::vector<uint8_t>(32, 0), {}, EVP_sha256(), ec);
    // Actually shared_secret being zero is fine for HKDF, but ikm empty is not.
    // In derive_handshake_keys:
    // const auto early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, md, ec);
    // This should succeed.

    // Test with empty shared_secret
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
