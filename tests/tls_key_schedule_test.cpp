#include <vector>
#include <system_error>
#include <atomic>
#include <cstdint>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "tls_key_schedule.h"

using namespace reality;

namespace
{

std::atomic<int> g_tls_key_schedule_derive_call_counter{0};
std::atomic<int> g_tls_key_schedule_fail_derive_call{0};

void fail_evp_pkey_derive_on_call(const int call_index)
{
    g_tls_key_schedule_derive_call_counter.store(0, std::memory_order_release);
    g_tls_key_schedule_fail_derive_call.store(call_index, std::memory_order_release);
}

}    // namespace

extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)
{
    if (key == nullptr || keylen == nullptr)
    {
        return __real_EVP_PKEY_derive(ctx, key, keylen);
    }

    const int call_index = g_tls_key_schedule_derive_call_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
    const int fail_index = g_tls_key_schedule_fail_derive_call.load(std::memory_order_acquire);
    if (fail_index > 0 && call_index == fail_index)
    {
        g_tls_key_schedule_fail_derive_call.store(0, std::memory_order_release);
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);
}

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

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysCoversEarlySecretFailureBranch)
{
    std::error_code ec;
    fail_evp_pkey_derive_on_call(1);
    const auto keys =
        tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 0x22), EVP_sha256(), ec);
    EXPECT_TRUE(ec);
    EXPECT_TRUE(keys.client_handshake_traffic_secret.empty());
    EXPECT_TRUE(keys.server_handshake_traffic_secret.empty());
    EXPECT_TRUE(keys.master_secret.empty());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysCoversDerivedSecretFailureBranch)
{
    std::error_code ec;
    fail_evp_pkey_derive_on_call(2);
    const auto keys =
        tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x31), std::vector<std::uint8_t>(32, 0x42), EVP_sha256(), ec);
    EXPECT_TRUE(ec);
    EXPECT_TRUE(keys.client_handshake_traffic_secret.empty());
    EXPECT_TRUE(keys.server_handshake_traffic_secret.empty());
    EXPECT_TRUE(keys.master_secret.empty());
}

TEST(TlsKeyScheduleTest, DeriveApplicationSecretsCoversServerSecretFailureBranch)
{
    std::error_code ec;
    fail_evp_pkey_derive_on_call(2);
    const std::vector<std::uint8_t> master_secret(32, 0x79);
    const std::vector<std::uint8_t> handshake_hash(32, 0x8a);

    const auto app = tls_key_schedule::derive_application_secrets(master_secret, handshake_hash, EVP_sha256(), ec);
    EXPECT_TRUE(ec);
    EXPECT_EQ(app.first.size(), 32u);
    EXPECT_TRUE(app.second.empty());
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
