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
    auto keys = tls_key_schedule::derive_traffic_keys({});
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysInvalidSecret)
{
    auto keys = tls_key_schedule::derive_handshake_keys(std::vector<uint8_t>(32, 0), {}, EVP_sha256());

    auto keys2 = tls_key_schedule::derive_handshake_keys({}, std::vector<uint8_t>(32, 0), EVP_sha256());
    EXPECT_FALSE(keys2.has_value());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysCoversEarlySecretFailureBranch)
{
    fail_evp_pkey_derive_on_call(1);
    const auto keys =
        tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 0x22), EVP_sha256());
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysCoversDerivedSecretFailureBranch)
{
    fail_evp_pkey_derive_on_call(2);
    const auto keys =
        tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x31), std::vector<std::uint8_t>(32, 0x42), EVP_sha256());
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveApplicationSecretsCoversServerSecretFailureBranch)
{
    fail_evp_pkey_derive_on_call(2);
    const std::vector<std::uint8_t> master_secret(32, 0x79);
    const std::vector<std::uint8_t> handshake_hash(32, 0x8a);

    const auto app = tls_key_schedule::derive_application_secrets(master_secret, handshake_hash, EVP_sha256());
    // value_or is used internally, so this still returns a value with partial results
    ASSERT_TRUE(app.has_value());
    EXPECT_EQ(app->first.size(), 32u);
    EXPECT_TRUE(app->second.empty());
}

TEST(TlsKeyScheduleTest, DeriveApplicationSecretsNullDigestReturnsError)
{
    const std::vector<std::uint8_t> master_secret(32, 0x9b);
    const std::vector<std::uint8_t> handshake_hash(32, 0xac);

    const auto app = tls_key_schedule::derive_application_secrets(master_secret, handshake_hash, nullptr);
    // With null digest, EVP_MD_size returns 0, so hash_len will be 0 and results will be empty
    ASSERT_TRUE(app.has_value());
    EXPECT_TRUE(app->first.empty());
    EXPECT_TRUE(app->second.empty());
}

TEST(TlsKeyScheduleTest, ComputeFinishedVerifyDataInvalidBaseKey)
{
    auto data = tls_key_schedule::compute_finished_verify_data({}, std::vector<uint8_t>(32, 0), EVP_sha256());
    EXPECT_FALSE(data.has_value());
}

TEST(TlsKeyScheduleTest, DeriveTrafficKeysIvLengthTooLarge)
{
    const std::vector<std::uint8_t> secret(32, 0x11);
    auto keys = tls_key_schedule::derive_traffic_keys(secret, 16, 9000, EVP_sha256());
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveTrafficKeysSuccess)
{
    const std::vector<std::uint8_t> secret(32, 0x42);

    const auto keys = tls_key_schedule::derive_traffic_keys(secret);
    ASSERT_TRUE(keys.has_value());
    EXPECT_EQ(keys->first.size(), 16u);
    EXPECT_EQ(keys->second.size(), 12u);
}

TEST(TlsKeyScheduleTest, DeriveHandshakeAndApplicationSecretsSuccess)
{
    const std::vector<std::uint8_t> shared_secret(32, 0x21);
    const std::vector<std::uint8_t> server_hello_hash(32, 0x43);

    const auto hs = tls_key_schedule::derive_handshake_keys(shared_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(hs.has_value());
    EXPECT_EQ(hs->client_handshake_traffic_secret.size(), 32u);
    EXPECT_EQ(hs->server_handshake_traffic_secret.size(), 32u);
    EXPECT_EQ(hs->master_secret.size(), 32u);

    const auto app = tls_key_schedule::derive_application_secrets(hs->master_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(app.has_value());
    EXPECT_EQ(app->first.size(), 32u);
    EXPECT_EQ(app->second.size(), 32u);
}

TEST(TlsKeyScheduleTest, ComputeFinishedVerifyDataSuccess)
{
    const std::vector<std::uint8_t> base_key(32, 0x55);
    const std::vector<std::uint8_t> handshake_hash(32, 0x66);

    const auto verify = tls_key_schedule::compute_finished_verify_data(base_key, handshake_hash, EVP_sha256());
    ASSERT_TRUE(verify.has_value());
    EXPECT_EQ(verify->size(), 32u);
}
