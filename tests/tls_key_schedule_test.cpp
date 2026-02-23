
#include <atomic>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "crypto_util.h"
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

std::expected<handshake_keys, boost::system::error_code> derive_handshake_keys_reference_no_psk(const std::vector<std::uint8_t>& shared_secret,
                                                                                                 const std::vector<std::uint8_t>& server_hello_hash,
                                                                                                 const EVP_MD* md)
{
    const int hash_len_i = EVP_MD_size(md);
    if (hash_len_i <= 0)
    {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }
    const auto hash_len = static_cast<std::size_t>(hash_len_i);
    const std::vector<std::uint8_t> zero_ikm(hash_len, 0);
    auto early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, md);
    if (!early_secret)
    {
        return std::unexpected(early_secret.error());
    }

    std::vector<std::uint8_t> empty_hash(hash_len);
    unsigned int digest_len = 0;
    if (EVP_Digest(nullptr, 0, empty_hash.data(), &digest_len, md, nullptr) != 1 || digest_len != hash_len)
    {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }

    auto derived_secret = crypto_util::hkdf_expand_label(*early_secret, "derived", empty_hash, hash_len, md);
    if (!derived_secret)
    {
        return std::unexpected(derived_secret.error());
    }
    auto handshake_secret = crypto_util::hkdf_extract(*derived_secret, shared_secret, md);
    if (!handshake_secret)
    {
        return std::unexpected(handshake_secret.error());
    }

    auto c_hs_secret = crypto_util::hkdf_expand_label(*handshake_secret, "c hs traffic", server_hello_hash, hash_len, md);
    if (!c_hs_secret)
    {
        return std::unexpected(c_hs_secret.error());
    }
    auto s_hs_secret = crypto_util::hkdf_expand_label(*handshake_secret, "s hs traffic", server_hello_hash, hash_len, md);
    if (!s_hs_secret)
    {
        return std::unexpected(s_hs_secret.error());
    }

    auto derived_secret_2 = crypto_util::hkdf_expand_label(*handshake_secret, "derived", empty_hash, hash_len, md);
    if (!derived_secret_2)
    {
        return std::unexpected(derived_secret_2.error());
    }
    auto master_secret = crypto_util::hkdf_extract(*derived_secret_2, zero_ikm, md);
    if (!master_secret)
    {
        return std::unexpected(master_secret.error());
    }

    return handshake_keys{.client_handshake_traffic_secret = std::move(*c_hs_secret),
                          .server_handshake_traffic_secret = std::move(*s_hs_secret),
                          .master_secret = std::move(*master_secret)};
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
    const auto keys = tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 0x22), EVP_sha256());
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysCoversDerivedSecretFailureBranch)
{
    fail_evp_pkey_derive_on_call(2);
    const auto keys = tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x31), std::vector<std::uint8_t>(32, 0x42), EVP_sha256());
    EXPECT_FALSE(keys.has_value());
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysRejectsAllLateStageDeriveFailures)
{
    for (const int call_index : {3, 4, 5, 6, 7})
    {
        fail_evp_pkey_derive_on_call(call_index);
        const auto keys =
            tls_key_schedule::derive_handshake_keys(std::vector<std::uint8_t>(32, 0x51), std::vector<std::uint8_t>(32, 0x62), EVP_sha256());
        EXPECT_FALSE(keys.has_value());
    }
}

TEST(TlsKeyScheduleTest, DeriveApplicationSecretsCoversServerSecretFailureBranch)
{
    fail_evp_pkey_derive_on_call(2);
    const std::vector<std::uint8_t> master_secret(32, 0x79);
    const std::vector<std::uint8_t> handshake_hash(32, 0x8a);

    const auto app = tls_key_schedule::derive_application_secrets(master_secret, handshake_hash, EVP_sha256());
    EXPECT_FALSE(app.has_value());
}

TEST(TlsKeyScheduleTest, DeriveApplicationSecretsNullDigestReturnsError)
{
    const std::vector<std::uint8_t> master_secret(32, 0x9b);
    const std::vector<std::uint8_t> handshake_hash(32, 0xac);

    const auto app = tls_key_schedule::derive_application_secrets(master_secret, handshake_hash, nullptr);
    EXPECT_FALSE(app.has_value());
    ASSERT_FALSE(app.has_value());
    EXPECT_EQ(app.error(), std::make_error_code(std::errc::protocol_error));
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
    EXPECT_EQ(keys->first.size(), 16U);
    EXPECT_EQ(keys->second.size(), 12U);
}

TEST(TlsKeyScheduleTest, DeriveHandshakeAndApplicationSecretsSuccess)
{
    const std::vector<std::uint8_t> shared_secret(32, 0x21);
    const std::vector<std::uint8_t> server_hello_hash(32, 0x43);

    const auto hs = tls_key_schedule::derive_handshake_keys(shared_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(hs.has_value());
    EXPECT_EQ(hs->client_handshake_traffic_secret.size(), 32U);
    EXPECT_EQ(hs->server_handshake_traffic_secret.size(), 32U);
    EXPECT_EQ(hs->master_secret.size(), 32U);

    const auto app = tls_key_schedule::derive_application_secrets(hs->master_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(app.has_value());
    EXPECT_EQ(app->first.size(), 32U);
    EXPECT_EQ(app->second.size(), 32U);
}

TEST(TlsKeyScheduleTest, DeriveHandshakeKeysMatchesReferenceNoPskSchedule)
{
    const std::vector<std::uint8_t> shared_secret(32, 0x5a);
    const std::vector<std::uint8_t> server_hello_hash(32, 0x6b);

    const auto derived = tls_key_schedule::derive_handshake_keys(shared_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(derived.has_value());

    const auto expected = derive_handshake_keys_reference_no_psk(shared_secret, server_hello_hash, EVP_sha256());
    ASSERT_TRUE(expected.has_value());

    EXPECT_EQ(derived->client_handshake_traffic_secret, expected->client_handshake_traffic_secret);
    EXPECT_EQ(derived->server_handshake_traffic_secret, expected->server_handshake_traffic_secret);
    EXPECT_EQ(derived->master_secret, expected->master_secret);
}

TEST(TlsKeyScheduleTest, ComputeFinishedVerifyDataSuccess)
{
    const std::vector<std::uint8_t> base_key(32, 0x55);
    const std::vector<std::uint8_t> handshake_hash(32, 0x66);

    const auto verify = tls_key_schedule::compute_finished_verify_data(base_key, handshake_hash, EVP_sha256());
    ASSERT_TRUE(verify.has_value());
    EXPECT_EQ(verify->size(), 32U);
}
