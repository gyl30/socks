#include <gtest/gtest.h>
#include <memory>
#include "reality_fingerprint.h"

using reality::FingerprintFactory;
using reality::FingerprintType;
using reality::tls_consts;
using reality::ExtensionType;

TEST(RealityFingerprintTest, Chrome120Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, GreaseValues)
{
    const reality::GreaseContext ctx;
    const uint16_t g1 = ctx.get_grease(0);
    const uint16_t g2 = ctx.get_grease(1);

    EXPECT_EQ(g1 & 0x0f0f, 0x0a0a);
    EXPECT_EQ(g2 & 0x0f0f, 0x0a0a);
}

TEST(RealityFingerprintTest, ShuffleExtensions)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    auto original_exts = spec.extensions;

    bool changed = false;
    for (int i = 0; i < 10; ++i)
    {
        auto current_exts = original_exts;
        FingerprintFactory::shuffle_extensions(current_exts);
        if (current_exts != original_exts)
        {
            changed = true;
            break;
        }
    }

    EXPECT_TRUE(changed);
}

TEST(RealityFingerprintTest, IOS14Identification)
{
    auto spec = FingerprintFactory::Get(FingerprintType::iOS_14);
    bool found_alpn = false;
    for (const auto& ext : spec.extensions)
    {
        if (ext->type() == ExtensionType::ALPN)
        {
            found_alpn = true;
            auto alpn = std::dynamic_pointer_cast<reality::ALPNBlueprint>(ext);
            ASSERT_NE(alpn, nullptr);
            EXPECT_EQ(alpn->protocols[0], "h2");
        }
    }
    EXPECT_TRUE(found_alpn);
}

TEST(RealityFingerprintTest, Firefox120Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Firefox_120);
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
}

TEST(RealityFingerprintTest, Android11Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Android_11_OkHttp);
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
}

TEST(RealityFingerprintTest, Chrome131Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_131);
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, GetChrome120Direct)
{
    auto spec = FingerprintFactory::GetChrome120();
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, CompressionMethods)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    ASSERT_EQ(spec.compression_methods.size(), 1);
    EXPECT_EQ(spec.compression_methods[0], 0x00);
}

TEST(RealityFingerprintTest, Chrome58Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_58);
    EXPECT_FALSE(spec.extensions.empty());

    bool found_cbc = false;
    for (auto c : spec.cipher_suites)
    {
        if (c == tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
        {
            found_cbc = true;
        }
    }
    EXPECT_TRUE(found_cbc);
}

TEST(RealityFingerprintTest, Chrome70Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_70);
    EXPECT_FALSE(spec.extensions.empty());

    bool found_ver = false;
    for (const auto& ext : spec.extensions)
    {
        if (ext->type() == ExtensionType::SupportedVersions)
        {
            found_ver = true;
        }
    }
    EXPECT_TRUE(found_ver);
}

TEST(RealityFingerprintTest, Chrome106Shuffle)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_106_Shuffle);
    EXPECT_TRUE(spec.shuffle_extensions);

    bool has_app_settings = false;
    for (const auto& ext : spec.extensions)
    {
        if (ext->type() == ExtensionType::ApplicationSettings)
        {
            has_app_settings = true;
        }
        if (ext->type() == ExtensionType::GreaseECH)
        {
            has_app_settings = true;
        }
    }
    EXPECT_FALSE(has_app_settings);
}

TEST(RealityFingerprintTest, Chrome133Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_133);
    bool found_mlkem = false;

    for (const auto& ext : spec.extensions)
    {
        if (ext->type() == ExtensionType::KeyShare)
        {
            auto k = std::dynamic_pointer_cast<reality::KeyShareBlueprint>(ext);
            for (auto& ks : k->key_shares)
            {
                if (ks.group == tls_consts::group::X25519_MLKEM768)
                {
                    found_mlkem = true;
                }
            }
        }
    }
    EXPECT_TRUE(found_mlkem);
}

TEST(RealityFingerprintTest, Browser360Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Browser360_11_0);
    bool found_chid = false;
    for (const auto& ext : spec.extensions)
    {
        if (ext->type() == ExtensionType::ChannelID)
        {
            found_chid = true;
        }
    }
    EXPECT_TRUE(found_chid);
}
