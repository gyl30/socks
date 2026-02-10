#include <memory>
#include <cstdint>

#include <gtest/gtest.h>

#include "reality_fingerprint.h"

using reality::ExtensionType;
using reality::FingerprintFactory;
using reality::FingerprintType;
namespace tls_consts = reality::tls_consts;

TEST(RealityFingerprintTest, Chrome120Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    EXPECT_EQ(spec.client_version, tls_consts::kVer12);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, GreaseValues)
{
    const reality::GreaseContext ctx;
    const std::uint16_t g1 = ctx.get_grease(0);
    const std::uint16_t g2 = ctx.get_grease(1);

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
        if (ext->type() == ExtensionType::kAlpn)
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
    EXPECT_EQ(spec.client_version, tls_consts::kVer12);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
}

TEST(RealityFingerprintTest, Android11Basic)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Android_11_OkHttp);
    EXPECT_EQ(spec.client_version, tls_consts::kVer12);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
}

TEST(RealityFingerprintTest, GetChrome120Direct)
{
    auto spec = FingerprintFactory::GetChrome120();
    EXPECT_EQ(spec.client_version, tls_consts::kVer12);
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, CompressionMethods)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    ASSERT_EQ(spec.compression_methods.size(), 1);
    EXPECT_EQ(spec.compression_methods[0], 0x00);
}
