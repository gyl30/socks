#include <gtest/gtest.h>
#include "reality_fingerprint.h"

using namespace reality;

TEST(RealityFingerprintTest, Chrome120_Basic) {
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    EXPECT_EQ(spec.client_version, tls_consts::VER_1_2);
    EXPECT_FALSE(spec.cipher_suites.empty());
    EXPECT_FALSE(spec.extensions.empty());
    EXPECT_TRUE(spec.shuffle_extensions);
}

TEST(RealityFingerprintTest, GreaseValues) {
    GreaseContext ctx;
    uint16_t g1 = ctx.get_grease(0);
    uint16_t g2 = ctx.get_grease(1);
    // They should be from the GREASE_VALUES set (ending in 0x?a?a)
    EXPECT_EQ(g1 & 0x0f0f, 0x0a0a);
    EXPECT_EQ(g2 & 0x0f0f, 0x0a0a);
}

TEST(RealityFingerprintTest, ShuffleExtensions) {
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    auto original_exts = spec.extensions;
    
    // Multiple shuffles to check for changes (statistically likely to change)
    bool changed = false;
    for (int i = 0; i < 10; ++i) {
        auto current_exts = original_exts;
        FingerprintFactory::shuffle_extensions(current_exts);
        if (current_exts != original_exts) {
            changed = true;
            break;
        }
    }
    // Note: Some extensions aren't shufflable, but Chrome 120 has many that are.
    EXPECT_TRUE(changed);
}

TEST(RealityFingerprintTest, IOS14_Identification) {
    auto spec = FingerprintFactory::Get(FingerprintType::iOS_14);
    bool found_alpn = false;
    for (const auto& ext : spec.extensions) {
        if (ext->type() == ExtensionType::ALPN) {
            found_alpn = true;
            auto alpn = std::dynamic_pointer_cast<ALPNBlueprint>(ext);
            ASSERT_NE(alpn, nullptr);
            EXPECT_EQ(alpn->protocols[0], "h2");
        }
    }
    EXPECT_TRUE(found_alpn);
}
