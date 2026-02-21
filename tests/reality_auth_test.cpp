
#include <span>
#include <array>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>

#include "reality_auth.h"

TEST(RealityAuthTest, BuildAndParseRoundTrip)
{
    const std::vector<std::uint8_t> short_id = {0x01, 0x02, 0x03, 0x04};
    const std::uint32_t ts = 0x11223344;
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    const std::array<std::uint8_t, 3> ver{1, 0, 0};

    ASSERT_TRUE(reality::build_auth_payload(short_id, ver, ts, payload));

    auto parsed = reality::parse_auth_payload(std::span<const std::uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(parsed.has_value());
    const auto& p = *parsed;
    EXPECT_EQ(p.version_x, 1);
    EXPECT_EQ(p.version_y, 0);
    EXPECT_EQ(p.version_z, 0);
    EXPECT_EQ(p.timestamp, ts);

    EXPECT_EQ(p.short_id[0], 0x01);
    EXPECT_EQ(p.short_id[1], 0x02);
    EXPECT_EQ(p.short_id[2], 0x03);
    EXPECT_EQ(p.short_id[3], 0x04);
    EXPECT_EQ(p.short_id[4], 0x00);
}

TEST(RealityAuthTest, RejectTooLongShortId)
{
    const std::vector<std::uint8_t> short_id(reality::kShortIdMaxLen + 1, 0x11);
    const std::uint32_t ts = 0x01020304;
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    const std::array<std::uint8_t, 3> ver{1, 0, 0};

    EXPECT_FALSE(reality::build_auth_payload(short_id, ver, ts, payload));
}

TEST(RealityAuthTest, ParsePayloadLayout)
{
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload = {
        0x01, 0x02, 0x03, 0x00, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    auto parsed = reality::parse_auth_payload(std::span<const std::uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(parsed.has_value());
    const auto& p = *parsed;
    EXPECT_EQ(p.version_x, 0x01);
    EXPECT_EQ(p.version_y, 0x02);
    EXPECT_EQ(p.version_z, 0x03);
    EXPECT_EQ(p.timestamp, 0x11223344);
    EXPECT_EQ(p.short_id[0], 0xAA);
    EXPECT_EQ(p.short_id[7], 0x11);
}

TEST(RealityAuthTest, ParseAllowsNonOneVersion)
{
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload = {
        0x1a, 0x02, 0x06, 0x00, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    auto parsed = reality::parse_auth_payload(std::span<const std::uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(parsed.has_value());
    const auto& p = *parsed;
    EXPECT_EQ(p.version_x, 0x1a);
    EXPECT_EQ(p.version_y, 0x02);
    EXPECT_EQ(p.version_z, 0x06);
}

TEST(RealityAuthTest, ParseRejectsInvalidLength)
{
    std::array<std::uint8_t, reality::kAuthPayloadLen - 1> short_payload{};
    const auto parsed = reality::parse_auth_payload(std::span<const std::uint8_t>(short_payload.data(), short_payload.size()));
    EXPECT_FALSE(parsed.has_value());
}
