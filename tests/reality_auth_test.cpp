#include <gtest/gtest.h>
#include <array>
#include <span>
#include "reality_auth.h"

using reality::auth_payload;

TEST(RealityAuthTest, BuildAndParseRoundTrip)
{
    std::vector<uint8_t> short_id = {0x01, 0x02, 0x03, 0x04};
    uint32_t ts = 0x11223344;
    std::array<uint8_t, 2> nonce = {0xAA, 0xBB};
    std::array<uint8_t, reality::AUTH_PAYLOAD_LEN> payload{};

    ASSERT_TRUE(reality::build_auth_payload(short_id, ts, nonce, payload));

    auto parsed = reality::parse_auth_payload(std::span<const uint8_t>(payload.data(), payload.size()));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->version, 1);
    EXPECT_EQ(parsed->short_id, short_id);
    EXPECT_EQ(parsed->timestamp, ts);
    EXPECT_EQ(parsed->nonce, nonce);
}

TEST(RealityAuthTest, RejectTooLongShortId)
{
    std::vector<uint8_t> short_id(reality::SHORT_ID_MAX_LEN + 1, 0x11);
    uint32_t ts = 0x01020304;
    std::array<uint8_t, 2> nonce = {0x00, 0x01};
    std::array<uint8_t, reality::AUTH_PAYLOAD_LEN> payload{};

    EXPECT_FALSE(reality::build_auth_payload(short_id, ts, nonce, payload));
}

TEST(RealityAuthTest, RejectInvalidPayload)
{
    std::array<uint8_t, reality::AUTH_PAYLOAD_LEN> payload{};
    payload.fill(0);
    payload[0] = 2;
    auto parsed = reality::parse_auth_payload(std::span<const uint8_t>(payload.data(), payload.size()));
    EXPECT_FALSE(parsed.has_value());
}
