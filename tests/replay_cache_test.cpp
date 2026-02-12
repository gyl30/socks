#include <vector>
#include <cstdint>

#include <gtest/gtest.h>

#include "replay_cache.h"

TEST(ReplayCacheTest, Basic)
{
    mux::replay_cache cache;
    const std::vector<std::uint8_t> sid(32, 0x01);

    EXPECT_TRUE(cache.check_and_insert(sid));
    EXPECT_FALSE(cache.check_and_insert(sid));

    const std::vector<std::uint8_t> sid2(32, 0x02);
    EXPECT_TRUE(cache.check_and_insert(sid2));
}

TEST(ReplayCacheTest, InvalidSize)
{
    mux::replay_cache cache;
    const std::vector<std::uint8_t> sid(31, 0x01);
    EXPECT_FALSE(cache.check_and_insert(sid));
}

TEST(ReplayCacheTest, InvalidSizeTooLong)
{
    mux::replay_cache cache;
    const std::vector<std::uint8_t> sid(33, 0x01);
    EXPECT_FALSE(cache.check_and_insert(sid));
}

TEST(ReplayCacheTest, CapacityEviction)
{
    mux::replay_cache cache(3);
    const std::vector<std::uint8_t> sid1(32, 0x01);
    const std::vector<std::uint8_t> sid2(32, 0x02);
    const std::vector<std::uint8_t> sid3(32, 0x03);
    const std::vector<std::uint8_t> sid4(32, 0x04);

    EXPECT_TRUE(cache.check_and_insert(sid1));
    EXPECT_TRUE(cache.check_and_insert(sid2));
    EXPECT_TRUE(cache.check_and_insert(sid3));
    EXPECT_FALSE(cache.check_and_insert(sid1));

    EXPECT_TRUE(cache.check_and_insert(sid4));
    EXPECT_TRUE(cache.check_and_insert(sid1));
}

TEST(ReplayCacheTest, ZeroCapacityClampedToOne)
{
    mux::replay_cache cache(0);
    const std::vector<std::uint8_t> sid1(32, 0x01);
    const std::vector<std::uint8_t> sid2(32, 0x02);

    EXPECT_TRUE(cache.check_and_insert(sid1));
    EXPECT_TRUE(cache.check_and_insert(sid2));
    EXPECT_TRUE(cache.check_and_insert(sid1));
}
