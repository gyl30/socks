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
