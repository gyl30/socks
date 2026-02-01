#include <gtest/gtest.h>
#include "replay_cache.h"
#include <thread>

using namespace mux;

TEST(ReplayCacheTest, Basic)
{
    replay_cache cache;
    std::vector<uint8_t> sid(32, 0x01);

    EXPECT_TRUE(cache.check_and_insert(sid));
    EXPECT_FALSE(cache.check_and_insert(sid));    // Replay detected

    std::vector<uint8_t> sid2(32, 0x02);
    EXPECT_TRUE(cache.check_and_insert(sid2));
}

TEST(ReplayCacheTest, InvalidSize)
{
    replay_cache cache;
    std::vector<uint8_t> sid(31, 0x01);
    EXPECT_FALSE(cache.check_and_insert(sid));
}

// Note: Testing cleanup() would require waiting 5 minutes or mocking time.
// Since it's a simple implementation, we'll stick to basic verification.
