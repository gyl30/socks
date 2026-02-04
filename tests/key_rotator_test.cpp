#include <gtest/gtest.h>
#include <thread>
#include "key_rotator.h"

TEST(KeyRotatorTest, InitialKeyGenerated)
{
    reality::key_rotator rotator;
    auto key = rotator.get_current_key();
    ASSERT_NE(key, nullptr);
}

TEST(KeyRotatorTest, ConsistencyWithinTimeout)
{
    reality::key_rotator rotator;
    auto key1 = rotator.get_current_key();
    auto key2 = rotator.get_current_key();
    EXPECT_EQ(key1, key2);
}
