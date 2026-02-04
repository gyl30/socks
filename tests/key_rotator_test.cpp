#include <gtest/gtest.h>

#include "key_rotator.h"

TEST(KeyRotatorTest, InitialKeyGenerated)
{
    reality::key_rotator rotator;
    const auto key = rotator.get_current_key();
    ASSERT_NE(key, nullptr);
}

TEST(KeyRotatorTest, ConsistencyWithinTimeout)
{
    reality::key_rotator rotator;
    const auto key1 = rotator.get_current_key();
    const auto key2 = rotator.get_current_key();
    EXPECT_EQ(key1, key2);
}
