#include <gtest/gtest.h>
#include <thread>
#include <vector>
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

    EXPECT_NE(key1->public_key, nullptr);
}

TEST(KeyRotatorTest, ThreadSafety)
{
    reality::key_rotator rotator;
    std::vector<std::shared_ptr<reality::x25519_keypair>> keys(100);
    std::vector<std::thread> threads;

    for (int i = 0; i < 100; ++i)
    {
        threads.emplace_back([&rotator, &keys, i]() { keys[i] = rotator.get_current_key(); });
    }

    for (auto& t : threads)
    {
        if (t.joinable())
            t.join();
    }

    for (int i = 1; i < 100; ++i)
    {
        EXPECT_EQ(keys[0], keys[i]);
    }
}
