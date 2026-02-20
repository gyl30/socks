// NOLINTBEGIN(performance-inefficient-vector-operation, readability-named-parameter)
// NOLINTBEGIN(misc-include-cleaner)
#include <atomic>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "crypto_util.h"
#define private public
#include "key_rotator.h"
#undef private

namespace
{

enum class keygen_mode : std::uint8_t
{
    kSuccess = 0,
    kReturnFalse = 1,
};

std::atomic<keygen_mode> g_keygen_mode{keygen_mode::kSuccess};
std::atomic<std::uint8_t> g_seed{1};
std::atomic<bool> g_fail_nothrow_new_once{false};

}    // namespace

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define SOCKS_HAS_TSAN 1
#endif
#endif

#if defined(__SANITIZE_THREAD__)
#define SOCKS_HAS_TSAN 1
#endif

#if !defined(SOCKS_HAS_TSAN)
void* operator new(std::size_t size, const std::nothrow_t&) noexcept
{
    if (g_fail_nothrow_new_once.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return std::malloc(size);
}

void operator delete(void* ptr, const std::nothrow_t&) noexcept
{
    std::free(ptr);
}
#endif

namespace reality
{

bool crypto_util::generate_x25519_keypair(std::uint8_t out_public[32], std::uint8_t out_private[32])
{
    const auto mode = g_keygen_mode.load(std::memory_order_relaxed);
    if (mode == keygen_mode::kReturnFalse)
    {
        return false;
    }
    const auto seed = g_seed.fetch_add(1, std::memory_order_relaxed);
    for (std::size_t i = 0; i < 32; ++i)
    {
        out_private[i] = static_cast<std::uint8_t>(seed + i);
        out_public[i] = static_cast<std::uint8_t>(seed + i + 32);
    }
    return true;
}

}    // namespace reality

TEST(KeyRotatorTest, InitialKeyGenerated)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator;
    const auto key = rotator.get_current_key();
    ASSERT_NE(key, nullptr);
}

TEST(KeyRotatorTest, ConsistencyWithinTimeout)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator;
    const auto key1 = rotator.get_current_key();
    const auto key2 = rotator.get_current_key();
    EXPECT_EQ(key1, key2);

    EXPECT_NE(key1->public_key, nullptr);
}

TEST(KeyRotatorTest, ThreadSafety)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
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
        {
            t.join();
        }
    }

    for (int i = 1; i < 100; ++i)
    {
        EXPECT_EQ(keys[0], keys[i]);
    }
}

TEST(KeyRotatorTest, KeyRotation)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(1));
    const auto key1 = rotator.get_current_key();

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    const auto key2 = rotator.get_current_key();
    EXPECT_NE(key1, key2);

    const auto key3 = rotator.get_current_key();
    EXPECT_EQ(key2, key3);
}

TEST(KeyRotatorTest, MissingCurrentKeyTriggersFallbackRotationPath)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(60));

    std::atomic_store_explicit(&rotator.current_key_, std::shared_ptr<reality::x25519_keypair>{}, std::memory_order_release);
    rotator.next_rotate_time_.store(std::chrono::steady_clock::now() + std::chrono::hours(1), std::memory_order_relaxed);

    const auto key = rotator.get_current_key();
    EXPECT_NE(key, nullptr);
}

TEST(KeyRotatorTest, ConstructorHandlesGenerateFailureAndRecovers)
{
    g_keygen_mode.store(keygen_mode::kReturnFalse, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(60));

    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    const auto key = rotator.get_current_key();
    EXPECT_NE(key, nullptr);
}

TEST(KeyRotatorTest, TimeBasedRotationCompareExchangeFailureReturnsCurrentKey)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(60));
    const auto original_key = rotator.get_current_key();
    ASSERT_NE(original_key, nullptr);

    rotator.next_rotate_time_.store(std::chrono::steady_clock::now() - std::chrono::seconds(1), std::memory_order_relaxed);
    rotator.rotating_.store(true, std::memory_order_release);

    const auto key = rotator.get_current_key();
    EXPECT_EQ(key, original_key);

    rotator.rotating_.store(false, std::memory_order_release);
}

TEST(KeyRotatorTest, FallbackCompareExchangeFailureReturnsNullWhenStillRotating)
{
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(60));

    std::atomic_store_explicit(&rotator.current_key_, std::shared_ptr<reality::x25519_keypair>{}, std::memory_order_release);
    rotator.next_rotate_time_.store(std::chrono::steady_clock::now() + std::chrono::hours(1), std::memory_order_relaxed);
    rotator.rotating_.store(true, std::memory_order_release);

    const auto key = rotator.get_current_key();
    EXPECT_EQ(key, nullptr);

    rotator.rotating_.store(false, std::memory_order_release);
}

TEST(KeyRotatorTest, RotateReturnsFalseWhenKeyAllocationFails)
{
#if defined(SOCKS_HAS_TSAN)
    GTEST_SKIP() << "tsan runtime overrides nothrow operator new/delete";
#else
    g_keygen_mode.store(keygen_mode::kSuccess, std::memory_order_relaxed);
    reality::key_rotator rotator(std::chrono::seconds(60));

    const auto before = rotator.get_current_key();
    ASSERT_NE(before, nullptr);

    g_fail_nothrow_new_once.store(true, std::memory_order_release);
    EXPECT_FALSE(rotator.rotate());

    const auto after = rotator.get_current_key();
    EXPECT_EQ(after, before);
#endif
}
// NOLINTEND(misc-include-cleaner)
// NOLINTEND(performance-inefficient-vector-operation, readability-named-parameter)
