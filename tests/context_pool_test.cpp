// NOLINTBEGIN(performance-inefficient-vector-operation)
// NOLINTBEGIN(misc-include-cleaner)
#include <thread>
#include <vector>
#include <cstddef>
#include <system_error>
#include <unordered_set>

#include <gtest/gtest.h>

#include "context_pool.h"

namespace mux
{

TEST(ContextPoolTest, ZeroSizeClampedToOne)
{
    io_context_pool pool(0);
    auto& ctx = pool.get_io_context();
    EXPECT_FALSE(ctx.stopped());
    pool.stop();
}

TEST(ContextPoolTest, SingleContextWorks)
{
    boost::system::error_code const ec;
    io_context_pool pool(1);
    EXPECT_FALSE(ec);

    auto& ctx1 = pool.get_io_context();
    auto& ctx2 = pool.get_io_context();

    EXPECT_EQ(&ctx1, &ctx2);

    pool.stop();
}

TEST(ContextPoolTest, MultipleContextsRoundRobin)
{
    boost::system::error_code const ec;
    io_context_pool pool(3);
    EXPECT_FALSE(ec);

    std::vector<boost::asio::io_context*> contexts;
    for (int i = 0; i < 6; ++i)
    {
        contexts.push_back(&pool.get_io_context());
    }

    EXPECT_EQ(contexts[0], contexts[3]);
    EXPECT_EQ(contexts[1], contexts[4]);
    EXPECT_EQ(contexts[2], contexts[5]);

    std::unordered_set<boost::asio::io_context*> const unique_contexts(contexts.begin(), contexts.begin() + 3);
    EXPECT_EQ(unique_contexts.size(), 3U);

    pool.stop();
}

TEST(ContextPoolTest, StopMultipleTimes)
{
    boost::system::error_code const ec;
    io_context_pool pool(2);
    EXPECT_FALSE(ec);

    pool.stop();
    pool.stop();
}

TEST(ContextPoolTest, StopMarksAllContextsStopped)
{
    boost::system::error_code const ec;
    io_context_pool pool(2);
    EXPECT_FALSE(ec);

    auto& ctx1 = pool.get_io_context();
    auto& ctx2 = pool.get_io_context();
    EXPECT_FALSE(ctx1.stopped());
    EXPECT_FALSE(ctx2.stopped());

    pool.stop();
    EXPECT_TRUE(ctx1.stopped());
    EXPECT_TRUE(ctx2.stopped());
}

TEST(ContextPoolTest, RunAndStop)
{
    boost::system::error_code const ec;
    io_context_pool pool(2);
    EXPECT_FALSE(ec);

    std::thread stopper(
        [&pool]()
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            pool.stop();
        });

    std::thread runner([&pool]() { pool.run(); });

    stopper.join();
    runner.join();
}

}    // namespace mux
// NOLINTEND(misc-include-cleaner)
// NOLINTEND(performance-inefficient-vector-operation)
