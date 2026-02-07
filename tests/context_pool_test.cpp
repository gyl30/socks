#include <vector>
#include <thread>
#include <cstddef>
#include <system_error>
#include <unordered_set>

#include <gtest/gtest.h>

#include "context_pool.h"

namespace mux
{

TEST(ContextPoolTest, ZeroSizeRejected)
{
    std::error_code ec;
    io_context_pool pool(0, ec);
    EXPECT_TRUE(ec);
    EXPECT_EQ(ec, std::make_error_code(std::errc::invalid_argument));
}

TEST(ContextPoolTest, SingleContextWorks)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    EXPECT_FALSE(ec);

    auto& ctx1 = pool.get_io_context();
    auto& ctx2 = pool.get_io_context();

    EXPECT_EQ(&ctx1, &ctx2);

    pool.stop();
}

TEST(ContextPoolTest, MultipleContextsRoundRobin)
{
    std::error_code ec;
    io_context_pool pool(3, ec);
    EXPECT_FALSE(ec);

    std::vector<asio::io_context*> contexts;
    for (int i = 0; i < 6; ++i)
    {
        contexts.push_back(&pool.get_io_context());
    }

    EXPECT_EQ(contexts[0], contexts[3]);
    EXPECT_EQ(contexts[1], contexts[4]);
    EXPECT_EQ(contexts[2], contexts[5]);

    std::unordered_set<asio::io_context*> unique_contexts(contexts.begin(), contexts.begin() + 3);
    EXPECT_EQ(unique_contexts.size(), 3U);

    pool.stop();
}

TEST(ContextPoolTest, StopMultipleTimes)
{
    std::error_code ec;
    io_context_pool pool(2, ec);
    EXPECT_FALSE(ec);

    pool.stop();
    pool.stop();
}

TEST(ContextPoolTest, RunAndStop)
{
    std::error_code ec;
    io_context_pool pool(2, ec);
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
