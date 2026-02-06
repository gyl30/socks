#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include "log_context.h"

namespace mux
{

TEST(LogContextTest, TargetInfo)
{
    connection_context ctx;
    ctx.set_target("example.com", 443);
    EXPECT_EQ(ctx.target_info(), "example.com_443");
}

TEST(LogContextTest, DurationSeconds)
{
    connection_context ctx;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    double duration = ctx.duration_seconds();
    EXPECT_GE(duration, 0.1);
    EXPECT_LT(duration, 1.0);
}

TEST(LogContextTest, StatsSummary)
{
    connection_context ctx;
    ctx.tx_bytes(1024);
    ctx.rx_bytes(2048);
    std::string summary = ctx.stats_summary();
    EXPECT_TRUE(summary.find("tx 1024") != std::string::npos);
    EXPECT_TRUE(summary.find("rx 2048") != std::string::npos);
    EXPECT_TRUE(summary.find("duration") != std::string::npos);
}

TEST(LogContextTest, WithStream)
{
    connection_context ctx;
    ctx.trace_id("parent-trace");
    ctx.tx_bytes(5000);

    auto stream_ctx = ctx.with_stream(42);
    EXPECT_EQ(stream_ctx.trace_id(), "parent-trace");
    EXPECT_EQ(stream_ctx.tx_bytes(), 0);
    EXPECT_EQ(stream_ctx.rx_bytes(), 0);
}

TEST(LogContextTest, FormatBytes)
{
    EXPECT_EQ(format_bytes(500), "500B");
    EXPECT_EQ(format_bytes(1024), "1.00KB");
    EXPECT_EQ(format_bytes(1024 * 1024), "1.00MB");
    EXPECT_EQ(format_bytes(1024ULL * 1024 * 1024), "1.00GB");
    EXPECT_EQ(format_bytes(1536), "1.50KB");
}

TEST(LogContextTest, FormatLatency) { EXPECT_EQ(format_latency_ms(123), "123ms"); }

}    // namespace mux
