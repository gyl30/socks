#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "statistics.h"

namespace
{

std::uint64_t find_metric_count(const std::vector<mux::statistics::handshake_failure_sni_metric>& metrics,
                                const std::string_view reason,
                                const std::string_view sni)
{
    for (const auto& metric : metrics)
    {
        if (metric.reason == reason && metric.sni == sni)
        {
            return metric.count;
        }
    }
    return 0;
}

std::size_t count_reason_keys(const std::vector<mux::statistics::handshake_failure_sni_metric>& metrics, const std::string_view reason)
{
    std::size_t count = 0;
    for (const auto& metric : metrics)
    {
        if (metric.reason == reason && metric.sni != "others")
        {
            count++;
        }
    }
    return count;
}

}    // namespace

namespace mux
{

TEST(StatisticsTest, CountersAndUptime)
{
    auto& stats = statistics::instance();
    stats.start_time();
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_GE(stats.uptime_seconds(), 1U);

    const auto active_before = stats.active_connections();
    stats.inc_active_connections();
    EXPECT_EQ(stats.active_connections(), active_before + 1);
    stats.dec_active_connections();
    EXPECT_EQ(stats.active_connections(), active_before);

    const auto total_before = stats.total_connections();
    stats.inc_total_connections();
    EXPECT_EQ(stats.total_connections(), total_before + 1);

    const auto mux_before = stats.active_mux_sessions();
    stats.inc_active_mux_sessions();
    EXPECT_EQ(stats.active_mux_sessions(), mux_before + 1);
    stats.dec_active_mux_sessions();
    EXPECT_EQ(stats.active_mux_sessions(), mux_before);

    const auto read_before = stats.bytes_read();
    stats.add_bytes_read(7);
    EXPECT_EQ(stats.bytes_read(), read_before + 7);

    const auto written_before = stats.bytes_written();
    stats.add_bytes_written(9);
    EXPECT_EQ(stats.bytes_written(), written_before + 9);

    const auto auth_before = stats.auth_failures();
    stats.inc_auth_failures();
    EXPECT_EQ(stats.auth_failures(), auth_before + 1);

    const auto short_id_before = stats.auth_short_id_failures();
    stats.inc_auth_short_id_failures();
    EXPECT_EQ(stats.auth_short_id_failures(), short_id_before + 1);

    const auto skew_before = stats.auth_clock_skew_failures();
    stats.inc_auth_clock_skew_failures();
    EXPECT_EQ(stats.auth_clock_skew_failures(), skew_before + 1);

    const auto replay_before = stats.auth_replay_failures();
    stats.inc_auth_replay_failures();
    EXPECT_EQ(stats.auth_replay_failures(), replay_before + 1);

    const auto cert_before = stats.cert_verify_failures();
    stats.inc_cert_verify_failures();
    EXPECT_EQ(stats.cert_verify_failures(), cert_before + 1);

    const auto finished_before = stats.client_finished_failures();
    stats.inc_client_finished_failures();
    EXPECT_EQ(stats.client_finished_failures(), finished_before + 1);

    const auto fallback_before = stats.fallback_rate_limited();
    stats.inc_fallback_rate_limited();
    EXPECT_EQ(stats.fallback_rate_limited(), fallback_before + 1);

    const auto blocked_before = stats.routing_blocked();
    stats.inc_routing_blocked();
    EXPECT_EQ(stats.routing_blocked(), blocked_before + 1);
}

TEST(StatisticsTest, HandshakeFailureMetricsTracksAndSorts)
{
    auto& stats = statistics::instance();

    const auto before = stats.handshake_failure_sni_metrics();
    const auto empty_before = find_metric_count(before, "short_id", "empty");
    const auto alpha_before = find_metric_count(before, "short_id", "alpha");

    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "");
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "alpha");
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "alpha");

    const auto after = stats.handshake_failure_sni_metrics();
    EXPECT_EQ(find_metric_count(after, "short_id", "empty"), empty_before + 1);
    EXPECT_EQ(find_metric_count(after, "short_id", "alpha"), alpha_before + 2);

    for (std::size_t i = 1; i < after.size(); ++i)
    {
        const auto& lhs = after[i - 1];
        const auto& rhs = after[i];
        if (lhs.reason == rhs.reason)
        {
            if (lhs.count == rhs.count)
            {
                EXPECT_LE(lhs.sni, rhs.sni);
            }
            else
            {
                EXPECT_GE(lhs.count, rhs.count);
            }
        }
        else
        {
            EXPECT_LE(lhs.reason, rhs.reason);
        }
    }
}

TEST(StatisticsTest, HandshakeFailureMetricsOverflowGoesToOthers)
{
    auto& stats = statistics::instance();

    const auto reason = statistics::handshake_failure_reason::kClockSkew;
    const std::string reason_label = statistics::handshake_failure_reason_label(reason);
    const auto before = stats.handshake_failure_sni_metrics();
    const auto others_before = find_metric_count(before, reason_label, "others");
    const auto unique_before = count_reason_keys(before, reason_label);

    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    for (int i = 0; i < 120; ++i)
    {
        stats.inc_handshake_failure_by_sni(reason, "overflow-" + suffix + "-" + std::to_string(i));
    }

    const auto after = stats.handshake_failure_sni_metrics();
    const auto others_after = find_metric_count(after, reason_label, "others");
    const auto expected_overflow = unique_before + 120 > 100 ? unique_before + 120 - 100 : 0;
    EXPECT_EQ(others_after, others_before + static_cast<std::uint64_t>(expected_overflow));
}

TEST(StatisticsTest, InvalidReasonIsIgnoredAndLabelsCovered)
{
    auto& stats = statistics::instance();
    const auto before = stats.handshake_failure_sni_metrics();

    stats.inc_handshake_failure_by_sni(static_cast<statistics::handshake_failure_reason>(99), "ignored");
    const auto after = stats.handshake_failure_sni_metrics();
    EXPECT_EQ(after.size(), before.size());

    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kShortId), "short_id");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kClockSkew), "clock_skew");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kReplay), "replay");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kCertVerify), "cert_verify");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(static_cast<statistics::handshake_failure_reason>(99)), "unknown");
}

}    // namespace mux
