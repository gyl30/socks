
#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include <string_view>

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

    const auto fallback_no_target_before = stats.fallback_no_target();
    stats.inc_fallback_no_target();
    EXPECT_EQ(stats.fallback_no_target(), fallback_no_target_before + 1);

    const auto fallback_resolve_before = stats.fallback_resolve_failures();
    stats.inc_fallback_resolve_failures();
    EXPECT_EQ(stats.fallback_resolve_failures(), fallback_resolve_before + 1);

    const auto fallback_resolve_timeout_before = stats.fallback_resolve_timeouts();
    stats.inc_fallback_resolve_timeouts();
    EXPECT_EQ(stats.fallback_resolve_timeouts(), fallback_resolve_timeout_before + 1);

    const auto fallback_resolve_error_before = stats.fallback_resolve_errors();
    stats.inc_fallback_resolve_errors();
    EXPECT_EQ(stats.fallback_resolve_errors(), fallback_resolve_error_before + 1);

    const auto fallback_connect_before = stats.fallback_connect_failures();
    stats.inc_fallback_connect_failures();
    EXPECT_EQ(stats.fallback_connect_failures(), fallback_connect_before + 1);

    const auto fallback_connect_timeout_before = stats.fallback_connect_timeouts();
    stats.inc_fallback_connect_timeouts();
    EXPECT_EQ(stats.fallback_connect_timeouts(), fallback_connect_timeout_before + 1);

    const auto fallback_connect_error_before = stats.fallback_connect_errors();
    stats.inc_fallback_connect_errors();
    EXPECT_EQ(stats.fallback_connect_errors(), fallback_connect_error_before + 1);

    const auto fallback_write_before = stats.fallback_write_failures();
    stats.inc_fallback_write_failures();
    EXPECT_EQ(stats.fallback_write_failures(), fallback_write_before + 1);

    const auto fallback_write_timeout_before = stats.fallback_write_timeouts();
    stats.inc_fallback_write_timeouts();
    EXPECT_EQ(stats.fallback_write_timeouts(), fallback_write_timeout_before + 1);

    const auto fallback_write_error_before = stats.fallback_write_errors();
    stats.inc_fallback_write_errors();
    EXPECT_EQ(stats.fallback_write_errors(), fallback_write_error_before + 1);

    const auto direct_upstream_resolve_timeout_before = stats.direct_upstream_resolve_timeouts();
    stats.inc_direct_upstream_resolve_timeouts();
    EXPECT_EQ(stats.direct_upstream_resolve_timeouts(), direct_upstream_resolve_timeout_before + 1);

    const auto direct_upstream_resolve_error_before = stats.direct_upstream_resolve_errors();
    stats.inc_direct_upstream_resolve_errors();
    EXPECT_EQ(stats.direct_upstream_resolve_errors(), direct_upstream_resolve_error_before + 1);

    const auto direct_upstream_connect_timeout_before = stats.direct_upstream_connect_timeouts();
    stats.inc_direct_upstream_connect_timeouts();
    EXPECT_EQ(stats.direct_upstream_connect_timeouts(), direct_upstream_connect_timeout_before + 1);

    const auto direct_upstream_connect_error_before = stats.direct_upstream_connect_errors();
    stats.inc_direct_upstream_connect_errors();
    EXPECT_EQ(stats.direct_upstream_connect_errors(), direct_upstream_connect_error_before + 1);

    const auto remote_resolve_timeout_before = stats.remote_session_resolve_timeouts();
    stats.inc_remote_session_resolve_timeouts();
    EXPECT_EQ(stats.remote_session_resolve_timeouts(), remote_resolve_timeout_before + 1);

    const auto remote_resolve_error_before = stats.remote_session_resolve_errors();
    stats.inc_remote_session_resolve_errors();
    EXPECT_EQ(stats.remote_session_resolve_errors(), remote_resolve_error_before + 1);

    const auto remote_connect_timeout_before = stats.remote_session_connect_timeouts();
    stats.inc_remote_session_connect_timeouts();
    EXPECT_EQ(stats.remote_session_connect_timeouts(), remote_connect_timeout_before + 1);

    const auto remote_connect_error_before = stats.remote_session_connect_errors();
    stats.inc_remote_session_connect_errors();
    EXPECT_EQ(stats.remote_session_connect_errors(), remote_connect_error_before + 1);

    const auto remote_udp_resolve_timeout_before = stats.remote_udp_session_resolve_timeouts();
    stats.inc_remote_udp_session_resolve_timeouts();
    EXPECT_EQ(stats.remote_udp_session_resolve_timeouts(), remote_udp_resolve_timeout_before + 1);

    const auto remote_udp_resolve_error_before = stats.remote_udp_session_resolve_errors();
    stats.inc_remote_udp_session_resolve_errors();
    EXPECT_EQ(stats.remote_udp_session_resolve_errors(), remote_udp_resolve_error_before + 1);

    const auto client_tunnel_resolve_timeout_before = stats.client_tunnel_pool_resolve_timeouts();
    stats.inc_client_tunnel_pool_resolve_timeouts();
    EXPECT_EQ(stats.client_tunnel_pool_resolve_timeouts(), client_tunnel_resolve_timeout_before + 1);

    const auto client_tunnel_resolve_error_before = stats.client_tunnel_pool_resolve_errors();
    stats.inc_client_tunnel_pool_resolve_errors();
    EXPECT_EQ(stats.client_tunnel_pool_resolve_errors(), client_tunnel_resolve_error_before + 1);

    const auto client_tunnel_connect_timeout_before = stats.client_tunnel_pool_connect_timeouts();
    stats.inc_client_tunnel_pool_connect_timeouts();
    EXPECT_EQ(stats.client_tunnel_pool_connect_timeouts(), client_tunnel_connect_timeout_before + 1);

    const auto client_tunnel_connect_error_before = stats.client_tunnel_pool_connect_errors();
    stats.inc_client_tunnel_pool_connect_errors();
    EXPECT_EQ(stats.client_tunnel_pool_connect_errors(), client_tunnel_connect_error_before + 1);

    const auto client_tunnel_handshake_timeout_before = stats.client_tunnel_pool_handshake_timeouts();
    stats.inc_client_tunnel_pool_handshake_timeouts();
    EXPECT_EQ(stats.client_tunnel_pool_handshake_timeouts(), client_tunnel_handshake_timeout_before + 1);

    const auto client_tunnel_handshake_error_before = stats.client_tunnel_pool_handshake_errors();
    stats.inc_client_tunnel_pool_handshake_errors();
    EXPECT_EQ(stats.client_tunnel_pool_handshake_errors(), client_tunnel_handshake_error_before + 1);

    const auto blocked_before = stats.routing_blocked();
    stats.inc_routing_blocked();
    EXPECT_EQ(stats.routing_blocked(), blocked_before + 1);

    const auto conn_limit_before = stats.connection_limit_rejected();
    stats.inc_connection_limit_rejected();
    EXPECT_EQ(stats.connection_limit_rejected(), conn_limit_before + 1);

    const auto stream_limit_before = stats.stream_limit_rejected();
    stats.inc_stream_limit_rejected();
    EXPECT_EQ(stats.stream_limit_rejected(), stream_limit_before + 1);

    const auto monitor_auth_before = stats.monitor_auth_failures();
    stats.inc_monitor_auth_failures();
    EXPECT_EQ(stats.monitor_auth_failures(), monitor_auth_before + 1);

    const auto monitor_rate_before = stats.monitor_rate_limited();
    stats.inc_monitor_rate_limited();
    EXPECT_EQ(stats.monitor_rate_limited(), monitor_rate_before + 1);

    const auto dispatch_enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    stats.inc_tproxy_udp_dispatch_enqueued();
    EXPECT_EQ(stats.tproxy_udp_dispatch_enqueued(), dispatch_enqueued_before + 1);

    const auto dispatch_dropped_before = stats.tproxy_udp_dispatch_dropped();
    stats.inc_tproxy_udp_dispatch_dropped();
    EXPECT_EQ(stats.tproxy_udp_dispatch_dropped(), dispatch_dropped_before + 1);
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
    const auto invalid_reason = statistics::handshake_failure_reason::kCount;

    stats.inc_handshake_failure_by_sni(invalid_reason, "ignored");
    const auto after = stats.handshake_failure_sni_metrics();
    EXPECT_EQ(after.size(), before.size());

    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kShortId), "short_id");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kClockSkew), "clock_skew");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kReplay), "replay");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(statistics::handshake_failure_reason::kCertVerify), "cert_verify");
    EXPECT_STREQ(statistics::handshake_failure_reason_label(invalid_reason), "unknown");
}

TEST(StatisticsTest, HandshakeFailureMetricsSortsAcrossDifferentReasons)
{
    auto& stats = statistics::instance();
    const auto before = stats.handshake_failure_sni_metrics();
    const auto cert_before = find_metric_count(before, "cert_verify", "cert-order");
    const auto short_before = find_metric_count(before, "short_id", "short-order");

    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kCertVerify, "cert-order");
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "short-order");

    const auto after = stats.handshake_failure_sni_metrics();
    EXPECT_EQ(find_metric_count(after, "cert_verify", "cert-order"), cert_before + 1);
    EXPECT_EQ(find_metric_count(after, "short_id", "short-order"), short_before + 1);

    std::size_t cert_index = after.size();
    std::size_t short_index = after.size();
    for (std::size_t i = 0; i < after.size(); ++i)
    {
        if (after[i].reason == "cert_verify" && after[i].sni == "cert-order")
        {
            cert_index = i;
        }
        if (after[i].reason == "short_id" && after[i].sni == "short-order")
        {
            short_index = i;
        }
    }

    ASSERT_LT(cert_index, after.size());
    ASSERT_LT(short_index, after.size());
    EXPECT_LT(cert_index, short_index);
}

}    // namespace mux
