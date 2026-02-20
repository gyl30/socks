#ifndef STATISTICS_H
#define STATISTICS_H

#include <array>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace mux
{

class statistics
{
   public:
    enum class handshake_failure_reason : std::uint8_t
    {
        kShortId = 0,
        kClockSkew,
        kReplay,
        kCertVerify,
        kCount
    };

    struct handshake_failure_sni_metric
    {
        std::string_view reason;
        std::string sni;
        std::uint64_t count = 0;
    };

    static statistics& instance()
    {
        static statistics s;
        return s;
    }

    void start_time() { start_time_ = std::chrono::steady_clock::now(); }

    std::uint64_t uptime_seconds() const
    {
        const auto now = std::chrono::steady_clock::now();
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
        if (uptime <= 0)
        {
            return 0;
        }
        return static_cast<std::uint64_t>(uptime);
    }

    void inc_active_connections() { active_connections_++; }
    void dec_active_connections() { active_connections_--; }
    std::uint64_t active_connections() const { return active_connections_.load(); }

    void inc_total_connections() { total_connections_++; }
    std::uint64_t total_connections() const { return total_connections_.load(); }

    void inc_active_mux_sessions() { active_mux_sessions_++; }
    void dec_active_mux_sessions() { active_mux_sessions_--; }
    std::uint64_t active_mux_sessions() const { return active_mux_sessions_.load(); }

    void add_bytes_read(std::uint64_t n) { bytes_read_ += n; }
    std::uint64_t bytes_read() const { return bytes_read_.load(); }

    void add_bytes_written(std::uint64_t n) { bytes_written_ += n; }
    std::uint64_t bytes_written() const { return bytes_written_.load(); }

    void inc_auth_failures() { auth_failures_++; }
    std::uint64_t auth_failures() const { return auth_failures_.load(); }

    void inc_auth_short_id_failures() { auth_short_id_failures_++; }
    std::uint64_t auth_short_id_failures() const { return auth_short_id_failures_.load(); }

    void inc_auth_clock_skew_failures() { auth_clock_skew_failures_++; }
    std::uint64_t auth_clock_skew_failures() const { return auth_clock_skew_failures_.load(); }

    void inc_auth_replay_failures() { auth_replay_failures_++; }
    std::uint64_t auth_replay_failures() const { return auth_replay_failures_.load(); }

    void inc_cert_verify_failures() { cert_verify_failures_++; }
    std::uint64_t cert_verify_failures() const { return cert_verify_failures_.load(); }

    void inc_client_finished_failures() { client_finished_failures_++; }
    std::uint64_t client_finished_failures() const { return client_finished_failures_.load(); }

    void inc_fallback_rate_limited() { fallback_rate_limited_++; }
    std::uint64_t fallback_rate_limited() const { return fallback_rate_limited_.load(); }

    void inc_fallback_no_target() { fallback_no_target_++; }
    std::uint64_t fallback_no_target() const { return fallback_no_target_.load(); }

    void inc_fallback_resolve_failures() { fallback_resolve_failures_++; }
    std::uint64_t fallback_resolve_failures() const { return fallback_resolve_failures_.load(); }

    void inc_fallback_resolve_timeouts() { fallback_resolve_timeouts_++; }
    std::uint64_t fallback_resolve_timeouts() const { return fallback_resolve_timeouts_.load(); }

    void inc_fallback_resolve_errors() { fallback_resolve_errors_++; }
    std::uint64_t fallback_resolve_errors() const { return fallback_resolve_errors_.load(); }

    void inc_fallback_connect_failures() { fallback_connect_failures_++; }
    std::uint64_t fallback_connect_failures() const { return fallback_connect_failures_.load(); }

    void inc_fallback_connect_timeouts() { fallback_connect_timeouts_++; }
    std::uint64_t fallback_connect_timeouts() const { return fallback_connect_timeouts_.load(); }

    void inc_fallback_connect_errors() { fallback_connect_errors_++; }
    std::uint64_t fallback_connect_errors() const { return fallback_connect_errors_.load(); }

    void inc_fallback_write_failures() { fallback_write_failures_++; }
    std::uint64_t fallback_write_failures() const { return fallback_write_failures_.load(); }

    void inc_fallback_write_timeouts() { fallback_write_timeouts_++; }
    std::uint64_t fallback_write_timeouts() const { return fallback_write_timeouts_.load(); }

    void inc_fallback_write_errors() { fallback_write_errors_++; }
    std::uint64_t fallback_write_errors() const { return fallback_write_errors_.load(); }

    void inc_direct_upstream_resolve_timeouts() { direct_upstream_resolve_timeouts_++; }
    std::uint64_t direct_upstream_resolve_timeouts() const { return direct_upstream_resolve_timeouts_.load(); }

    void inc_direct_upstream_resolve_errors() { direct_upstream_resolve_errors_++; }
    std::uint64_t direct_upstream_resolve_errors() const { return direct_upstream_resolve_errors_.load(); }

    void inc_direct_upstream_connect_timeouts() { direct_upstream_connect_timeouts_++; }
    std::uint64_t direct_upstream_connect_timeouts() const { return direct_upstream_connect_timeouts_.load(); }

    void inc_direct_upstream_connect_errors() { direct_upstream_connect_errors_++; }
    std::uint64_t direct_upstream_connect_errors() const { return direct_upstream_connect_errors_.load(); }

    void inc_remote_session_resolve_timeouts() { remote_session_resolve_timeouts_++; }
    std::uint64_t remote_session_resolve_timeouts() const { return remote_session_resolve_timeouts_.load(); }

    void inc_remote_session_resolve_errors() { remote_session_resolve_errors_++; }
    std::uint64_t remote_session_resolve_errors() const { return remote_session_resolve_errors_.load(); }

    void inc_remote_session_connect_timeouts() { remote_session_connect_timeouts_++; }
    std::uint64_t remote_session_connect_timeouts() const { return remote_session_connect_timeouts_.load(); }

    void inc_remote_session_connect_errors() { remote_session_connect_errors_++; }
    std::uint64_t remote_session_connect_errors() const { return remote_session_connect_errors_.load(); }

    void inc_remote_udp_session_resolve_timeouts() { remote_udp_session_resolve_timeouts_++; }
    std::uint64_t remote_udp_session_resolve_timeouts() const { return remote_udp_session_resolve_timeouts_.load(); }

    void inc_remote_udp_session_resolve_errors() { remote_udp_session_resolve_errors_++; }
    std::uint64_t remote_udp_session_resolve_errors() const { return remote_udp_session_resolve_errors_.load(); }

    void inc_client_tunnel_pool_resolve_timeouts() { client_tunnel_pool_resolve_timeouts_++; }
    std::uint64_t client_tunnel_pool_resolve_timeouts() const { return client_tunnel_pool_resolve_timeouts_.load(); }

    void inc_client_tunnel_pool_resolve_errors() { client_tunnel_pool_resolve_errors_++; }
    std::uint64_t client_tunnel_pool_resolve_errors() const { return client_tunnel_pool_resolve_errors_.load(); }

    void inc_client_tunnel_pool_connect_timeouts() { client_tunnel_pool_connect_timeouts_++; }
    std::uint64_t client_tunnel_pool_connect_timeouts() const { return client_tunnel_pool_connect_timeouts_.load(); }

    void inc_client_tunnel_pool_connect_errors() { client_tunnel_pool_connect_errors_++; }
    std::uint64_t client_tunnel_pool_connect_errors() const { return client_tunnel_pool_connect_errors_.load(); }

    void inc_client_tunnel_pool_handshake_timeouts() { client_tunnel_pool_handshake_timeouts_++; }
    std::uint64_t client_tunnel_pool_handshake_timeouts() const { return client_tunnel_pool_handshake_timeouts_.load(); }

    void inc_client_tunnel_pool_handshake_errors() { client_tunnel_pool_handshake_errors_++; }
    std::uint64_t client_tunnel_pool_handshake_errors() const { return client_tunnel_pool_handshake_errors_.load(); }

    void inc_routing_blocked() { routing_blocked_++; }
    std::uint64_t routing_blocked() const { return routing_blocked_.load(); }

    void inc_connection_limit_rejected() { connection_limit_rejected_++; }
    std::uint64_t connection_limit_rejected() const { return connection_limit_rejected_.load(); }

    void inc_stream_limit_rejected() { stream_limit_rejected_++; }
    std::uint64_t stream_limit_rejected() const { return stream_limit_rejected_.load(); }

    void inc_monitor_auth_failures() { monitor_auth_failures_++; }
    std::uint64_t monitor_auth_failures() const { return monitor_auth_failures_.load(); }

    void inc_monitor_rate_limited() { monitor_rate_limited_++; }
    std::uint64_t monitor_rate_limited() const { return monitor_rate_limited_.load(); }

    void inc_tproxy_udp_dispatch_enqueued() { tproxy_udp_dispatch_enqueued_++; }
    std::uint64_t tproxy_udp_dispatch_enqueued() const { return tproxy_udp_dispatch_enqueued_.load(); }

    void inc_tproxy_udp_dispatch_dropped() { tproxy_udp_dispatch_dropped_++; }
    std::uint64_t tproxy_udp_dispatch_dropped() const { return tproxy_udp_dispatch_dropped_.load(); }

    void inc_handshake_failure_by_sni(const handshake_failure_reason reason, const std::string_view sni)
    {
        const auto reason_index = static_cast<std::size_t>(reason);
        if (reason_index >= static_cast<std::size_t>(handshake_failure_reason::kCount))
        {
            return;
        }

        const std::string_view key = normalize_sni_metric_key(sni);    // GCOVR_EXCL_LINE
        const std::lock_guard<std::mutex> lock(handshake_failure_sni_mu_);    // GCOVR_EXCL_LINE
        auto& counters = handshake_failure_sni_counters_[reason_index];
        const auto it = counters.by_sni.find(key);    // GCOVR_EXCL_LINE
        if (it != counters.by_sni.end())
        {
            it->second++;
            return;
        }
        if (counters.by_sni.size() < kMaxTrackedSniPerReason)
        {
            counters.by_sni.emplace(std::string(key), 1);    // GCOVR_EXCL_LINE
            return;
        }
        counters.others++;
    }

    std::vector<handshake_failure_sni_metric> handshake_failure_sni_metrics() const
    {
        std::vector<handshake_failure_sni_metric> out;
        const std::lock_guard<std::mutex> lock(handshake_failure_sni_mu_);
        std::size_t total_metrics = 0;
        for (std::size_t i = 0; i < static_cast<std::size_t>(handshake_failure_reason::kCount); ++i)
        {
            const auto& counters = handshake_failure_sni_counters_[i];
            total_metrics += counters.by_sni.size();
            if (counters.others > 0)
            {
                ++total_metrics;
            }
        }
        out.reserve(total_metrics);
        for (std::size_t i = 0; i < static_cast<std::size_t>(handshake_failure_reason::kCount); ++i)
        {
            const auto reason = static_cast<handshake_failure_reason>(i);
            const std::string_view reason_label = handshake_failure_reason_label(reason);
            const auto& counters = handshake_failure_sni_counters_[i];
            for (const auto& [sni, count] : counters.by_sni)
            {
                out.push_back({.reason = reason_label, .sni = sni, .count = count});
            }
            if (counters.others > 0)
            {
                out.push_back({.reason = reason_label, .sni = "others", .count = counters.others});    // GCOVR_EXCL_LINE
            }
        }
        std::ranges::sort(out,
                          [](const handshake_failure_sni_metric& a, const handshake_failure_sni_metric& b)
                          {
                              if (a.reason != b.reason)
                              {
                                  return a.reason < b.reason;
                              }
                              if (a.count != b.count)
                              {
                                  return a.count > b.count;
                              }
                              return a.sni < b.sni;
                          });
        return out;
    }

    static const char* handshake_failure_reason_label(const handshake_failure_reason reason)
    {
        switch (reason)
        {
            case handshake_failure_reason::kShortId:
                return "short_id";
            case handshake_failure_reason::kClockSkew:
                return "clock_skew";
            case handshake_failure_reason::kReplay:
                return "replay";
            case handshake_failure_reason::kCertVerify:
                return "cert_verify";
            default:
                return "unknown";
        }
    }

   private:
    static std::string_view normalize_sni_metric_key(const std::string_view sni)
    {
        if (sni.empty())
        {
            return "empty";    // GCOVR_EXCL_LINE
        }
        return sni;    // GCOVR_EXCL_LINE
    }

    struct transparent_string_hash
    {
        using is_transparent = void;

        [[nodiscard]] std::size_t operator()(const std::string_view value) const noexcept
        {
            return std::hash<std::string_view>{}(value);
        }
    };

    struct transparent_string_equal
    {
        using is_transparent = void;

        [[nodiscard]] bool operator()(const std::string_view lhs, const std::string_view rhs) const noexcept
        {
            return lhs == rhs;
        }
    };

    struct handshake_failure_sni_counter
    {
        std::unordered_map<std::string, std::uint64_t, transparent_string_hash, transparent_string_equal> by_sni;
        std::uint64_t others = 0;
    };

    static constexpr std::size_t kMaxTrackedSniPerReason = 100;

    std::atomic<std::uint64_t> active_connections_{0};
    std::atomic<std::uint64_t> total_connections_{0};
    std::atomic<std::uint64_t> active_mux_sessions_{0};
    std::atomic<std::uint64_t> bytes_read_{0};
    std::atomic<std::uint64_t> bytes_written_{0};
    std::atomic<std::uint64_t> auth_failures_{0};
    std::atomic<std::uint64_t> auth_short_id_failures_{0};
    std::atomic<std::uint64_t> auth_clock_skew_failures_{0};
    std::atomic<std::uint64_t> auth_replay_failures_{0};
    std::atomic<std::uint64_t> cert_verify_failures_{0};
    std::atomic<std::uint64_t> client_finished_failures_{0};
    std::atomic<std::uint64_t> fallback_rate_limited_{0};
    std::atomic<std::uint64_t> fallback_no_target_{0};
    std::atomic<std::uint64_t> fallback_resolve_failures_{0};
    std::atomic<std::uint64_t> fallback_resolve_timeouts_{0};
    std::atomic<std::uint64_t> fallback_resolve_errors_{0};
    std::atomic<std::uint64_t> fallback_connect_failures_{0};
    std::atomic<std::uint64_t> fallback_connect_timeouts_{0};
    std::atomic<std::uint64_t> fallback_connect_errors_{0};
    std::atomic<std::uint64_t> fallback_write_failures_{0};
    std::atomic<std::uint64_t> fallback_write_timeouts_{0};
    std::atomic<std::uint64_t> fallback_write_errors_{0};
    std::atomic<std::uint64_t> direct_upstream_resolve_timeouts_{0};
    std::atomic<std::uint64_t> direct_upstream_resolve_errors_{0};
    std::atomic<std::uint64_t> direct_upstream_connect_timeouts_{0};
    std::atomic<std::uint64_t> direct_upstream_connect_errors_{0};
    std::atomic<std::uint64_t> remote_session_resolve_timeouts_{0};
    std::atomic<std::uint64_t> remote_session_resolve_errors_{0};
    std::atomic<std::uint64_t> remote_session_connect_timeouts_{0};
    std::atomic<std::uint64_t> remote_session_connect_errors_{0};
    std::atomic<std::uint64_t> remote_udp_session_resolve_timeouts_{0};
    std::atomic<std::uint64_t> remote_udp_session_resolve_errors_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_resolve_timeouts_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_resolve_errors_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_connect_timeouts_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_connect_errors_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_handshake_timeouts_{0};
    std::atomic<std::uint64_t> client_tunnel_pool_handshake_errors_{0};
    std::atomic<std::uint64_t> routing_blocked_{0};
    std::atomic<std::uint64_t> connection_limit_rejected_{0};
    std::atomic<std::uint64_t> stream_limit_rejected_{0};
    std::atomic<std::uint64_t> monitor_auth_failures_{0};
    std::atomic<std::uint64_t> monitor_rate_limited_{0};
    std::atomic<std::uint64_t> tproxy_udp_dispatch_enqueued_{0};
    std::atomic<std::uint64_t> tproxy_udp_dispatch_dropped_{0};
    mutable std::mutex handshake_failure_sni_mu_;
    std::array<handshake_failure_sni_counter, static_cast<std::size_t>(handshake_failure_reason::kCount)> handshake_failure_sni_counters_{};

   private:
    statistics() = default;
    ~statistics() = default;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
};

}    // namespace mux

#endif
