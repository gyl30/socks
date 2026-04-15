#ifndef TRACE_STORE_H
#define TRACE_STORE_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace relay
{

enum class trace_status
{
    kRunning,
    kSuccess,
    kFailed,
    kTimeout
};

enum class trace_result
{
    kOk,
    kFail,
    kTimeout,
    kSkip
};

enum class trace_stage
{
    kConnAccepted,
    kHandshakeStart,
    kHandshakeDone,
    kAuthStart,
    kAuthDone,
    kRequestStart,
    kRequestDone,
    kRouteDecideStart,
    kRouteDecideDone,
    kOutboundConnectStart,
    kOutboundConnectDone,
    kRelayStart,
    kDataSend,
    kDataRecv,
    kSessionClose,
    kSessionError,
    kFallbackStart,
    kFallbackDone
};

enum class trace_sort_field
{
    kStartTime,
    kLastEventTime,
    kDuration,
    kEventsCount
};

enum class trace_sort_order
{
    kAsc,
    kDesc
};

struct trace_event
{
    uint64_t event_id = 0;
    uint64_t trace_id = 0;
    uint32_t conn_id = 0;
    uint64_t ts_unix_ms = 0;
    uint64_t ts_mono_ns = 0;
    trace_stage stage = trace_stage::kConnAccepted;
    trace_result result = trace_result::kOk;
    std::string inbound_tag;
    std::string inbound_type;
    std::string outbound_tag;
    std::string outbound_type;
    std::string target_host;
    uint16_t target_port = 0;
    std::string local_host;
    uint16_t local_port = 0;
    std::string remote_host;
    uint16_t remote_port = 0;
    std::string route_type;
    std::string match_type;
    std::string match_value;
    uint64_t bytes_tx = 0;
    uint64_t bytes_rx = 0;
    uint32_t latency_ms = 0;
    int32_t error_code = 0;
    std::string error_message;
    std::map<std::string, std::string> extra;
};

struct trace_session_summary
{
    uint64_t trace_id = 0;
    uint32_t conn_id = 0;
    trace_status status = trace_status::kRunning;
    uint64_t first_event_unix_ms = 0;
    uint64_t last_event_unix_ms = 0;
    uint64_t first_event_mono_ns = 0;
    uint64_t last_event_mono_ns = 0;
    trace_stage last_stage = trace_stage::kConnAccepted;
    trace_result last_result = trace_result::kOk;
    std::string inbound_tag;
    std::string inbound_type;
    std::string outbound_tag;
    std::string outbound_type;
    std::string target_host;
    uint16_t target_port = 0;
    std::string local_host;
    uint16_t local_port = 0;
    std::string remote_host;
    uint16_t remote_port = 0;
    std::string route_type;
    std::string match_type;
    std::string match_value;
    uint64_t total_tx_bytes = 0;
    uint64_t total_rx_bytes = 0;
    uint64_t duration_ms = 0;
    uint64_t events_count = 0;
    int32_t final_error_code = 0;
    std::string final_error_message;
};

struct trace_session_snapshot
{
    trace_session_summary summary;
    std::vector<trace_event> events;
};

struct trace_query
{
    std::optional<trace_status> status;
    std::optional<std::string> inbound_tag;
    std::optional<std::string> outbound_tag;
    std::optional<std::string> target_host;
    std::optional<std::string> route_type;
    std::optional<std::string> match_type;
    std::size_t limit = 100;
    std::size_t offset = 0;
    trace_sort_field sort_field = trace_sort_field::kLastEventTime;
    trace_sort_order sort_order = trace_sort_order::kDesc;
};

struct trace_stats
{
    uint64_t total_sessions = 0;
    uint64_t running_sessions = 0;
    uint64_t success_sessions = 0;
    uint64_t failed_sessions = 0;
    uint64_t timeout_sessions = 0;
    uint64_t total_events = 0;
    uint64_t total_tx_bytes = 0;
    uint64_t total_rx_bytes = 0;
};

[[nodiscard]] std::string_view to_string(trace_status status);
[[nodiscard]] std::string_view to_string(trace_result result);
[[nodiscard]] std::string_view to_string(trace_stage stage);
[[nodiscard]] std::string_view to_string(trace_sort_field field);
[[nodiscard]] std::string_view to_string(trace_sort_order order);

[[nodiscard]] std::optional<trace_status> parse_trace_status(std::string_view value);
[[nodiscard]] std::optional<trace_result> parse_trace_result(std::string_view value);
[[nodiscard]] std::optional<trace_stage> parse_trace_stage(std::string_view value);
[[nodiscard]] std::optional<trace_sort_field> parse_trace_sort_field(std::string_view value);
[[nodiscard]] std::optional<trace_sort_order> parse_trace_sort_order(std::string_view value);

class trace_store
{
   public:
    [[nodiscard]] static trace_store& instance();

    trace_event record_event(trace_event event);

    [[nodiscard]] std::optional<trace_session_snapshot> get_trace(uint64_t trace_id) const;
    [[nodiscard]] std::vector<trace_session_summary> list_traces(const trace_query& query) const;
    [[nodiscard]] trace_stats get_stats() const;

   private:
    struct trace_session_state
    {
        trace_session_summary summary;
        std::vector<trace_event> events;
    };

   private:
    trace_store() = default;

    static uint64_t now_unix_ms();
    static uint64_t now_mono_ns();
    static void update_summary(trace_session_summary& summary, const trace_event& event);
    static bool match_query(const trace_session_summary& summary, const trace_query& query);
    static bool compare_summary(const trace_session_summary& lhs, const trace_session_summary& rhs, trace_sort_field field);

   private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, trace_session_state> sessions_;
    std::vector<uint64_t> insertion_order_;
    std::atomic<uint64_t> next_event_id_{1};
};

}    // namespace relay

#endif
