#include "trace_store.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <utility>

namespace relay
{

namespace
{

constexpr uint64_t kTrafficHistoryWindowMs = 30ULL * 60ULL * 1000ULL;
constexpr uint64_t kTrafficSampleMinIntervalMs = 1000ULL;

void increment_counter(std::map<std::string, uint64_t>& counters, const std::string& key)
{
    if (key.empty())
    {
        return;
    }

    counters[key]++;
}

}    // namespace

std::string_view to_string(const trace_status status)
{
    switch (status)
    {
        case trace_status::kRunning:
            return "running";
        case trace_status::kSuccess:
            return "success";
        case trace_status::kFailed:
            return "failed";
        case trace_status::kTimeout:
            return "timeout";
    }
    return "unknown";
}

std::string_view to_string(const trace_result result)
{
    switch (result)
    {
        case trace_result::kOk:
            return "ok";
        case trace_result::kFail:
            return "fail";
        case trace_result::kTimeout:
            return "timeout";
        case trace_result::kSkip:
            return "skip";
    }
    return "unknown";
}

std::string_view to_string(const trace_stage stage)
{
    switch (stage)
    {
        case trace_stage::kConnAccepted:
            return "conn_accepted";
        case trace_stage::kHandshakeStart:
            return "handshake_start";
        case trace_stage::kHandshakeDone:
            return "handshake_done";
        case trace_stage::kAuthStart:
            return "auth_start";
        case trace_stage::kAuthDone:
            return "auth_done";
        case trace_stage::kRequestStart:
            return "request_start";
        case trace_stage::kRequestDone:
            return "request_done";
        case trace_stage::kRouteDecideStart:
            return "route_decide_start";
        case trace_stage::kRouteDecideDone:
            return "route_decide_done";
        case trace_stage::kOutboundConnectStart:
            return "outbound_connect_start";
        case trace_stage::kOutboundConnectDone:
            return "outbound_connect_done";
        case trace_stage::kRelayStart:
            return "relay_start";
        case trace_stage::kDataSend:
            return "data_send";
        case trace_stage::kDataRecv:
            return "data_recv";
        case trace_stage::kSessionClose:
            return "session_close";
        case trace_stage::kSessionError:
            return "session_error";
        case trace_stage::kFallbackStart:
            return "fallback_start";
        case trace_stage::kFallbackDone:
            return "fallback_done";
    }
    return "unknown";
}

std::string_view to_string(const trace_sort_field field)
{
    switch (field)
    {
        case trace_sort_field::kStartTime:
            return "start_time";
        case trace_sort_field::kLastEventTime:
            return "last_event_time";
        case trace_sort_field::kDuration:
            return "duration";
        case trace_sort_field::kEventsCount:
            return "events_count";
    }
    return "unknown";
}

std::string_view to_string(const trace_sort_order order)
{
    switch (order)
    {
        case trace_sort_order::kAsc:
            return "asc";
        case trace_sort_order::kDesc:
            return "desc";
    }
    return "unknown";
}

std::optional<trace_status> parse_trace_status(const std::string_view value)
{
    if (value == "running")
    {
        return trace_status::kRunning;
    }
    if (value == "success")
    {
        return trace_status::kSuccess;
    }
    if (value == "failed")
    {
        return trace_status::kFailed;
    }
    if (value == "timeout")
    {
        return trace_status::kTimeout;
    }
    return std::nullopt;
}

std::optional<trace_result> parse_trace_result(const std::string_view value)
{
    if (value == "ok")
    {
        return trace_result::kOk;
    }
    if (value == "fail")
    {
        return trace_result::kFail;
    }
    if (value == "timeout")
    {
        return trace_result::kTimeout;
    }
    if (value == "skip")
    {
        return trace_result::kSkip;
    }
    return std::nullopt;
}

std::optional<trace_stage> parse_trace_stage(const std::string_view value)
{
    if (value == "conn_accepted")
    {
        return trace_stage::kConnAccepted;
    }
    if (value == "handshake_start")
    {
        return trace_stage::kHandshakeStart;
    }
    if (value == "handshake_done")
    {
        return trace_stage::kHandshakeDone;
    }
    if (value == "auth_start")
    {
        return trace_stage::kAuthStart;
    }
    if (value == "auth_done")
    {
        return trace_stage::kAuthDone;
    }
    if (value == "request_start")
    {
        return trace_stage::kRequestStart;
    }
    if (value == "request_done")
    {
        return trace_stage::kRequestDone;
    }
    if (value == "route_decide_start")
    {
        return trace_stage::kRouteDecideStart;
    }
    if (value == "route_decide_done")
    {
        return trace_stage::kRouteDecideDone;
    }
    if (value == "outbound_connect_start")
    {
        return trace_stage::kOutboundConnectStart;
    }
    if (value == "outbound_connect_done")
    {
        return trace_stage::kOutboundConnectDone;
    }
    if (value == "relay_start")
    {
        return trace_stage::kRelayStart;
    }
    if (value == "data_send")
    {
        return trace_stage::kDataSend;
    }
    if (value == "data_recv")
    {
        return trace_stage::kDataRecv;
    }
    if (value == "session_close")
    {
        return trace_stage::kSessionClose;
    }
    if (value == "session_error")
    {
        return trace_stage::kSessionError;
    }
    if (value == "fallback_start")
    {
        return trace_stage::kFallbackStart;
    }
    if (value == "fallback_done")
    {
        return trace_stage::kFallbackDone;
    }
    return std::nullopt;
}

std::optional<trace_sort_field> parse_trace_sort_field(const std::string_view value)
{
    if (value == "start_time")
    {
        return trace_sort_field::kStartTime;
    }
    if (value == "last_event_time")
    {
        return trace_sort_field::kLastEventTime;
    }
    if (value == "duration")
    {
        return trace_sort_field::kDuration;
    }
    if (value == "events_count")
    {
        return trace_sort_field::kEventsCount;
    }
    return std::nullopt;
}

std::optional<trace_sort_order> parse_trace_sort_order(const std::string_view value)
{
    if (value == "asc")
    {
        return trace_sort_order::kAsc;
    }
    if (value == "desc")
    {
        return trace_sort_order::kDesc;
    }
    return std::nullopt;
}

trace_store& trace_store::instance()
{
    static trace_store store;
    return store;
}

void trace_store::add_live_tx_bytes(const uint64_t bytes)
{
    if (bytes == 0)
    {
        return;
    }
    live_total_tx_bytes_.fetch_add(bytes, std::memory_order_relaxed);
}

void trace_store::add_live_rx_bytes(const uint64_t bytes)
{
    if (bytes == 0)
    {
        return;
    }
    live_total_rx_bytes_.fetch_add(bytes, std::memory_order_relaxed);
}

uint64_t trace_store::now_unix_ms()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

uint64_t trace_store::now_mono_ns()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}

void update_lifecycle(trace_lifecycle_summary& lifecycle, const trace_stage stage)
{
    switch (stage)
    {
        case trace_stage::kConnAccepted:
            lifecycle.conn_accepted = true;
            break;
        case trace_stage::kHandshakeStart:
            lifecycle.handshake_start = true;
            break;
        case trace_stage::kHandshakeDone:
            lifecycle.handshake_done = true;
            break;
        case trace_stage::kAuthStart:
            lifecycle.auth_start = true;
            break;
        case trace_stage::kAuthDone:
            lifecycle.auth_done = true;
            break;
        case trace_stage::kRequestStart:
            lifecycle.request_start = true;
            break;
        case trace_stage::kRequestDone:
            lifecycle.request_done = true;
            break;
        case trace_stage::kRouteDecideStart:
            lifecycle.route_decide_start = true;
            break;
        case trace_stage::kRouteDecideDone:
            lifecycle.route_decide_done = true;
            break;
        case trace_stage::kOutboundConnectStart:
            lifecycle.outbound_connect_start = true;
            break;
        case trace_stage::kOutboundConnectDone:
            lifecycle.outbound_connect_done = true;
            break;
        case trace_stage::kRelayStart:
            lifecycle.relay_start = true;
            break;
        case trace_stage::kDataSend:
            lifecycle.data_send = true;
            break;
        case trace_stage::kDataRecv:
            lifecycle.data_recv = true;
            break;
        case trace_stage::kSessionClose:
            lifecycle.session_close = true;
            break;
        case trace_stage::kSessionError:
            lifecycle.session_error = true;
            break;
        case trace_stage::kFallbackStart:
            lifecycle.fallback_start = true;
            break;
        case trace_stage::kFallbackDone:
            lifecycle.fallback_done = true;
            break;
    }
}

void trace_store::update_summary(trace_session_summary& summary, const trace_event& event)
{
    if (summary.trace_id == 0)
    {
        summary.trace_id = event.trace_id;
    }
    if (summary.conn_id == 0 && event.conn_id != 0)
    {
        summary.conn_id = event.conn_id;
    }
    if (summary.first_event_unix_ms == 0)
    {
        summary.first_event_unix_ms = event.ts_unix_ms;
        summary.first_event_mono_ns = event.ts_mono_ns;
    }
    summary.last_event_unix_ms = event.ts_unix_ms;
    summary.last_event_mono_ns = event.ts_mono_ns;
    summary.last_stage = event.stage;
    summary.last_result = event.result;
    summary.events_count++;
    update_lifecycle(summary.lifecycle, event.stage);
    summary.stage_counts[std::string(to_string(event.stage))]++;

    if (!event.inbound_tag.empty() && summary.inbound_tag.empty())
    {
        summary.inbound_tag = event.inbound_tag;
    }
    if (!event.inbound_type.empty() && summary.inbound_type.empty())
    {
        summary.inbound_type = event.inbound_type;
    }
    if (!event.outbound_tag.empty() && summary.outbound_tag.empty())
    {
        summary.outbound_tag = event.outbound_tag;
    }
    if (!event.outbound_type.empty() && summary.outbound_type.empty())
    {
        summary.outbound_type = event.outbound_type;
    }
    if (!event.target_host.empty() && summary.target_host.empty())
    {
        summary.target_host = event.target_host;
        summary.target_port = event.target_port;
    }
    if (!event.resolved_target_host.empty() && (summary.resolved_target_host.empty() || summary.target_host == event.target_host))
    {
        summary.resolved_target_host = event.resolved_target_host;
        summary.resolved_target_port = event.resolved_target_port;
    }
    if (!event.local_host.empty() && summary.local_host.empty())
    {
        summary.local_host = event.local_host;
        summary.local_port = event.local_port;
    }
    if (!event.remote_host.empty() && summary.remote_host.empty())
    {
        summary.remote_host = event.remote_host;
        summary.remote_port = event.remote_port;
    }
    if (!event.route_type.empty() && summary.route_type.empty())
    {
        summary.route_type = event.route_type;
    }
    if (!event.match_type.empty() && summary.match_type.empty())
    {
        summary.match_type = event.match_type;
    }
    if (!event.match_value.empty() && summary.match_value.empty())
    {
        summary.match_value = event.match_value;
    }

    if (event.bytes_tx != 0)
    {
        summary.total_tx_bytes += event.bytes_tx;
    }
    if (event.bytes_rx != 0)
    {
        summary.total_rx_bytes += event.bytes_rx;
    }
    summary.duration_ms = summary.last_event_mono_ns >= summary.first_event_mono_ns
                              ? static_cast<uint64_t>(
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::nanoseconds(summary.last_event_mono_ns - summary.first_event_mono_ns))
                                        .count())
                              : 0;

    if (event.result == trace_result::kFail)
    {
        summary.status = trace_status::kFailed;
        summary.final_error_code = event.error_code;
        summary.final_error_message = event.error_message;
        return;
    }
    if (event.result == trace_result::kTimeout)
    {
        summary.status = trace_status::kTimeout;
        summary.final_error_code = event.error_code;
        summary.final_error_message = event.error_message;
        return;
    }
    if (event.stage == trace_stage::kSessionError)
    {
        summary.status = trace_status::kFailed;
        summary.final_error_code = event.error_code;
        summary.final_error_message = event.error_message;
        return;
    }
    if (event.stage == trace_stage::kSessionClose && event.result == trace_result::kOk && summary.status == trace_status::kRunning)
    {
        summary.status = trace_status::kSuccess;
    }
}

bool trace_store::match_query(const trace_session_summary& summary, const trace_query& query)
{
    if (query.status.has_value() && summary.status != *query.status)
    {
        return false;
    }
    if (query.inbound_tag.has_value() && summary.inbound_tag != *query.inbound_tag)
    {
        return false;
    }
    if (query.outbound_tag.has_value() && summary.outbound_tag != *query.outbound_tag)
    {
        return false;
    }
    if (query.target_host.has_value() && summary.target_host != *query.target_host)
    {
        return false;
    }
    if (query.route_type.has_value() && summary.route_type != *query.route_type)
    {
        return false;
    }
    if (query.match_type.has_value() && summary.match_type != *query.match_type)
    {
        return false;
    }
    return true;
}

bool trace_store::match_query(const trace_event& event, const trace_event_query& query)
{
    if (query.trace_id.has_value() && event.trace_id != *query.trace_id)
    {
        return false;
    }
    if (query.stage.has_value() && event.stage != *query.stage)
    {
        return false;
    }
    if (query.result.has_value() && event.result != *query.result)
    {
        return false;
    }
    if (query.inbound_tag.has_value() && event.inbound_tag != *query.inbound_tag)
    {
        return false;
    }
    if (query.outbound_tag.has_value() && event.outbound_tag != *query.outbound_tag)
    {
        return false;
    }
    if (query.target_host.has_value() && event.target_host != *query.target_host)
    {
        return false;
    }
    return true;
}

bool trace_store::compare_summary(const trace_session_summary& lhs, const trace_session_summary& rhs, const trace_sort_field field)
{
    switch (field)
    {
        case trace_sort_field::kStartTime:
            return lhs.first_event_mono_ns < rhs.first_event_mono_ns;
        case trace_sort_field::kLastEventTime:
            return lhs.last_event_mono_ns < rhs.last_event_mono_ns;
        case trace_sort_field::kDuration:
            return lhs.duration_ms < rhs.duration_ms;
        case trace_sort_field::kEventsCount:
            return lhs.events_count < rhs.events_count;
    }
    return lhs.trace_id < rhs.trace_id;
}

trace_event trace_store::record_event(trace_event event)
{
    event.event_id = next_event_id_.fetch_add(1, std::memory_order_relaxed);
    event.ts_unix_ms = now_unix_ms();
    event.ts_mono_ns = now_mono_ns();

    std::unique_lock lock(mutex_);
    auto [it, inserted] = sessions_.try_emplace(event.trace_id);
    if (inserted)
    {
        insertion_order_.push_back(event.trace_id);
    }
    auto& session = it->second;
    session.events.push_back(event);
    update_summary(session.summary, event);
    return event;
}

std::optional<trace_session_snapshot> trace_store::get_trace(const uint64_t trace_id) const
{
    std::shared_lock lock(mutex_);
    const auto it = sessions_.find(trace_id);
    if (it == sessions_.end())
    {
        return std::nullopt;
    }

    trace_session_snapshot snapshot;
    snapshot.summary = it->second.summary;
    snapshot.events = it->second.events;
    return snapshot;
}

std::vector<trace_session_summary> trace_store::list_traces(const trace_query& query) const
{
    std::vector<trace_session_summary> items;
    std::shared_lock lock(mutex_);
    items.reserve(sessions_.size());
    for (const auto trace_id : insertion_order_)
    {
        const auto it = sessions_.find(trace_id);
        if (it == sessions_.end())
        {
            continue;
        }
        if (!match_query(it->second.summary, query))
        {
            continue;
        }
        items.push_back(it->second.summary);
    }

    std::sort(
        items.begin(),
        items.end(),
        [&query](const trace_session_summary& lhs, const trace_session_summary& rhs)
        {
            const bool less = compare_summary(lhs, rhs, query.sort_field);
            const bool greater = compare_summary(rhs, lhs, query.sort_field);
            if (less == greater)
            {
                return lhs.trace_id < rhs.trace_id;
            }
            return query.sort_order == trace_sort_order::kAsc ? less : greater;
        });

    if (query.offset >= items.size())
    {
        return {};
    }

    const std::size_t begin_index = query.offset;
    const std::size_t end_index = std::min(items.size(), begin_index + query.limit);
    return std::vector<trace_session_summary>(items.begin() + static_cast<std::ptrdiff_t>(begin_index),
                                              items.begin() + static_cast<std::ptrdiff_t>(end_index));
}

trace_event_page trace_store::list_events(const trace_event_query& query) const
{
    trace_event_page page;
    page.query = query;

    std::vector<trace_event> items;
    std::shared_lock lock(mutex_);
    if (query.trace_id.has_value())
    {
        const auto it = sessions_.find(*query.trace_id);
        if (it == sessions_.end())
        {
            return page;
        }

        items.reserve(it->second.events.size());
        for (const auto& event : it->second.events)
        {
            if (!match_query(event, query))
            {
                continue;
            }
            items.push_back(event);
        }
    }
    else
    {
        items.reserve(insertion_order_.size() * 4);
        for (const auto trace_id : insertion_order_)
        {
            const auto it = sessions_.find(trace_id);
            if (it == sessions_.end())
            {
                continue;
            }
            for (const auto& event : it->second.events)
            {
                if (!match_query(event, query))
                {
                    continue;
                }
                items.push_back(event);
            }
        }
    }

    std::sort(
        items.begin(),
        items.end(),
        [&query](const trace_event& lhs, const trace_event& rhs)
        {
            if (lhs.event_id == rhs.event_id)
            {
                return lhs.trace_id < rhs.trace_id;
            }

            if (query.sort_order == trace_sort_order::kAsc)
            {
                return lhs.event_id < rhs.event_id;
            }
            return lhs.event_id > rhs.event_id;
        });

    page.total = static_cast<uint64_t>(items.size());
    if (query.offset >= items.size())
    {
        return page;
    }

    const std::size_t begin_index = query.offset;
    const std::size_t end_index = std::min(items.size(), begin_index + query.limit);
    page.items = std::vector<trace_event>(items.begin() + static_cast<std::ptrdiff_t>(begin_index),
                                          items.begin() + static_cast<std::ptrdiff_t>(end_index));
    return page;
}

trace_stats trace_store::get_stats() const
{
    trace_stats stats;
    std::shared_lock lock(mutex_);
    stats.total_sessions = static_cast<uint64_t>(sessions_.size());
    stats.total_tx_bytes = live_total_tx_bytes_.load(std::memory_order_relaxed);
    stats.total_rx_bytes = live_total_rx_bytes_.load(std::memory_order_relaxed);
    for (const auto& [_, session] : sessions_)
    {
        stats.total_events += static_cast<uint64_t>(session.events.size());
        switch (session.summary.status)
        {
            case trace_status::kRunning:
                stats.running_sessions++;
                break;
            case trace_status::kSuccess:
                stats.success_sessions++;
                break;
            case trace_status::kFailed:
                stats.failed_sessions++;
                break;
            case trace_status::kTimeout:
                stats.timeout_sessions++;
                break;
        }
    }
    return stats;
}

void trace_store::append_traffic_sample_locked(const uint64_t now_unix_ms, const trace_stats& stats) const
{
    if (!traffic_history_.empty() && now_unix_ms <= traffic_history_.back().ts_unix_ms + kTrafficSampleMinIntervalMs)
    {
        traffic_history_.back().ts_unix_ms = now_unix_ms;
        traffic_history_.back().total_tx_bytes = stats.total_tx_bytes;
        traffic_history_.back().total_rx_bytes = stats.total_rx_bytes;
    }
    else
    {
        traffic_history_.push_back(trace_traffic_sample{
            .ts_unix_ms = now_unix_ms,
            .total_tx_bytes = stats.total_tx_bytes,
            .total_rx_bytes = stats.total_rx_bytes,
        });
    }

    const auto cutoff = (now_unix_ms > kTrafficHistoryWindowMs) ? (now_unix_ms - kTrafficHistoryWindowMs) : 0ULL;
    while (traffic_history_.size() > 1 && traffic_history_.front().ts_unix_ms < cutoff)
    {
        traffic_history_.pop_front();
    }
}

trace_dashboard_snapshot trace_store::get_dashboard() const
{
    trace_dashboard_snapshot snapshot;
    std::unique_lock lock(mutex_);
    snapshot.stats.total_sessions = static_cast<uint64_t>(sessions_.size());
    snapshot.stats.total_tx_bytes = live_total_tx_bytes_.load(std::memory_order_relaxed);
    snapshot.stats.total_rx_bytes = live_total_rx_bytes_.load(std::memory_order_relaxed);
    for (const auto& [_, session] : sessions_)
    {
        const auto& summary = session.summary;
        snapshot.stats.total_events += static_cast<uint64_t>(session.events.size());
        snapshot.latest_event_unix_ms = std::max(snapshot.latest_event_unix_ms, summary.last_event_unix_ms);
        snapshot.status_counts[std::string(to_string(summary.status))]++;
        increment_counter(snapshot.inbound_tag_counts, summary.inbound_tag);
        increment_counter(snapshot.inbound_type_counts, summary.inbound_type);
        increment_counter(snapshot.outbound_tag_counts, summary.outbound_tag);
        increment_counter(snapshot.outbound_type_counts, summary.outbound_type);
        increment_counter(snapshot.route_type_counts, summary.route_type);
        increment_counter(snapshot.match_type_counts, summary.match_type);
        for (const auto& [stage, count] : summary.stage_counts)
        {
            snapshot.stage_event_counts[stage] += count;
        }

        switch (summary.status)
        {
            case trace_status::kRunning:
                snapshot.stats.running_sessions++;
                break;
            case trace_status::kSuccess:
                snapshot.stats.success_sessions++;
                break;
            case trace_status::kFailed:
                snapshot.stats.failed_sessions++;
                break;
            case trace_status::kTimeout:
                snapshot.stats.timeout_sessions++;
                break;
        }
    }
    append_traffic_sample_locked(now_unix_ms(), snapshot.stats);
    snapshot.traffic_history.assign(traffic_history_.begin(), traffic_history_.end());
    return snapshot;
}

}    // namespace relay
