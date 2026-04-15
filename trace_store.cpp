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

trace_stats trace_store::get_stats() const
{
    trace_stats stats;
    std::shared_lock lock(mutex_);
    stats.total_sessions = static_cast<uint64_t>(sessions_.size());
    for (const auto& [_, session] : sessions_)
    {
        stats.total_events += static_cast<uint64_t>(session.events.size());
        stats.total_tx_bytes += session.summary.total_tx_bytes;
        stats.total_rx_bytes += session.summary.total_rx_bytes;
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

}    // namespace relay
