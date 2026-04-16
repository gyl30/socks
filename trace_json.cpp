#include "trace_json.h"

#include <cstdio>
#include <string_view>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

namespace relay
{

namespace
{

[[nodiscard]] std::string trace_id_hex(const uint64_t trace_id)
{
    char buffer[17] = {0};
    std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(trace_id));
    return buffer;
}

template <typename Writer>
void write_string_field(Writer& writer, const char* key, const std::string& value)
{
    writer.Key(key);
    writer.String(value.c_str(), static_cast<rapidjson::SizeType>(value.size()));
}

template <typename Writer>
void write_view_field(Writer& writer, const char* key, std::string_view value)
{
    writer.Key(key);
    writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
}

template <typename Writer>
void write_extra_map(Writer& writer, const std::map<std::string, std::string>& extra)
{
    writer.Key("extra");
    writer.StartObject();
    for (const auto& [key, value] : extra)
    {
        writer.Key(key.c_str());
        writer.String(value.c_str(), static_cast<rapidjson::SizeType>(value.size()));
    }
    writer.EndObject();
}

template <typename Writer>
void write_stage_counts(Writer& writer, const std::map<std::string, uint64_t>& stage_counts)
{
    writer.Key("stage_counts");
    writer.StartObject();
    for (const auto& [stage, count] : stage_counts)
    {
        writer.Key(stage.c_str());
        writer.Uint64(count);
    }
    writer.EndObject();
}

template <typename Writer>
void write_counts_map(Writer& writer, const char* key, const std::map<std::string, uint64_t>& counts)
{
    writer.Key(key);
    writer.StartObject();
    for (const auto& [name, count] : counts)
    {
        writer.Key(name.c_str());
        writer.Uint64(count);
    }
    writer.EndObject();
}

template <typename Writer>
void write_lifecycle_summary(Writer& writer, const trace_lifecycle_summary& lifecycle)
{
    writer.Key("lifecycle");
    writer.StartObject();
    writer.Key("conn_accepted");
    writer.Bool(lifecycle.conn_accepted);
    writer.Key("handshake_start");
    writer.Bool(lifecycle.handshake_start);
    writer.Key("handshake_done");
    writer.Bool(lifecycle.handshake_done);
    writer.Key("auth_start");
    writer.Bool(lifecycle.auth_start);
    writer.Key("auth_done");
    writer.Bool(lifecycle.auth_done);
    writer.Key("request_start");
    writer.Bool(lifecycle.request_start);
    writer.Key("request_done");
    writer.Bool(lifecycle.request_done);
    writer.Key("route_decide_start");
    writer.Bool(lifecycle.route_decide_start);
    writer.Key("route_decide_done");
    writer.Bool(lifecycle.route_decide_done);
    writer.Key("outbound_connect_start");
    writer.Bool(lifecycle.outbound_connect_start);
    writer.Key("outbound_connect_done");
    writer.Bool(lifecycle.outbound_connect_done);
    writer.Key("relay_start");
    writer.Bool(lifecycle.relay_start);
    writer.Key("data_send");
    writer.Bool(lifecycle.data_send);
    writer.Key("data_recv");
    writer.Bool(lifecycle.data_recv);
    writer.Key("session_close");
    writer.Bool(lifecycle.session_close);
    writer.Key("session_error");
    writer.Bool(lifecycle.session_error);
    writer.Key("fallback_start");
    writer.Bool(lifecycle.fallback_start);
    writer.Key("fallback_done");
    writer.Bool(lifecycle.fallback_done);
    writer.EndObject();
}

template <typename Writer>
void write_trace_event(Writer& writer, const trace_event& event)
{
    writer.StartObject();
    write_string_field(writer, "trace_id", trace_id_hex(event.trace_id));
    writer.Key("event_id");
    writer.Uint64(event.event_id);
    writer.Key("conn_id");
    writer.Uint(event.conn_id);
    writer.Key("ts_unix_ms");
    writer.Uint64(event.ts_unix_ms);
    writer.Key("ts_mono_ns");
    writer.Uint64(event.ts_mono_ns);
    write_view_field(writer, "stage", to_string(event.stage));
    write_view_field(writer, "result", to_string(event.result));
    write_string_field(writer, "inbound_tag", event.inbound_tag);
    write_string_field(writer, "inbound_type", event.inbound_type);
    write_string_field(writer, "outbound_tag", event.outbound_tag);
    write_string_field(writer, "outbound_type", event.outbound_type);
    write_string_field(writer, "target_host", event.target_host);
    writer.Key("target_port");
    writer.Uint(event.target_port);
    write_string_field(writer, "resolved_target_host", event.resolved_target_host);
    writer.Key("resolved_target_port");
    writer.Uint(event.resolved_target_port);
    write_string_field(writer, "local_host", event.local_host);
    writer.Key("local_port");
    writer.Uint(event.local_port);
    write_string_field(writer, "remote_host", event.remote_host);
    writer.Key("remote_port");
    writer.Uint(event.remote_port);
    write_string_field(writer, "route_type", event.route_type);
    write_string_field(writer, "match_type", event.match_type);
    write_string_field(writer, "match_value", event.match_value);
    writer.Key("bytes_tx");
    writer.Uint64(event.bytes_tx);
    writer.Key("bytes_rx");
    writer.Uint64(event.bytes_rx);
    writer.Key("latency_ms");
    writer.Uint(event.latency_ms);
    writer.Key("error_code");
    writer.Int(event.error_code);
    write_string_field(writer, "error_message", event.error_message);
    write_extra_map(writer, event.extra);
    writer.EndObject();
}

template <typename Writer>
void write_trace_summary(Writer& writer, const trace_session_summary& summary)
{
    writer.StartObject();
    write_string_field(writer, "trace_id", trace_id_hex(summary.trace_id));
    writer.Key("conn_id");
    writer.Uint(summary.conn_id);
    write_view_field(writer, "status", to_string(summary.status));
    writer.Key("first_event_unix_ms");
    writer.Uint64(summary.first_event_unix_ms);
    writer.Key("last_event_unix_ms");
    writer.Uint64(summary.last_event_unix_ms);
    writer.Key("first_event_mono_ns");
    writer.Uint64(summary.first_event_mono_ns);
    writer.Key("last_event_mono_ns");
    writer.Uint64(summary.last_event_mono_ns);
    write_view_field(writer, "last_stage", to_string(summary.last_stage));
    write_view_field(writer, "last_result", to_string(summary.last_result));
    write_string_field(writer, "inbound_tag", summary.inbound_tag);
    write_string_field(writer, "inbound_type", summary.inbound_type);
    write_string_field(writer, "outbound_tag", summary.outbound_tag);
    write_string_field(writer, "outbound_type", summary.outbound_type);
    write_string_field(writer, "target_host", summary.target_host);
    writer.Key("target_port");
    writer.Uint(summary.target_port);
    write_string_field(writer, "resolved_target_host", summary.resolved_target_host);
    writer.Key("resolved_target_port");
    writer.Uint(summary.resolved_target_port);
    write_string_field(writer, "local_host", summary.local_host);
    writer.Key("local_port");
    writer.Uint(summary.local_port);
    write_string_field(writer, "remote_host", summary.remote_host);
    writer.Key("remote_port");
    writer.Uint(summary.remote_port);
    write_string_field(writer, "route_type", summary.route_type);
    write_string_field(writer, "match_type", summary.match_type);
    write_string_field(writer, "match_value", summary.match_value);
    writer.Key("total_tx_bytes");
    writer.Uint64(summary.total_tx_bytes);
    writer.Key("total_rx_bytes");
    writer.Uint64(summary.total_rx_bytes);
    writer.Key("duration_ms");
    writer.Uint64(summary.duration_ms);
    writer.Key("events_count");
    writer.Uint64(summary.events_count);
    writer.Key("final_error_code");
    writer.Int(summary.final_error_code);
    write_string_field(writer, "final_error_message", summary.final_error_message);
    write_lifecycle_summary(writer, summary.lifecycle);
    write_stage_counts(writer, summary.stage_counts);
    writer.EndObject();
}

template <typename Writer>
void write_trace_stats(Writer& writer, const trace_stats& stats)
{
    writer.StartObject();
    writer.Key("total_sessions");
    writer.Uint64(stats.total_sessions);
    writer.Key("running_sessions");
    writer.Uint64(stats.running_sessions);
    writer.Key("success_sessions");
    writer.Uint64(stats.success_sessions);
    writer.Key("failed_sessions");
    writer.Uint64(stats.failed_sessions);
    writer.Key("timeout_sessions");
    writer.Uint64(stats.timeout_sessions);
    writer.Key("total_events");
    writer.Uint64(stats.total_events);
    writer.Key("total_tx_bytes");
    writer.Uint64(stats.total_tx_bytes);
    writer.Key("total_rx_bytes");
    writer.Uint64(stats.total_rx_bytes);
    writer.EndObject();
}

template <typename Writer>
void write_trace_traffic_history(Writer& writer, const std::vector<trace_traffic_sample>& traffic_history)
{
    writer.Key("traffic_history");
    writer.StartArray();
    for (const auto& sample : traffic_history)
    {
        writer.StartObject();
        writer.Key("ts_unix_ms");
        writer.Uint64(sample.ts_unix_ms);
        writer.Key("total_tx_bytes");
        writer.Uint64(sample.total_tx_bytes);
        writer.Key("total_rx_bytes");
        writer.Uint64(sample.total_rx_bytes);
        writer.EndObject();
    }
    writer.EndArray();
}

template <typename Writer>
void write_trace_dashboard(Writer& writer, const trace_dashboard_snapshot& snapshot)
{
    writer.StartObject();
    writer.Key("stats");
    write_trace_stats(writer, snapshot.stats);
    writer.Key("latest_event_unix_ms");
    writer.Uint64(snapshot.latest_event_unix_ms);
    write_trace_traffic_history(writer, snapshot.traffic_history);
    write_counts_map(writer, "status_counts", snapshot.status_counts);
    write_counts_map(writer, "inbound_tag_counts", snapshot.inbound_tag_counts);
    write_counts_map(writer, "inbound_type_counts", snapshot.inbound_type_counts);
    write_counts_map(writer, "outbound_tag_counts", snapshot.outbound_tag_counts);
    write_counts_map(writer, "outbound_type_counts", snapshot.outbound_type_counts);
    write_counts_map(writer, "route_type_counts", snapshot.route_type_counts);
    write_counts_map(writer, "match_type_counts", snapshot.match_type_counts);
    write_counts_map(writer, "stage_event_counts", snapshot.stage_event_counts);
    writer.EndObject();
}

template <typename Writer>
void write_trace_query(Writer& writer, const trace_query& query)
{
    writer.StartObject();
    if (query.status.has_value())
    {
        write_view_field(writer, "status", to_string(*query.status));
    }
    if (query.inbound_tag.has_value())
    {
        write_string_field(writer, "inbound_tag", *query.inbound_tag);
    }
    if (query.outbound_tag.has_value())
    {
        write_string_field(writer, "outbound_tag", *query.outbound_tag);
    }
    if (query.target_host.has_value())
    {
        write_string_field(writer, "target_host", *query.target_host);
    }
    if (query.route_type.has_value())
    {
        write_string_field(writer, "route_type", *query.route_type);
    }
    if (query.match_type.has_value())
    {
        write_string_field(writer, "match_type", *query.match_type);
    }
    writer.Key("limit");
    writer.Uint64(query.limit);
    writer.Key("offset");
    writer.Uint64(query.offset);
    write_view_field(writer, "sort_field", to_string(query.sort_field));
    write_view_field(writer, "sort_order", to_string(query.sort_order));
    writer.EndObject();
}

template <typename Writer>
void write_trace_event_query(Writer& writer, const trace_event_query& query)
{
    writer.StartObject();
    if (query.trace_id.has_value())
    {
        write_string_field(writer, "trace_id", trace_id_hex(*query.trace_id));
    }
    if (query.stage.has_value())
    {
        write_view_field(writer, "stage", to_string(*query.stage));
    }
    if (query.result.has_value())
    {
        write_view_field(writer, "result", to_string(*query.result));
    }
    if (query.inbound_tag.has_value())
    {
        write_string_field(writer, "inbound_tag", *query.inbound_tag);
    }
    if (query.outbound_tag.has_value())
    {
        write_string_field(writer, "outbound_tag", *query.outbound_tag);
    }
    if (query.target_host.has_value())
    {
        write_string_field(writer, "target_host", *query.target_host);
    }
    writer.Key("limit");
    writer.Uint64(query.limit);
    writer.Key("offset");
    writer.Uint64(query.offset);
    write_view_field(writer, "sort_order", to_string(query.sort_order));
    writer.EndObject();
}

}    // namespace

std::string dump_trace_event_json(const trace_event& event)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    write_trace_event(writer, event);
    return buffer.GetString();
}

std::string dump_trace_summary_json(const trace_session_summary& summary)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    write_trace_summary(writer, summary);
    return buffer.GetString();
}

std::string dump_trace_snapshot_json(const trace_session_snapshot& snapshot)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("summary");
    write_trace_summary(writer, snapshot.summary);
    writer.Key("events");
    writer.StartArray();
    for (const auto& event : snapshot.events)
    {
        write_trace_event(writer, event);
    }
    writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

std::string dump_trace_events_json(const trace_session_snapshot& snapshot)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    const auto trace_id = trace_id_hex(snapshot.summary.trace_id);
    writer.StartObject();
    writer.Key("trace_id");
    writer.String(trace_id.c_str(), static_cast<rapidjson::SizeType>(trace_id.size()));
    writer.Key("count");
    writer.Uint64(snapshot.events.size());
    writer.Key("events");
    writer.StartArray();
    for (const auto& event : snapshot.events)
    {
        write_trace_event(writer, event);
    }
    writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

std::string dump_trace_events_json(const uint64_t trace_id, const trace_event_page& page)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    const auto trace_id_text = trace_id_hex(trace_id);
    writer.StartObject();
    writer.Key("trace_id");
    writer.String(trace_id_text.c_str(), static_cast<rapidjson::SizeType>(trace_id_text.size()));
    writer.Key("query");
    write_trace_event_query(writer, page.query);
    writer.Key("total");
    writer.Uint64(page.total);
    writer.Key("count");
    writer.Uint64(page.items.size());
    writer.Key("events");
    writer.StartArray();
    for (const auto& item : page.items)
    {
        write_trace_event(writer, item);
    }
    writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

std::string dump_trace_stats_json(const trace_stats& stats)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    write_trace_stats(writer, stats);
    return buffer.GetString();
}

std::string dump_trace_dashboard_json(const trace_dashboard_snapshot& snapshot)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    write_trace_dashboard(writer, snapshot);
    return buffer.GetString();
}

std::string dump_trace_list_json(const std::vector<trace_session_summary>& items, const trace_query& query)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("query");
    write_trace_query(writer, query);
    writer.Key("count");
    writer.Uint64(items.size());
    writer.Key("items");
    writer.StartArray();
    for (const auto& item : items)
    {
        write_trace_summary(writer, item);
    }
    writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

std::string dump_trace_event_page_json(const trace_event_page& page)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("query");
    write_trace_event_query(writer, page.query);
    writer.Key("total");
    writer.Uint64(page.total);
    writer.Key("count");
    writer.Uint64(page.items.size());
    writer.Key("items");
    writer.StartArray();
    for (const auto& item : page.items)
    {
        write_trace_event(writer, item);
    }
    writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

}    // namespace relay
