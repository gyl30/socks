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

std::string dump_trace_stats_json(const trace_stats& stats)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    write_trace_stats(writer, stats);
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

}    // namespace relay
