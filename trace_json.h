#ifndef TRACE_JSON_H
#define TRACE_JSON_H

#include <string>

#include "trace_store.h"

namespace relay
{

[[nodiscard]] std::string dump_trace_event_json(const trace_event& event);
[[nodiscard]] std::string dump_trace_summary_json(const trace_session_summary& summary);
[[nodiscard]] std::string dump_trace_snapshot_json(const trace_session_snapshot& snapshot);
[[nodiscard]] std::string dump_trace_events_json(const trace_session_snapshot& snapshot);
[[nodiscard]] std::string dump_trace_events_json(uint64_t trace_id, const trace_event_page& page);
[[nodiscard]] std::string dump_trace_stats_json(const trace_stats& stats);
[[nodiscard]] std::string dump_trace_dashboard_json(const trace_dashboard_snapshot& snapshot);
[[nodiscard]] std::string dump_trace_list_json(const std::vector<trace_session_summary>& items, const trace_query& query);
[[nodiscard]] std::string dump_trace_event_page_json(const trace_event_page& page);

}    // namespace relay

#endif
