#ifndef TRACE_WEB_QUERY_H
#define TRACE_WEB_QUERY_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "trace_store.h"

namespace relay
{

using trace_web_query_params = std::unordered_map<std::string, std::string>;

[[nodiscard]] std::optional<trace_web_query_params> parse_trace_web_query_params(std::string_view query);
[[nodiscard]] bool parse_trace_web_size_t_param(const trace_web_query_params& params, const char* key, std::size_t& value);
[[nodiscard]] std::optional<uint64_t> parse_trace_web_trace_id_value(std::string_view text);
[[nodiscard]] const char* apply_trace_web_event_query_params(const trace_web_query_params& params, trace_event_query& query);
[[nodiscard]] const char* apply_trace_web_trace_query_params(const trace_web_query_params& params, trace_query& query);

}    // namespace relay

#endif
