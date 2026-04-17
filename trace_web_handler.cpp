#include "trace_web_handler.h"

#include <optional>

#include "trace_json.h"
#include "trace_store.h"
#include "trace_web_dashboard_page.h"
#include "trace_web_query.h"

namespace relay
{

namespace
{

[[nodiscard]] std::string_view trim_path(std::string_view path)
{
    while (path.size() > 1 && path.back() == '/')
    {
        path.remove_suffix(1);
    }
    return path;
}

[[nodiscard]] web_reply build_root_reply()
{
    const auto stats = trace_store::instance().get_stats();
    web_reply reply;
    reply.body = "{\"service\":\"trace-web\",\"stats\":" + dump_trace_stats_json(stats) +
                 ",\"endpoints\":[\"/dashboard\",\"/api/traces\",\"/api/traces/stats\",\"/api/traces/dashboard\",\"/api/traces/events\",\"/api/traces/{trace_id}\",\"/api/traces/{trace_id}/events\"]}";
    return reply;
}

[[nodiscard]] web_reply build_dashboard_page_reply()
{
    web_reply reply;
    reply.content_type = "text/html; charset=utf-8";
    reply.body = build_trace_dashboard_page_body();
    return reply;
}

[[nodiscard]] web_reply build_stats_reply()
{
    web_reply reply;
    reply.body = dump_trace_stats_json(trace_store::instance().get_stats());
    return reply;
}

[[nodiscard]] web_reply build_dashboard_reply()
{
    web_reply reply;
    reply.body = dump_trace_dashboard_json(trace_store::instance().get_dashboard());
    return reply;
}

[[nodiscard]] web_reply build_events_reply(const trace_web_query_params& params)
{
    trace_event_query query;
    if (const auto* error = apply_trace_web_event_query_params(params, query); error != nullptr)
    {
        return web_reply{boost::beast::http::status::bad_request, make_trace_web_error_body(error)};
    }

    web_reply reply;
    reply.body = dump_trace_event_page_json(trace_store::instance().list_events(query));
    return reply;
}

[[nodiscard]] web_reply build_list_reply(const trace_web_query_params& params)
{
    trace_query query;
    if (const auto* error = apply_trace_web_trace_query_params(params, query); error != nullptr)
    {
        return {boost::beast::http::status::bad_request, make_trace_web_error_body(error)};
    }

    const auto items = trace_store::instance().list_traces(query);
    web_reply reply;
    reply.body = dump_trace_list_json(items, query);
    return reply;
}

[[nodiscard]] web_reply build_trace_reply(const uint64_t trace_id)
{
    const auto snapshot = trace_store::instance().get_trace(trace_id);
    if (!snapshot.has_value())
    {
        return {boost::beast::http::status::not_found, make_trace_web_error_body("trace_not_found")};
    }

    web_reply reply;
    reply.body = dump_trace_snapshot_json(*snapshot);
    return reply;
}

[[nodiscard]] web_reply build_trace_events_reply(const uint64_t trace_id, const trace_web_query_params& params)
{
    const auto snapshot = trace_store::instance().get_trace(trace_id);
    if (!snapshot.has_value())
    {
        return {boost::beast::http::status::not_found, make_trace_web_error_body("trace_not_found")};
    }

    trace_event_query query;
    query.trace_id = trace_id;
    if (const auto* error = apply_trace_web_event_query_params(params, query); error != nullptr)
    {
        return web_reply{boost::beast::http::status::bad_request, make_trace_web_error_body(error)};
    }

    web_reply reply;
    reply.body = dump_trace_events_json(trace_id, trace_store::instance().list_events(query));
    return reply;
}

}    // namespace

std::string make_trace_web_error_body(const char* message)
{
    std::string body;
    body.reserve(std::char_traits<char>::length(message) + 14);
    body.append("{\"error\":\"");
    body.append(message);
    body.append("\"}");
    return body;
}

web_reply dispatch_trace_request(std::string_view path, std::string_view query)
{
    const auto decoded_query = parse_trace_web_query_params(query);
    if (!decoded_query.has_value())
    {
        return {boost::beast::http::status::bad_request, make_trace_web_error_body("invalid_query")};
    }

    path = trim_path(path);
    if (path == "/" || path.empty())
    {
        return build_root_reply();
    }
    if (path == "/dashboard")
    {
        return build_dashboard_page_reply();
    }
    if (path == "/api/traces/stats")
    {
        return build_stats_reply();
    }
    if (path == "/api/traces/dashboard")
    {
        return build_dashboard_reply();
    }
    if (path == "/api/traces/events")
    {
        return build_events_reply(*decoded_query);
    }
    if (path == "/api/traces" || path == "/api/traces/")
    {
        return build_list_reply(*decoded_query);
    }
    if (!path.starts_with("/api/traces/"))
    {
        return {boost::beast::http::status::not_found, make_trace_web_error_body("not_found")};
    }

    auto tail = path.substr(std::string_view("/api/traces/").size());
    tail = trim_path(tail);
    if (tail.empty())
    {
        return build_list_reply(*decoded_query);
    }

    if (tail.ends_with("/events"))
    {
        tail.remove_suffix(std::string_view("/events").size());
        tail = trim_path(tail);
        const auto trace_id = parse_trace_web_trace_id_value(tail);
        if (!trace_id.has_value())
        {
            return {boost::beast::http::status::bad_request, make_trace_web_error_body("invalid_trace_id")};
        }
        return build_trace_events_reply(*trace_id, *decoded_query);
    }

    const auto trace_id = parse_trace_web_trace_id_value(tail);
    if (!trace_id.has_value())
    {
        return {boost::beast::http::status::bad_request, make_trace_web_error_body("invalid_trace_id")};
    }
    return build_trace_reply(*trace_id);
}

}    // namespace relay
