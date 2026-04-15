#include "trace_web_server.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "log.h"
#include "constants.h"
#include "trace_json.h"
#include "trace_store.h"

namespace relay
{

namespace
{

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

constexpr std::size_t kMaxTraceListLimit = 500;

struct web_reply
{
    http::status status = http::status::ok;
    std::string body;
    bool allow_get_only = false;
};

[[nodiscard]] std::string make_error_body(const char* message)
{
    std::string body;
    body.reserve(std::char_traits<char>::length(message) + 14);
    body.append("{\"error\":\"");
    body.append(message);
    body.append("\"}");
    return body;
}

[[nodiscard]] std::string_view trim_path(std::string_view path)
{
    while (path.size() > 1 && path.back() == '/')
    {
        path.remove_suffix(1);
    }
    return path;
}

[[nodiscard]] std::pair<std::string_view, std::string_view> split_target(std::string_view target)
{
    const auto question = target.find('?');
    if (question == std::string_view::npos)
    {
        return {target, std::string_view{}};
    }
    return {target.substr(0, question), target.substr(question + 1)};
}

[[nodiscard]] int hex_value(const char ch)
{
    if (ch >= '0' && ch <= '9')
    {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f')
    {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F')
    {
        return 10 + (ch - 'A');
    }
    return -1;
}

[[nodiscard]] std::optional<std::string> url_decode(std::string_view input)
{
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0; index < input.size(); ++index)
    {
        const char ch = input[index];
        if (ch == '+')
        {
            output.push_back(' ');
            continue;
        }
        if (ch == '%')
        {
            if (index + 2 >= input.size())
            {
                return std::nullopt;
            }
            const auto hi = hex_value(input[index + 1]);
            const auto lo = hex_value(input[index + 2]);
            if (hi < 0 || lo < 0)
            {
                return std::nullopt;
            }
            output.push_back(static_cast<char>((hi << 4) | lo));
            index += 2;
            continue;
        }
        output.push_back(ch);
    }
    return output;
}

[[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> parse_query_params(std::string_view query)
{
    std::unordered_map<std::string, std::string> params;
    while (!query.empty())
    {
        const auto amp = query.find('&');
        const auto token = query.substr(0, amp);
        const auto eq = token.find('=');
        const auto key_view = token.substr(0, eq);
        const auto value_view = (eq == std::string_view::npos) ? std::string_view{} : token.substr(eq + 1);
        const auto decoded_key = url_decode(key_view);
        const auto decoded_value = url_decode(value_view);
        if (!decoded_key.has_value() || !decoded_value.has_value())
        {
            return std::nullopt;
        }
        params[std::move(*decoded_key)] = std::move(*decoded_value);
        if (amp == std::string_view::npos)
        {
            break;
        }
        query.remove_prefix(amp + 1);
    }
    return params;
}

[[nodiscard]] bool parse_size_t_param(const std::unordered_map<std::string, std::string>& params,
                                      const char* key,
                                      std::size_t& value)
{
    const auto it = params.find(key);
    if (it == params.end())
    {
        return true;
    }
    std::size_t parsed = 0;
    const auto [ptr, ec] = std::from_chars(it->second.data(), it->second.data() + it->second.size(), parsed);
    if (ec != std::errc{} || ptr != it->second.data() + it->second.size())
    {
        return false;
    }
    value = parsed;
    return true;
}

[[nodiscard]] std::optional<uint64_t> parse_trace_id_value(std::string_view text)
{
    if (text.empty())
    {
        return std::nullopt;
    }

    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
    {
        text.remove_prefix(2);
    }

    for (const char ch : text)
    {
        if (std::isxdigit(static_cast<unsigned char>(ch)) == 0)
        {
            return std::nullopt;
        }
    }

    uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (ec != std::errc{} || ptr != text.data() + text.size())
    {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] web_reply build_root_reply()
{
    const auto stats = trace_store::instance().get_stats();
    web_reply reply;
    reply.body = "{\"service\":\"trace-web\",\"stats\":" + dump_trace_stats_json(stats) +
                 ",\"endpoints\":[\"/api/traces\",\"/api/traces/stats\",\"/api/traces/{trace_id}\",\"/api/traces/{trace_id}/events\"]}";
    return reply;
}

[[nodiscard]] web_reply build_stats_reply()
{
    web_reply reply;
    reply.body = dump_trace_stats_json(trace_store::instance().get_stats());
    return reply;
}

[[nodiscard]] web_reply build_list_reply(const std::unordered_map<std::string, std::string>& params)
{
    trace_query query;

    if (const auto it = params.find("status"); it != params.end())
    {
        const auto parsed = parse_trace_status(it->second);
        if (!parsed.has_value())
        {
            return {http::status::bad_request, make_error_body("invalid_status")};
        }
        query.status = parsed;
    }

    if (const auto it = params.find("inbound_tag"); it != params.end())
    {
        query.inbound_tag = it->second;
    }
    if (const auto it = params.find("outbound_tag"); it != params.end())
    {
        query.outbound_tag = it->second;
    }
    if (const auto it = params.find("target_host"); it != params.end())
    {
        query.target_host = it->second;
    }
    if (const auto it = params.find("route_type"); it != params.end())
    {
        query.route_type = it->second;
    }
    if (const auto it = params.find("match_type"); it != params.end())
    {
        query.match_type = it->second;
    }

    if (const auto it = params.find("sort_field"); it != params.end())
    {
        const auto parsed = parse_trace_sort_field(it->second);
        if (!parsed.has_value())
        {
            return {http::status::bad_request, make_error_body("invalid_sort_field")};
        }
        query.sort_field = *parsed;
    }

    if (const auto it = params.find("sort_order"); it != params.end())
    {
        const auto parsed = parse_trace_sort_order(it->second);
        if (!parsed.has_value())
        {
            return {http::status::bad_request, make_error_body("invalid_sort_order")};
        }
        query.sort_order = *parsed;
    }

    if (!parse_size_t_param(params, "limit", query.limit))
    {
        return {http::status::bad_request, make_error_body("invalid_limit")};
    }
    if (!parse_size_t_param(params, "offset", query.offset))
    {
        return {http::status::bad_request, make_error_body("invalid_offset")};
    }
    if (query.limit > kMaxTraceListLimit)
    {
        query.limit = kMaxTraceListLimit;
    }

    const auto items = trace_store::instance().list_traces(query);
    web_reply reply;
    reply.body = dump_trace_list_json(items, query);
    return reply;
}

[[nodiscard]] web_reply build_trace_reply(uint64_t trace_id)
{
    const auto snapshot = trace_store::instance().get_trace(trace_id);
    if (!snapshot.has_value())
    {
        return {http::status::not_found, make_error_body("trace_not_found")};
    }

    web_reply reply;
    reply.body = dump_trace_snapshot_json(*snapshot);
    return reply;
}

[[nodiscard]] web_reply build_trace_events_reply(uint64_t trace_id)
{
    const auto snapshot = trace_store::instance().get_trace(trace_id);
    if (!snapshot.has_value())
    {
        return {http::status::not_found, make_error_body("trace_not_found")};
    }

    web_reply reply;
    reply.body = dump_trace_events_json(*snapshot);
    return reply;
}

[[nodiscard]] web_reply dispatch_trace_request(std::string_view path, std::string_view query)
{
    const auto decoded_query = parse_query_params(query);
    if (!decoded_query.has_value())
    {
        return {http::status::bad_request, make_error_body("invalid_query")};
    }

    path = trim_path(path);
    if (path == "/" || path.empty())
    {
        return build_root_reply();
    }
    if (path == "/api/traces/stats")
    {
        return build_stats_reply();
    }
    if (path == "/api/traces" || path == "/api/traces/")
    {
        return build_list_reply(*decoded_query);
    }
    if (!path.starts_with("/api/traces/"))
    {
        return {http::status::not_found, make_error_body("not_found")};
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
        const auto trace_id = parse_trace_id_value(tail);
        if (!trace_id.has_value())
        {
            return {http::status::bad_request, make_error_body("invalid_trace_id")};
        }
        return build_trace_events_reply(*trace_id);
    }

    const auto trace_id = parse_trace_id_value(tail);
    if (!trace_id.has_value())
    {
        return {http::status::bad_request, make_error_body("invalid_trace_id")};
    }
    return build_trace_reply(*trace_id);
}

}    // namespace

trace_web_server::trace_web_server(io_context_pool& pool, const config& cfg)
    : cfg_(cfg), worker_(pool.get_io_worker()), acceptor_(worker_.io_context)
{
}

void trace_web_server::start()
{
    if (!cfg_.web.enabled)
    {
        return;
    }

    boost::system::error_code ec;
    const auto listen_addr = boost::asio::ip::make_address(cfg_.web.host, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen host {} parse failed {}", log_event::kConnInit, cfg_.web.host, ec.message());
        std::exit(EXIT_FAILURE);
    }

    const tcp::endpoint endpoint{listen_addr, cfg_.web.port};
    ec = acceptor_.open(endpoint.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} open failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} reuse_address failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    if (listen_addr.is_v6() && listen_addr.to_v6().is_unspecified())
    {
        ec = acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("{} stage start web listen {}:{} v6_only failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
            std::exit(EXIT_FAILURE);
        }
    }
    ec = acceptor_.bind(endpoint, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} bind failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start web listen {}:{} listen failed {}", log_event::kConnInit, cfg_.web.host, cfg_.web.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("{} stage start web listen {}:{} started", log_event::kConnInit, cfg_.web.host, cfg_.web.port);
    worker_.group.spawn([self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await self->accept_loop(); });
}

void trace_web_server::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::system::error_code ec;
    ec = acceptor_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_ERROR("{} stage stop web listen {}:{} close failed {}", log_event::kConnClose, cfg_.web.host, cfg_.web.port, ec.message());
    }
    else
    {
        LOG_INFO("{} stage stop web listen {}:{} stopped", log_event::kConnClose, cfg_.web.host, cfg_.web.port);
    }
}

boost::asio::awaitable<void> trace_web_server::accept_loop()
{
    boost::system::error_code ec;
    while (!stopping_.load(std::memory_order_relaxed))
    {
        tcp::socket socket(worker_.io_context);
        co_await acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            break;
        }
        if (ec)
        {
            LOG_WARN("{} stage accept web listen {}:{} accept failed {}",
                     log_event::kConnInit,
                     cfg_.web.host,
                     cfg_.web.port,
                     ec.message());
            continue;
        }

        worker_.group.spawn([self = shared_from_this(), socket = std::move(socket)]() mutable -> boost::asio::awaitable<void>
                            { co_await self->serve_session(std::move(socket)); });
    }
    co_return;
}

boost::asio::awaitable<void> trace_web_server::serve_session(boost::asio::ip::tcp::socket socket)
{
    beast::tcp_stream stream(std::move(socket));
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    boost::system::error_code ec;
    co_await http::async_read(stream, buffer, req, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        if (ec != boost::asio::error::operation_aborted && ec != http::error::end_of_stream)
        {
            LOG_WARN("{} stage web request read failed {}", log_event::kConnInit, ec.message());
        }
        co_return;
    }

    web_reply reply;
    if (req.method() != http::verb::get)
    {
        reply.status = http::status::method_not_allowed;
        reply.body = make_error_body("method_not_allowed");
        reply.allow_get_only = true;
    }
    else
    {
        const std::string_view target{req.target().data(), req.target().size()};
        const auto [path, query] = split_target(target);
        reply = dispatch_trace_request(path, query);
    }

    http::response<http::string_body> res{reply.status, req.version()};
    res.set(http::field::server, "socks-trace-web");
    res.set(http::field::content_type, "application/json; charset=utf-8");
    if (reply.allow_get_only)
    {
        res.set(http::field::allow, "GET");
    }
    res.keep_alive(false);
    res.body() = std::move(reply.body);
    res.prepare_payload();
    co_await http::async_write(stream, res, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec && ec != boost::asio::error::operation_aborted)
    {
        LOG_WARN("{} stage web response write failed {}", log_event::kConnInit, ec.message());
    }
    co_return;
}

}    // namespace relay
