#ifndef TRACE_WEB_HANDLER_H
#define TRACE_WEB_HANDLER_H

#include <ostream>
#include <string>
#include <string_view>

#include <boost/beast/http/status.hpp>

namespace relay
{

struct web_reply
{
    boost::beast::http::status status = boost::beast::http::status::ok;
    std::string body;
    std::string content_type = "application/json; charset=utf-8";
    bool allow_get_only = false;
};

[[nodiscard]] std::string make_trace_web_error_body(const char* message);
[[nodiscard]] web_reply dispatch_trace_request(std::string_view path, std::string_view query);

}    // namespace relay

#endif
