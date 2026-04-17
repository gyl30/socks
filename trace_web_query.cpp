#include "trace_web_query.h"

#include <charconv>
#include <cctype>

namespace relay
{

namespace
{

constexpr std::size_t kMaxTraceListLimit = 500;

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

}    // namespace

std::optional<trace_web_query_params> parse_trace_web_query_params(std::string_view query)
{
    trace_web_query_params params;
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

bool parse_trace_web_size_t_param(const trace_web_query_params& params, const char* key, std::size_t& value)
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

std::optional<uint64_t> parse_trace_web_trace_id_value(std::string_view text)
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

const char* apply_trace_web_event_query_params(const trace_web_query_params& params, trace_event_query& query)
{
    if (const auto it = params.find("trace_id"); it != params.end())
    {
        const auto parsed = parse_trace_web_trace_id_value(it->second);
        if (!parsed.has_value())
        {
            return "invalid_trace_id";
        }
        query.trace_id = *parsed;
    }
    if (const auto it = params.find("stage"); it != params.end())
    {
        const auto parsed = parse_trace_stage(it->second);
        if (!parsed.has_value())
        {
            return "invalid_stage";
        }
        query.stage = *parsed;
    }
    if (const auto it = params.find("result"); it != params.end())
    {
        const auto parsed = parse_trace_result(it->second);
        if (!parsed.has_value())
        {
            return "invalid_result";
        }
        query.result = *parsed;
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
    if (const auto it = params.find("sort_order"); it != params.end())
    {
        const auto parsed = parse_trace_sort_order(it->second);
        if (!parsed.has_value())
        {
            return "invalid_sort_order";
        }
        query.sort_order = *parsed;
    }

    if (!parse_trace_web_size_t_param(params, "limit", query.limit))
    {
        return "invalid_limit";
    }
    if (!parse_trace_web_size_t_param(params, "offset", query.offset))
    {
        return "invalid_offset";
    }
    if (query.limit > kMaxTraceListLimit)
    {
        query.limit = kMaxTraceListLimit;
    }

    return nullptr;
}

const char* apply_trace_web_trace_query_params(const trace_web_query_params& params, trace_query& query)
{
    if (const auto it = params.find("status"); it != params.end())
    {
        const auto parsed = parse_trace_status(it->second);
        if (!parsed.has_value())
        {
            return "invalid_status";
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
            return "invalid_sort_field";
        }
        query.sort_field = *parsed;
    }

    if (const auto it = params.find("sort_order"); it != params.end())
    {
        const auto parsed = parse_trace_sort_order(it->second);
        if (!parsed.has_value())
        {
            return "invalid_sort_order";
        }
        query.sort_order = *parsed;
    }

    if (!parse_trace_web_size_t_param(params, "limit", query.limit))
    {
        return "invalid_limit";
    }
    if (!parse_trace_web_size_t_param(params, "offset", query.offset))
    {
        return "invalid_offset";
    }
    if (query.limit > kMaxTraceListLimit)
    {
        query.limit = kMaxTraceListLimit;
    }

    return nullptr;
}

}    // namespace relay
