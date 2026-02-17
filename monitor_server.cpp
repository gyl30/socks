#include <array>
#include <cctype>
#include <charconv>
#include <string>
#include <string_view>

#include "log.h"
#include "stop_dispatch.h"
#include "statistics.h"
#include "monitor_server.h"

namespace mux
{

namespace
{

std::string escape_prometheus_label(const std::string_view value)
{
    std::string out;
    out.reserve(value.size());
    for (const char c : value)
    {
        if (c == '\\' || c == '"')
        {
            out.push_back('\\');
        }
        if (c == '\n')
        {
            out.append("\\n");
            continue;
        }
        out.push_back(c);
    }
    return out;
}

void append_uint64(std::string& out, const std::uint64_t value)
{
    std::array<char, 32> buffer{};
    const auto [ptr, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
    if (ec == std::errc())
    {
        out.append(buffer.data(), ptr);
        return;
    }
    out.push_back('0');
}

void append_metric_line(std::string& out, const std::string_view metric_name, const std::uint64_t value)
{
    out.append(metric_name);
    out.push_back(' ');
    append_uint64(out, value);
    out.push_back('\n');
}

std::string_view trim_left(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
    {
        value.remove_prefix(1);
    }
    return value;
}

std::string_view trim(std::string_view value)
{
    value = trim_left(value);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
    {
        value.remove_suffix(1);
    }
    return value;
}

struct parsed_monitor_request
{
    bool valid = false;
    std::string_view query;
};

constexpr std::size_t kMaxMonitorRequestLineSize = 4096;
constexpr std::size_t kMonitorRateStateMaxSources = 4096;
constexpr std::uint32_t kMonitorRateStateRetentionMultiplier = 32;
constexpr auto kMonitorRateStateMinRetention = std::chrono::minutes(5);

int hex_to_int(const char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

bool url_decoded_equals(std::string_view encoded, const std::string_view expected)
{
    std::size_t expected_pos = 0;
    for (std::size_t i = 0; i < encoded.size(); ++i)
    {
        const char c = encoded[i];
        char decoded_char = c;
        if (c == '%' && i + 2 < encoded.size())
        {
            const int hi = hex_to_int(encoded[i + 1]);
            const int lo = hex_to_int(encoded[i + 2]);
            if (hi >= 0 && lo >= 0)
            {
                decoded_char = static_cast<char>((hi << 4) | lo);
                i += 2;
            }
        }
        else if (c == '+')
        {
            decoded_char = ' ';
        }

        if (expected_pos >= expected.size() || decoded_char != expected[expected_pos])
        {
            return false;
        }
        ++expected_pos;
    }
    return expected_pos == expected.size();
}

parsed_monitor_request parse_monitor_request(const std::string_view request)
{
    const std::size_t line_end_pos = request.find('\n');
    std::string_view line(request.data(), line_end_pos == std::string::npos ? request.size() : line_end_pos);
    if (!line.empty() && line.back() == '\r')
    {
        line.remove_suffix(1);
    }
    line = trim(line);
    if (line.empty())
    {
        return {};
    }

    std::string_view target = line;
    const std::size_t first_space = line.find(' ');
    if (first_space != std::string::npos)
    {
        const std::string_view method = line.substr(0, first_space);
        if (method != "GET")
        {
            return {};
        }

        const std::string_view after_method = trim_left(line.substr(first_space + 1));
        const std::size_t target_end = after_method.find(' ');
        if (target_end == std::string::npos)
        {
            return {};
        }
        target = after_method.substr(0, target_end);
    }
    if (target.empty())
    {
        return {};
    }

    const std::size_t query_pos = target.find('?');
    const std::string_view path = target.substr(0, query_pos);
    if (path != "metrics" && path != "/metrics")
    {
        return {};
    }

    parsed_monitor_request parsed;
    parsed.valid = true;
    if (query_pos != std::string::npos && query_pos + 1 < target.size())
    {
        parsed.query = target.substr(query_pos + 1);
    }
    return parsed;
}

bool has_exact_token_parameter(const std::string_view query, const std::string& token)
{
    if (token.empty())
    {
        return true;
    }

    std::size_t pos = 0;
    while (pos <= query.size())
    {
        const std::size_t amp = query.find('&', pos);
        const std::size_t pair_end = amp == std::string::npos ? query.size() : amp;
        const std::string_view pair = query.substr(pos, pair_end - pos);
        const std::size_t eq = pair.find('=');
        const std::string_view key = pair.substr(0, eq);
        const std::string_view value = eq == std::string::npos ? std::string_view{} : pair.substr(eq + 1);
        if (key == "token")
        {
            const bool needs_decode = value.find_first_of("%+") != std::string_view::npos;
            if (!needs_decode)
            {
                if (value == token)
                {
                    return true;
                }
            }
            else if (url_decoded_equals(value, token))
            {
                return true;
            }
        }
        if (amp == std::string::npos)
        {
            break;
        }
        pos = amp + 1;
    }
    return false;
}

bool is_authorized_monitor_request(const std::string_view request, const std::string& token)
{
    const auto parsed = parse_monitor_request(request);
    if (!parsed.valid)
    {
        return false;
    }
    return has_exact_token_parameter(parsed.query, token);
}

std::string monitor_rate_limit_key(asio::ip::tcp::socket& socket)
{
    std::error_code ec;
    const auto remote_ep = socket.remote_endpoint(ec);
    if (ec)
    {
        return "unknown";
    }
    return remote_ep.address().to_string();
}

void prune_monitor_rate_state(
    std::unordered_map<std::string,
                       std::chrono::steady_clock::time_point,
                       monitor_rate_state::transparent_string_hash,
                       monitor_rate_state::transparent_string_equal>& last_request_time_by_source,
    const std::chrono::steady_clock::time_point now,
    std::chrono::milliseconds retention,
    const std::string_view rate_key)
{
    if (retention < kMonitorRateStateMinRetention)
    {
        retention = kMonitorRateStateMinRetention;
    }

    for (auto it = last_request_time_by_source.begin(); it != last_request_time_by_source.end();)
    {
        if (now - it->second >= retention)
        {
            it = last_request_time_by_source.erase(it);
            continue;
        }
        ++it;
    }

    if (last_request_time_by_source.size() < kMonitorRateStateMaxSources)
    {
        return;
    }
    if (last_request_time_by_source.find(rate_key) != last_request_time_by_source.end())
    {
        return;
    }

    auto oldest_it = last_request_time_by_source.end();
    for (auto it = last_request_time_by_source.begin(); it != last_request_time_by_source.end(); ++it)
    {
        if (oldest_it == last_request_time_by_source.end() || it->second < oldest_it->second)
        {
            oldest_it = it;
        }
    }
    if (oldest_it != last_request_time_by_source.end())
    {
        last_request_time_by_source.erase(oldest_it);
    }
}

bool should_prune_monitor_rate_state(
    const std::unordered_map<std::string,
                             std::chrono::steady_clock::time_point,
                             monitor_rate_state::transparent_string_hash,
                             monitor_rate_state::transparent_string_equal>& last_request_time_by_source,
    const std::chrono::steady_clock::time_point last_prune_time,
    const std::chrono::steady_clock::time_point now,
    std::chrono::milliseconds retention)
{
    if (last_request_time_by_source.size() >= kMonitorRateStateMaxSources)
    {
        return true;
    }
    if (retention < kMonitorRateStateMinRetention)
    {
        retention = kMonitorRateStateMinRetention;
    }
    if (last_prune_time.time_since_epoch().count() == 0)
    {
        return true;
    }
    return now - last_prune_time >= retention;
}

}    // namespace

namespace detail
{

bool allow_monitor_request_by_source(monitor_rate_state& rate_state,
                                     const std::string_view source_key,
                                     const std::uint32_t min_interval_ms,
                                     const std::chrono::steady_clock::time_point now)
{
    if (min_interval_ms == 0)
    {
        return true;
    }

    std::lock_guard<std::mutex> lock(rate_state.mutex);
    const auto retention_ms = static_cast<std::uint64_t>(min_interval_ms) * kMonitorRateStateRetentionMultiplier;
    const auto retention = std::chrono::milliseconds(retention_ms);
    if (should_prune_monitor_rate_state(rate_state.last_request_time_by_source, rate_state.last_prune_time, now, retention))
    {
        prune_monitor_rate_state(rate_state.last_request_time_by_source, now, retention, source_key);
        rate_state.last_prune_time = now;
    }
    if (auto it = rate_state.last_request_time_by_source.find(source_key); it != rate_state.last_request_time_by_source.end())
    {
        if (now - it->second < std::chrono::milliseconds(min_interval_ms))
        {
            return false;
        }
        it->second = now;
        return true;
    }
    rate_state.last_request_time_by_source.emplace(std::string(source_key), now);
    return true;
}

}    // namespace detail

class monitor_session : public std::enable_shared_from_this<monitor_session>
{
   public:
    monitor_session(asio::ip::tcp::socket socket, std::string token, std::shared_ptr<monitor_rate_state> rate_state, std::uint32_t min_interval_ms)
        : socket_(std::move(socket)), token_(std::move(token)), rate_state_(std::move(rate_state)), min_interval_ms_(min_interval_ms)
    {
    }

    void start()
    {
        auto self = shared_from_this();
        asio::async_read_until(socket_,
                               asio::dynamic_buffer(request_line_, kMaxMonitorRequestLineSize),
                               '\n',
                               [this, self](std::error_code ec, std::size_t length)
                               {
                                   if (ec)
                                   {
                                       if (ec != asio::error::eof && ec != asio::error::operation_aborted)
                                       {
                                           LOG_WARN("monitor read failed {}", ec.message());
                                       }
                                       close_socket();
                                       return;
                                   }

                                   if (length == 0 || length > request_line_.size())
                                   {
                                       LOG_WARN("monitor request line invalid");
                                       close_socket();
                                       return;
                                   }

                                   const std::string_view request_view(request_line_.data(), length);
                                   if (!is_authorized_monitor_request(request_view, token_))
                                   {
                                       statistics::instance().inc_monitor_auth_failures();
                                       if (!token_.empty())
                                       {
                                           LOG_WARN("monitor auth failed");
                                       }
                                       else
                                       {
                                           LOG_WARN("monitor invalid request");
                                       }
                                       close_socket();
                                       return;
                                   }
                                   if (!check_rate_limit())
                                   {
                                       statistics::instance().inc_monitor_rate_limited();
                                       LOG_WARN("monitor rate limited");
                                       close_socket();
                                       return;
                                   }
                                   write_stats();
                               });
    }

   private:
    void close_socket()
    {
        std::error_code ignored_ec;
        ignored_ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
        ignored_ec = socket_.close(ignored_ec);
    }

    bool check_rate_limit()
    {
        if (min_interval_ms_ == 0 || rate_state_ == nullptr)
        {
            return true;
        }
        const auto rate_key = monitor_rate_limit_key(socket_);
        return detail::allow_monitor_request_by_source(
            *rate_state_, rate_key, min_interval_ms_, std::chrono::steady_clock::now());
    }

    void write_stats()
    {
        auto& stats = statistics::instance();
        std::string response;
        response.reserve(1024);

        append_metric_line(response, "socks_uptime_seconds", stats.uptime_seconds());
        append_metric_line(response, "socks_active_connections", stats.active_connections());
        append_metric_line(response, "socks_total_connections", stats.total_connections());
        append_metric_line(response, "socks_active_mux_tunnels", stats.active_mux_sessions());
        append_metric_line(response, "socks_bytes_read_total", stats.bytes_read());
        append_metric_line(response, "socks_bytes_written_total", stats.bytes_written());
        append_metric_line(response, "socks_auth_failures_total", stats.auth_failures());
        append_metric_line(response, "socks_auth_short_id_failures_total", stats.auth_short_id_failures());
        append_metric_line(response, "socks_auth_clock_skew_failures_total", stats.auth_clock_skew_failures());
        append_metric_line(response, "socks_auth_replay_failures_total", stats.auth_replay_failures());
        append_metric_line(response, "socks_cert_verify_failures_total", stats.cert_verify_failures());
        append_metric_line(response, "socks_client_finished_failures_total", stats.client_finished_failures());
        append_metric_line(response, "socks_fallback_rate_limited_total", stats.fallback_rate_limited());
        append_metric_line(response, "socks_fallback_no_target_total", stats.fallback_no_target());
        append_metric_line(response, "socks_fallback_resolve_failures_total", stats.fallback_resolve_failures());
        append_metric_line(response, "socks_fallback_connect_failures_total", stats.fallback_connect_failures());
        append_metric_line(response, "socks_fallback_write_failures_total", stats.fallback_write_failures());
        append_metric_line(response, "socks_routing_blocked_total", stats.routing_blocked());
        append_metric_line(response, "socks_connection_limit_rejected_total", stats.connection_limit_rejected());
        append_metric_line(response, "socks_stream_limit_rejected_total", stats.stream_limit_rejected());
        append_metric_line(response, "socks_monitor_auth_failures_total", stats.monitor_auth_failures());
        append_metric_line(response, "socks_monitor_rate_limited_total", stats.monitor_rate_limited());
        append_metric_line(response, "socks_tproxy_udp_dispatch_enqueued_total", stats.tproxy_udp_dispatch_enqueued());
        append_metric_line(response, "socks_tproxy_udp_dispatch_dropped_total", stats.tproxy_udp_dispatch_dropped());
        const auto handshake_failure_sni_metrics = stats.handshake_failure_sni_metrics();
        for (const auto& metric : handshake_failure_sni_metrics)
        {
            response.append("socks_handshake_failures_by_sni_total{reason=\"");
            response.append(escape_prometheus_label(metric.reason));
            response.append("\",sni=\"");
            response.append(escape_prometheus_label(metric.sni));
            response.append("\"} ");
            append_uint64(response, metric.count);
            response.push_back('\n');
        }

        response_ = std::move(response);

        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(response_), [this, self](std::error_code, std::size_t) { close_socket(); });
    }

   private:
    std::string response_;
    std::string request_line_;
    asio::ip::tcp::socket socket_;
    std::string token_;
    std::shared_ptr<monitor_rate_state> rate_state_;
    std::uint32_t min_interval_ms_ = 0;
};

monitor_server::monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), 0)
{
}

monitor_server::monitor_server(asio::io_context& ioc, std::uint16_t port, std::string token, const std::uint32_t min_interval_ms)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), min_interval_ms)
{
}

monitor_server::monitor_server(asio::io_context& ioc,
                               std::string bind_host,
                               const std::uint16_t port,
                               std::string token,
                               const std::uint32_t min_interval_ms)
    : acceptor_(ioc), token_(std::move(token)), min_interval_ms_(min_interval_ms)
{
    auto close_acceptor_on_failure = [this]()
    {
        asio::error_code close_ec;
        acceptor_.close(close_ec);
    };

    asio::ip::tcp::endpoint endpoint;
    asio::error_code ec;
    endpoint.address(asio::ip::make_address(bind_host, ec));
    if (ec)
    {
        LOG_ERROR("failed to parse address: {}", ec.message());
        return;
    }
    endpoint.port(port);
    if (acceptor_.open(endpoint.protocol(), ec); ec)
    {
        LOG_ERROR("failed to open acceptor: {}", ec.message());
        return;
    }
    if (acceptor_.set_option(asio::socket_base::reuse_address(true), ec); ec)
    {
        LOG_ERROR("failed to set reuse_address: {}", ec.message());
        close_acceptor_on_failure();
        return;
    }
    if (acceptor_.bind(endpoint, ec); ec)
    {
        LOG_ERROR("failed to bind: {}", ec.message());
        close_acceptor_on_failure();
        return;
    }
    if (acceptor_.listen(asio::socket_base::max_listen_connections, ec); ec)
    {
        LOG_ERROR("failed to listen: {}", ec.message());
        close_acceptor_on_failure();
        return;
    }
    LOG_INFO("monitor server listening on {}:{}", bind_host, port);
}

void monitor_server::start()
{
    if (!acceptor_.is_open())
    {
        return;
    }
    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
    {
        return;
    }
    stop_.store(false, std::memory_order_release);
    do_accept();
}

void monitor_server::stop()
{
    stop_.store(true, std::memory_order_release);
    started_.store(false, std::memory_order_release);

    auto& io_context = static_cast<asio::io_context&>(acceptor_.get_executor().context());
    detail::dispatch_cleanup_or_run_inline(
        io_context,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                self->stop_local();
            }
        });
}

void monitor_server::stop_local()
{
    started_.store(false, std::memory_order_release);
    std::error_code ec;
    ec = acceptor_.close(ec);
    if (ec && ec != asio::error::bad_descriptor)
    {
        LOG_WARN("monitor acceptor close failed {}", ec.message());
    }
}

void monitor_server::do_accept()
{
    if (stop_.load(std::memory_order_acquire) || !acceptor_.is_open())
    {
        return;
    }

    const auto self = shared_from_this();
    acceptor_.async_accept(
        [self](std::error_code ec, asio::ip::tcp::socket socket)
        {
            if (self->stop_.load(std::memory_order_acquire))
            {
                return;
            }
            if (ec)
            {
                if (ec != asio::error::operation_aborted && ec != asio::error::bad_descriptor)
                {
                    LOG_WARN("monitor accept failed {}", ec.message());
                    self->do_accept();
                }
                return;
            }

            std::make_shared<monitor_session>(std::move(socket), self->token_, self->rate_state_, self->min_interval_ms_)->start();
            self->do_accept();
        });
}

}    // namespace mux
