#include <array>
#include <charconv>
#include <chrono>
#include <string>
#include <string_view>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "log.h"
#include "monitor_server.h"
#include "statistics.h"
#include "stop_dispatch.h"

namespace mux
{

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

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

constexpr std::size_t kMonitorRateStateMaxSources = 4096;
constexpr std::uint32_t kMonitorRateStateRetentionMultiplier = 32;
constexpr auto kMonitorRateStateMinRetention = std::chrono::minutes(5);

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

bool is_metrics_target(const beast::string_view target)
{
    const std::size_t query_pos = target.find('?');
    const beast::string_view path = target.substr(0, query_pos);
    return path == "/metrics";
}

std::string build_metrics_payload()
{
    auto& stats = statistics::instance();
    std::string metrics_payload;
    metrics_payload.reserve(1024);

    append_metric_line(metrics_payload, "socks_uptime_seconds", stats.uptime_seconds());
    append_metric_line(metrics_payload, "socks_active_connections", stats.active_connections());
    append_metric_line(metrics_payload, "socks_total_connections", stats.total_connections());
    append_metric_line(metrics_payload, "socks_active_mux_tunnels", stats.active_mux_sessions());
    append_metric_line(metrics_payload, "socks_bytes_read_total", stats.bytes_read());
    append_metric_line(metrics_payload, "socks_bytes_written_total", stats.bytes_written());
    append_metric_line(metrics_payload, "socks_auth_failures_total", stats.auth_failures());
    append_metric_line(metrics_payload, "socks_auth_short_id_failures_total", stats.auth_short_id_failures());
    append_metric_line(metrics_payload, "socks_auth_clock_skew_failures_total", stats.auth_clock_skew_failures());
    append_metric_line(metrics_payload, "socks_auth_replay_failures_total", stats.auth_replay_failures());
    append_metric_line(metrics_payload, "socks_cert_verify_failures_total", stats.cert_verify_failures());
    append_metric_line(metrics_payload, "socks_client_finished_failures_total", stats.client_finished_failures());
    append_metric_line(metrics_payload, "socks_fallback_rate_limited_total", stats.fallback_rate_limited());
    append_metric_line(metrics_payload, "socks_fallback_no_target_total", stats.fallback_no_target());
    append_metric_line(metrics_payload, "socks_fallback_resolve_failures_total", stats.fallback_resolve_failures());
    append_metric_line(metrics_payload, "socks_fallback_resolve_timeouts_total", stats.fallback_resolve_timeouts());
    append_metric_line(metrics_payload, "socks_fallback_resolve_errors_total", stats.fallback_resolve_errors());
    append_metric_line(metrics_payload, "socks_fallback_connect_failures_total", stats.fallback_connect_failures());
    append_metric_line(metrics_payload, "socks_fallback_connect_timeouts_total", stats.fallback_connect_timeouts());
    append_metric_line(metrics_payload, "socks_fallback_connect_errors_total", stats.fallback_connect_errors());
    append_metric_line(metrics_payload, "socks_fallback_write_failures_total", stats.fallback_write_failures());
    append_metric_line(metrics_payload, "socks_fallback_write_timeouts_total", stats.fallback_write_timeouts());
    append_metric_line(metrics_payload, "socks_fallback_write_errors_total", stats.fallback_write_errors());
    append_metric_line(metrics_payload, "socks_direct_upstream_resolve_timeouts_total", stats.direct_upstream_resolve_timeouts());
    append_metric_line(metrics_payload, "socks_direct_upstream_resolve_errors_total", stats.direct_upstream_resolve_errors());
    append_metric_line(metrics_payload, "socks_direct_upstream_connect_timeouts_total", stats.direct_upstream_connect_timeouts());
    append_metric_line(metrics_payload, "socks_direct_upstream_connect_errors_total", stats.direct_upstream_connect_errors());
    append_metric_line(metrics_payload, "socks_remote_session_resolve_timeouts_total", stats.remote_session_resolve_timeouts());
    append_metric_line(metrics_payload, "socks_remote_session_resolve_errors_total", stats.remote_session_resolve_errors());
    append_metric_line(metrics_payload, "socks_remote_session_connect_timeouts_total", stats.remote_session_connect_timeouts());
    append_metric_line(metrics_payload, "socks_remote_session_connect_errors_total", stats.remote_session_connect_errors());
    append_metric_line(metrics_payload, "socks_remote_udp_session_resolve_timeouts_total", stats.remote_udp_session_resolve_timeouts());
    append_metric_line(metrics_payload, "socks_remote_udp_session_resolve_errors_total", stats.remote_udp_session_resolve_errors());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_resolve_timeouts_total", stats.client_tunnel_pool_resolve_timeouts());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_resolve_errors_total", stats.client_tunnel_pool_resolve_errors());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_connect_timeouts_total", stats.client_tunnel_pool_connect_timeouts());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_connect_errors_total", stats.client_tunnel_pool_connect_errors());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_handshake_timeouts_total", stats.client_tunnel_pool_handshake_timeouts());
    append_metric_line(metrics_payload, "socks_client_tunnel_pool_handshake_errors_total", stats.client_tunnel_pool_handshake_errors());
    append_metric_line(metrics_payload, "socks_routing_blocked_total", stats.routing_blocked());
    append_metric_line(metrics_payload, "socks_connection_limit_rejected_total", stats.connection_limit_rejected());
    append_metric_line(metrics_payload, "socks_stream_limit_rejected_total", stats.stream_limit_rejected());
    append_metric_line(metrics_payload, "socks_monitor_auth_failures_total", stats.monitor_auth_failures());
    append_metric_line(metrics_payload, "socks_monitor_rate_limited_total", stats.monitor_rate_limited());
    append_metric_line(metrics_payload, "socks_tproxy_udp_dispatch_enqueued_total", stats.tproxy_udp_dispatch_enqueued());
    append_metric_line(metrics_payload, "socks_tproxy_udp_dispatch_dropped_total", stats.tproxy_udp_dispatch_dropped());

    const auto handshake_failure_sni_metrics = stats.handshake_failure_sni_metrics();
    for (const auto& metric : handshake_failure_sni_metrics)
    {
        metrics_payload.append("socks_handshake_failures_by_sni_total{reason=\"");
        metrics_payload.append(escape_prometheus_label(metric.reason));
        metrics_payload.append("\",sni=\"");
        metrics_payload.append(escape_prometheus_label(metric.sni));
        metrics_payload.append("\"} ");
        append_uint64(metrics_payload, metric.count);
        metrics_payload.push_back('\n');
    }

    return metrics_payload;
}

http::response<http::string_body> make_text_response(const http::status status,
                                                     const unsigned version,
                                                     std::string body,
                                                     const std::string_view content_type)
{
    http::response<http::string_body> response(status, version);
    response.set(http::field::server, "socks-monitor");
    response.set(http::field::content_type, content_type);
    response.set(http::field::connection, "close");
    response.body() = std::move(body);
    response.prepare_payload();
    return response;
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
    monitor_session(tcp::socket socket, std::string token, std::shared_ptr<monitor_rate_state> rate_state, std::uint32_t min_interval_ms)
        : stream_(std::move(socket))
    {
        (void)token;
        (void)rate_state;
        (void)min_interval_ms;
    }

    void start() { do_read(); }

   private:
    void do_read()
    {
        auto self = shared_from_this();
        http::async_read(stream_,
                         read_buffer_,
                         request_,
                         [this, self](boost::system::error_code ec, std::size_t)
                         {
                             if (ec)
                             {
                                 if (ec != http::error::end_of_stream && ec != boost::asio::error::operation_aborted)
                                 {
                                     LOG_WARN("monitor read failed {}", ec.message());
                                 }
                                 close_socket();
                                 return;
                             }
                             handle_request();
                         });
    }

    void handle_request()
    {
        if (request_.method() != http::verb::get)
        {
            response_ = make_text_response(
                http::status::method_not_allowed, request_.version(), "method not allowed\n", "text/plain; charset=utf-8");
            write_response();
            return;
        }

        if (!is_metrics_target(request_.target()))
        {
            response_ = make_text_response(http::status::not_found, request_.version(), "not found\n", "text/plain; charset=utf-8");
            write_response();
            return;
        }

        response_ = make_text_response(http::status::ok,
                                       request_.version(),
                                       build_metrics_payload(),
                                       "text/plain; version=0.0.4; charset=utf-8");
        write_response();
    }

    void write_response()
    {
        auto self = shared_from_this();
        http::async_write(stream_, response_, [this, self](boost::system::error_code ec, std::size_t)
                          {
                              if (ec && ec != boost::asio::error::operation_aborted)
                              {
                                  LOG_WARN("monitor write failed {}", ec.message());
                              }
                              close_socket();
                          });
    }

    void close_socket()
    {
        boost::system::error_code ignored_ec;
        stream_.socket().shutdown(tcp::socket::shutdown_both, ignored_ec);
        stream_.socket().close(ignored_ec);
    }

   private:
    beast::tcp_stream stream_;
    beast::flat_buffer read_buffer_;
    http::request<http::string_body> request_;
    http::response<http::string_body> response_;
};

monitor_server::monitor_server(boost::asio::io_context& ioc, std::uint16_t port, std::string token)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), 0)
{
}

monitor_server::monitor_server(boost::asio::io_context& ioc, std::uint16_t port, std::string token, const std::uint32_t min_interval_ms)
    : monitor_server(ioc, "127.0.0.1", port, std::move(token), min_interval_ms)
{
}

monitor_server::monitor_server(boost::asio::io_context& ioc,
                               std::string bind_host,
                               const std::uint16_t port,
                               std::string token,
                               const std::uint32_t min_interval_ms)
    : acceptor_(ioc), token_(std::move(token)), min_interval_ms_(min_interval_ms)
{
    auto close_acceptor_on_failure = [this]()
    {
        boost::system::error_code close_ec;
        acceptor_.close(close_ec);
    };

    boost::asio::ip::tcp::endpoint endpoint;
    boost::system::error_code ec;
    endpoint.address(boost::asio::ip::make_address(bind_host, ec));
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
    if (acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec); ec)
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
    if (acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec); ec)
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

    auto& io_context = static_cast<boost::asio::io_context&>(acceptor_.get_executor().context());
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
    boost::system::error_code ec;
    ec = acceptor_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
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
        [self](boost::system::error_code ec, tcp::socket socket)
        {
            if (self->stop_.load(std::memory_order_acquire))
            {
                return;
            }
            if (ec)
            {
                if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::bad_descriptor)
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
