#include <array>
#include <string>
#include <chrono>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <charconv>
#include <string_view>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
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

bool is_metrics_target(const boost::beast::string_view target)
{
    const std::size_t query_pos = target.find('?');
    const boost::beast::string_view path = target.substr(0, query_pos);
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
    append_metric_line(metrics_payload, "socks_tproxy_udp_origdst_truncated_total", stats.tproxy_udp_origdst_truncated());
    append_metric_line(metrics_payload, "socks_tproxy_udp_payload_truncated_total", stats.tproxy_udp_payload_truncated());

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

boost::beast::http::response<boost::beast::http::string_body> make_text_response(uint32_t code,
                                                                                 uint32_t version,
                                                                                 std::string body,
                                                                                 std::string_view content_type)
{
    auto status = boost::beast::http::int_to_status(code);
    boost::beast::http::response<boost::beast::http::string_body> response(status, version);
    response.set(boost::beast::http::field::server, "socks");
    response.set(boost::beast::http::field::content_type, content_type);
    response.set(boost::beast::http::field::connection, "close");
    response.body() = std::move(body);
    response.prepare_payload();
    return response;
}

}    // namespace

static boost::asio::awaitable<void> handle_request(boost::beast::tcp_stream stream_)
{
    boost::system::error_code ec;

    auto local_addr = stream_.socket().local_endpoint(ec);
    auto remote_addr = stream_.socket().remote_endpoint(ec);
    auto local_addr_str = local_addr.address().to_string() + ":" + std::to_string(local_addr.port());
    auto remote_addr_str = remote_addr.address().to_string() + ":" + std::to_string(remote_addr.port());
    auto stream_id = local_addr_str + "<->" + remote_addr_str;
    stream_.expires_after(std::chrono::seconds(30));
    boost::beast::http::request<boost::beast::http::string_body> request;
    boost::beast::flat_buffer buffer;
    co_await boost::beast::http::async_read(stream_, buffer, request, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    do
    {
        if (ec)
        {
            LOG_ERROR("{} read http request error {}", stream_id, ec.message());
            break;
        }
        if (request.method() == boost::beast::http::verb::get && is_metrics_target(request.target()))
        {
            auto response = make_text_response(200, request.version(), build_metrics_payload(), "text/plain; version=0.0.4; charset=utf-8");
            co_await boost::beast::http::async_write(stream_, response, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                LOG_ERROR("{} write metrics response error {}", stream_id, ec.message());
                break;
            }
        }
        else
        {
            auto response = make_text_response(404, request.version(), "Not Found\n", "text/plain; charset=utf-8");
            co_await boost::beast::http::async_write(stream_, response, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                LOG_ERROR("{} write not found response error {}", stream_id, ec.message());
                break;
            }
        }
    } while (false);
    ec = stream_.socket().close(ec);
    if (ec)
    {
        LOG_ERROR("{} stream close error {}", stream_id, ec.message());
    }
}

monitor_server::monitor_server(boost::asio::io_context& ioc, const std::uint16_t port) : monitor_server(ioc, "127.0.0.1", port) {}

monitor_server::monitor_server(boost::asio::io_context& ioc, std::string bind_host, const std::uint16_t port)
    : port_(port), host_(std::move(bind_host)), ioc_(ioc)
{
}

int monitor_server::start()
{
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint endpoint;
    endpoint.address(boost::asio::ip::make_address(host_, ec));
    if (ec)
    {
        LOG_ERROR("failed to parse address {}", ec.message());
        return -1;
    }
    endpoint.port(port_);
    if (acceptor_.open(endpoint.protocol(), ec); ec)
    {
        LOG_ERROR("failed to open acceptor {}", ec.message());
        return -1;
    }
    if (acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec); ec)
    {
        LOG_ERROR("failed to set reuse_address {}", ec.message());
        return -1;
    }
    if (acceptor_.bind(endpoint, ec); ec)
    {
        LOG_ERROR("failed to bind {}", ec.message());
        return -1;
    }
    if (acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec); ec)
    {
        LOG_ERROR("failed to listen {}", ec.message());
        return -1;
    }

    LOG_INFO("monitor server listening on {}:{}", host_, port_);
    boost::asio::co_spawn(ioc_, accept_loop(), group_.adapt(::boost::asio::detached));
    return 0;
}

void monitor_server::stop() { boost::asio::co_spawn(ioc_, stop_accept(), boost::asio::detached); }

boost::asio::awaitable<void> monitor_server::stop_accept()
{
    boost::system::error_code ec;
    ec = acceptor_.close(ec);
    if (ec)
    {
        LOG_ERROR("acceptor close error {}", ec.message());
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    group_.emit(::boost::asio::cancellation_type::all);
    co_await group_.async_wait(::boost::asio::redirect_error(::boost::asio::use_awaitable, ec));
}

boost::asio::awaitable<void> monitor_server::accept_loop()
{
    boost::system::error_code ec;
    const auto self = shared_from_this();
    for (;;)
    {
        auto s = co_await acceptor_.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("accept error {}", ec.message());
            break;
        }
        boost::asio::co_spawn(ioc_, handle_request(boost::beast::tcp_stream(std::move(s))), group_.adapt(boost::asio::detached));
    }
}

}    // namespace mux
