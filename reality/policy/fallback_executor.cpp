#include <string>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "net_utils.h"
#include "scoped_exit.h"
#include "reality/policy/fallback_executor.h"
#include "stream_relay.h"
#include "stream_relay_transport.h"

namespace reality
{

namespace
{
void close_tcp_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.close(ec);
    (void)ec;
}

[[nodiscard]] const char* normalize_reason(const char* reason)
{
    if (reason == nullptr)
    {
        return "unknown";
    }
    return reason;
}

}    // namespace

fallback_executor::fallback_executor(boost::asio::io_context& io_context, const relay::config& cfg) : io_context_(io_context), cfg_(cfg) {}

boost::asio::awaitable<void> fallback_executor::run(
    fallback_request& request, const std::string& host, uint16_t port, const char* reason, boost::system::error_code& ec) const
{
    const char* log_reason = normalize_reason(reason);
    if (request.client_socket == nullptr)
    {
        ec = boost::asio::error::bad_descriptor;
        LOG_WARN("{} conn {} remote {}:{} reason {} missing client socket",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 log_reason);
        co_return;
    }

    LOG_INFO("{} conn {} local {}:{} remote {}:{} sni {} reason {} target {}:{} client_hello_size {}",
             relay::log_event::kFallback,
             request.conn_id,
             request.local_addr.empty() ? "unknown" : request.local_addr,
             request.local_port,
             request.remote_addr.empty() ? "unknown" : request.remote_addr,
             request.remote_port,
             request.sni.empty() ? "unknown" : request.sni,
             log_reason,
             host,
             port,
             request.client_hello_record.size());

    boost::asio::ip::tcp::socket upstream_socket(io_context_);
    DEFER(if (request.client_socket != nullptr) { close_tcp_socket(*request.client_socket); } close_tcp_socket(upstream_socket););

    co_await connect_target(upstream_socket, request, host, port, ec);
    if (ec)
    {
        co_return;
    }

    co_await write_initial_client_hello(upstream_socket, request, host, port, request.client_hello_record, ec);
    if (ec)
    {
        co_return;
    }

    boost::asio::steady_timer idle_timer(io_context_);
    uint64_t last_activity_time_ms = relay::net::now_ms();
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    relay::tcp_socket_stream_relay_transport inbound_transport(*request.client_socket, cfg_.timeout);
    relay::tcp_socket_stream_relay_transport outbound_transport(upstream_socket, cfg_.timeout);
    relay::stream_relay_context relay_context{
        .inbound = inbound_transport,
        .outbound = outbound_transport,
        .idle_timer = idle_timer,
        .timeout = cfg_.timeout,
        .trace_id = 0,
        .conn_id = request.conn_id,
        .log_event_name = relay::log_event::kFallback,
        .inbound_to_outbound_stage = "client_to_target",
        .outbound_to_inbound_stage = "target_to_client",
        .last_activity_time_ms = last_activity_time_ms,
        .tx_bytes = tx_bytes,
        .rx_bytes = rx_bytes,
    };
    const auto relay_result = co_await relay::relay_streams(relay_context);
    LOG_INFO("{} conn {} remote {}:{} finished target {}:{}",
             relay::log_event::kFallback,
             request.conn_id,
             request.remote_addr.empty() ? "unknown" : request.remote_addr,
             request.remote_port,
             host,
             port);
    (void)relay_result;
}

boost::asio::awaitable<void> fallback_executor::connect_target(boost::asio::ip::tcp::socket& upstream_socket,
                                                               const fallback_request& request,
                                                               const std::string& host,
                                                               uint16_t port,
                                                               boost::system::error_code& ec) const
{
    boost::asio::ip::tcp::resolver resolver(io_context_);
    const auto endpoints = co_await relay::net::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} remote {}:{} stage resolve target {}:{} error {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 host,
                 port,
                 ec.message());
        co_return;
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_WARN("{} conn {} remote {}:{} stage resolve target {}:{} error {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 host,
                 port,
                 ec.message());
        co_return;
    }

    if (upstream_socket.is_open())
    {
        close_tcp_socket(upstream_socket);
    }

    co_await relay::net::wait_connect_with_timeout(upstream_socket, endpoints, cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} remote {}:{} stage connect target {}:{} error {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 host,
                 port,
                 ec.message());
        co_return;
    }

    boost::system::error_code no_delay_ec;
    no_delay_ec = upstream_socket.set_option(boost::asio::ip::tcp::no_delay(true), no_delay_ec);
    if (no_delay_ec)
    {
        LOG_WARN("{} conn {} remote {}:{} stage connect target {}:{} set no delay error {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 host,
                 port,
                 no_delay_ec.message());
    }

    LOG_INFO("{} conn {} remote {}:{} stage connect target {}:{} connected",
             relay::log_event::kFallback,
             request.conn_id,
             request.remote_addr,
             request.remote_port,
             host,
             port);
}

boost::asio::awaitable<void> fallback_executor::write_initial_client_hello(boost::asio::ip::tcp::socket& upstream_socket,
                                                                           const fallback_request& request,
                                                                           const std::string& host,
                                                                           uint16_t port,
                                                                           const std::vector<uint8_t>& client_hello_record,
                                                                           boost::system::error_code& ec) const
{
    const auto initial_write =
        co_await relay::net::wait_write_with_timeout(upstream_socket, boost::asio::buffer(client_hello_record), cfg_.timeout.write, ec);
    if (ec || initial_write != client_hello_record.size())
    {
        if (!ec)
        {
            ec = boost::asio::error::fault;
        }
        LOG_WARN("{} conn {} remote {}:{} stage initial_write target {}:{} error {}",
                 relay::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 request.remote_port,
                 host,
                 port,
                 ec.message());
        co_return;
    }
}

}    // namespace reality
