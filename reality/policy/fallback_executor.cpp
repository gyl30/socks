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

fallback_executor::fallback_executor(boost::asio::io_context& io_context, const mux::config& cfg) : io_context_(io_context), cfg_(cfg) {}

boost::asio::awaitable<void> fallback_executor::run(
    fallback_request& request, const std::string& host, uint16_t port, const char* reason, boost::system::error_code& ec) const
{
    ec.clear();
    const char* log_reason = normalize_reason(reason);
    if (request.client_socket == nullptr)
    {
        ec = boost::asio::error::bad_descriptor;
        LOG_WARN("event {} conn_id {} remote {} reason {} missing client socket",
                 mux::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 log_reason);
        co_return;
    }

    LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} sni {} reason {} target {}:{} client_hello_size {}",
             mux::log_event::kFallback,
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

    co_await relay_bidirectional(*request.client_socket, upstream_socket, request);
    LOG_INFO("event {} conn_id {} remote {}:{} finished target {}:{}",
             mux::log_event::kFallback,
             request.conn_id,
             request.remote_addr.empty() ? "unknown" : request.remote_addr,
             request.remote_port,
             host,
             port);
}

boost::asio::awaitable<void> fallback_executor::connect_target(boost::asio::ip::tcp::socket& upstream_socket,
                                                               const fallback_request& request,
                                                               const std::string& host,
                                                               uint16_t port,
                                                               boost::system::error_code& ec) const
{
    ec.clear();

    boost::asio::ip::tcp::resolver resolver(io_context_);
    const auto endpoints = co_await mux::net::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} remote {} stage resolve target {}:{} error {}",
                 mux::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 host,
                 port,
                 ec.message());
        co_return;
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_WARN("event {} conn_id {} remote {} stage resolve target {}:{} error {}",
                 mux::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 host,
                 port,
                 ec.message());
        co_return;
    }

    boost::system::error_code last_ec = boost::asio::error::host_unreachable;
    for (const auto& entry : endpoints)
    {
        if (upstream_socket.is_open())
        {
            close_tcp_socket(upstream_socket);
        }

        boost::system::error_code op_ec;
        op_ec = upstream_socket.open(entry.endpoint().protocol(), op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }

        op_ec = upstream_socket.set_option(boost::asio::ip::tcp::no_delay(true), op_ec);
        if (op_ec)
        {
            last_ec = op_ec;
            continue;
        }

        co_await mux::net::wait_connect_with_timeout(upstream_socket, entry.endpoint(), cfg_.timeout.connect, op_ec);
        if (!op_ec)
        {
            ec.clear();
            LOG_INFO("event {} conn_id {} remote {} stage connect target {}:{} connected",
                     mux::log_event::kFallback,
                     request.conn_id,
                     request.remote_addr,
                     host,
                     port);
            co_return;
        }

        last_ec = op_ec;
    }

    ec = last_ec;
    LOG_WARN("event {} conn_id {} remote {} stage connect target {}:{} error {}",
             mux::log_event::kFallback,
             request.conn_id,
             request.remote_addr,
             host,
             port,
             ec.message());
}

boost::asio::awaitable<void> fallback_executor::write_initial_client_hello(boost::asio::ip::tcp::socket& upstream_socket,
                                                                           const fallback_request& request,
                                                                           const std::string& host,
                                                                           uint16_t port,
                                                                           const std::vector<uint8_t>& client_hello_record,
                                                                           boost::system::error_code& ec) const
{
    ec.clear();

    const auto initial_write =
        co_await mux::net::wait_write_with_timeout(upstream_socket, boost::asio::buffer(client_hello_record), cfg_.timeout.write, ec);
    if (ec || initial_write != client_hello_record.size())
    {
        if (!ec)
        {
            ec = boost::asio::error::fault;
        }
        LOG_WARN("event {} conn_id {} remote {} stage initial_write target {}:{} error {}",
                 mux::log_event::kFallback,
                 request.conn_id,
                 request.remote_addr,
                 host,
                 port,
                 ec.message());
        co_return;
    }
}

boost::asio::awaitable<void> fallback_executor::relay_data(boost::asio::ip::tcp::socket& src,
                                                           boost::asio::ip::tcp::socket& dst,
                                                           const fallback_request& request,
                                                           const char* direction) const
{
    const auto fallback_timeout = cfg_.timeout.idle;
    boost::system::error_code ec;
    std::vector<uint8_t> buf(constants::fallback::kRelayBufferSize);
    for (;;)
    {
        const auto n = co_await mux::net::wait_read_some_with_timeout(src, boost::asio::buffer(buf), fallback_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = dst.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec && shutdown_ec != boost::asio::error::not_connected)
                {
                    LOG_WARN("event {} conn_id {} remote {} stage {} shutdown send error {}",
                             mux::log_event::kFallback,
                             request.conn_id,
                             request.remote_addr,
                             direction,
                             shutdown_ec.message());
                }
                co_return;
            }
            if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::connection_reset)
            {
                LOG_WARN("event {} conn_id {} remote {} stage {} read error {}",
                         mux::log_event::kFallback,
                         request.conn_id,
                         request.remote_addr,
                         direction,
                         ec.message());
            }
            close_tcp_socket(dst);
            co_return;
        }
        if (n == 0)
        {
            co_return;
        }

        const auto written = co_await mux::net::wait_write_with_timeout(dst, boost::asio::buffer(buf.data(), n), fallback_timeout, ec);
        if (ec)
        {
            LOG_WARN("event {} conn_id {} remote {} stage {} write error {}",
                     mux::log_event::kFallback,
                     request.conn_id,
                     request.remote_addr,
                     direction,
                     ec.message());
            co_return;
        }
        if (written != n)
        {
            ec = boost::asio::error::fault;
            LOG_WARN("event {} conn_id {} remote {} stage {} short write {} of {}",
                     mux::log_event::kFallback,
                     request.conn_id,
                     request.remote_addr,
                     direction,
                     written,
                     n);
            co_return;
        }
    }
}

boost::asio::awaitable<void> fallback_executor::relay_bidirectional(boost::asio::ip::tcp::socket& client_socket,
                                                                    boost::asio::ip::tcp::socket& upstream_socket,
                                                                    const fallback_request& request) const
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    co_await (relay_data(client_socket, upstream_socket, request, "client_to_target") &&
              relay_data(upstream_socket, client_socket, request, "target_to_client"));
}

}    // namespace reality
