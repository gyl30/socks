#include <string>
#include <vector>
#include <cstdint>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "timeout_io.h"
#include "log_context.h"
#include "scoped_exit.h"
#include "reality/policy/fallback_executor.h"

namespace reality
{

namespace
{

void close_tcp_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket.close(ec);
}

void record_fallback_resolve_failure(const boost::system::error_code& ec)
{
    (void)ec;
}

void record_fallback_connect_failure(const boost::system::error_code& ec)
{
    (void)ec;
}

void record_fallback_write_failure(const boost::system::error_code& ec)
{
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

fallback_executor::fallback_executor(dependencies deps)
    : io_context_(deps.io_context),
      cfg_(deps.cfg),
      options_(deps.opts)
{
    if (options_.relay_buffer_size == 0)
    {
        options_.relay_buffer_size = 1;
    }
}

boost::asio::awaitable<void> fallback_executor::run(fallback_request& request,
                                                    const std::string& host,
                                                    const std::uint16_t port,
                                                    const char* reason,
                                                    boost::system::error_code& ec) const
{
    ec.clear();
    const char* log_reason = normalize_reason(reason);
    auto& ctx = request.ctx;
    if (request.client_socket == nullptr)
    {
        ec = boost::asio::error::bad_descriptor;
        LOG_CTX_WARN(ctx, "{} reason {} missing client socket", mux::log_event::kFallback, log_reason);
        co_return;
    }

    ctx.set_target(host, port);
    LOG_CTX_INFO(ctx,
                 "{} reason {} target {}:{} client_hello_size {}",
                 mux::log_event::kFallback,
                 log_reason,
                 host,
                 port,
                 request.client_hello_record.size());

    boost::asio::ip::tcp::socket upstream_socket(io_context_);
    DEFER(if (request.client_socket != nullptr) { close_tcp_socket(*request.client_socket); } close_tcp_socket(upstream_socket););

    co_await connect_target(upstream_socket, ctx, host, port, ec);
    if (ec)
    {
        co_return;
    }

    co_await write_initial_client_hello(upstream_socket, ctx, host, port, request.client_hello_record, ec);
    if (ec)
    {
        co_return;
    }

    co_await relay_bidirectional(*request.client_socket, upstream_socket, ctx);
    LOG_CTX_INFO(ctx, "{} finished target {}:{}", mux::log_event::kFallback, host, port);
}

boost::asio::awaitable<void> fallback_executor::connect_target(boost::asio::ip::tcp::socket& upstream_socket,
                                                               const mux::connection_context& ctx,
                                                               const std::string& host,
                                                               const std::uint16_t port,
                                                               boost::system::error_code& ec) const
{
    ec.clear();

    boost::asio::ip::tcp::resolver resolver(io_context_);
    const auto endpoints =
        co_await mux::timeout_io::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        record_fallback_resolve_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage resolve target {}:{} error {}", mux::log_event::kFallback, host, port, ec.message());
        co_return;
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        record_fallback_resolve_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage resolve target {}:{} error {}", mux::log_event::kFallback, host, port, ec.message());
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

        co_await mux::timeout_io::wait_connect_with_timeout(upstream_socket, entry.endpoint(), cfg_.timeout.connect, op_ec);
        if (!op_ec)
        {
            ec.clear();
            LOG_CTX_INFO(ctx, "{} stage connect target {}:{} connected", mux::log_event::kFallback, host, port);
            co_return;
        }

        last_ec = op_ec;
    }

    ec = last_ec;
    record_fallback_connect_failure(ec);
    LOG_CTX_WARN(ctx, "{} stage connect target {}:{} error {}", mux::log_event::kFallback, host, port, ec.message());
}

boost::asio::awaitable<void> fallback_executor::write_initial_client_hello(boost::asio::ip::tcp::socket& upstream_socket,
                                                                           const mux::connection_context& ctx,
                                                                           const std::string& host,
                                                                           const std::uint16_t port,
                                                                           const std::vector<std::uint8_t>& client_hello_record,
                                                                           boost::system::error_code& ec) const
{
    ec.clear();

    const auto initial_write = co_await mux::timeout_io::wait_write_with_timeout(
        upstream_socket, boost::asio::buffer(client_hello_record), cfg_.timeout.write, ec);
    if (ec || initial_write != client_hello_record.size())
    {
        if (!ec)
        {
            ec = boost::asio::error::fault;
        }
        record_fallback_write_failure(ec);
        LOG_CTX_WARN(ctx, "{} stage initial_write target {}:{} error {}", mux::log_event::kFallback, host, port, ec.message());
        co_return;
    }
}

boost::asio::awaitable<void> fallback_executor::relay_data(boost::asio::ip::tcp::socket& src,
                                                           boost::asio::ip::tcp::socket& dst,
                                                           const mux::connection_context& ctx,
                                                           const char* direction) const
{
    const auto fallback_timeout = cfg_.timeout.idle;
    boost::system::error_code ec;
    std::vector<std::uint8_t> buf(options_.relay_buffer_size);
    for (;;)
    {
        const auto n = co_await mux::timeout_io::wait_read_some_with_timeout(src, boost::asio::buffer(buf), fallback_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = dst.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec && shutdown_ec != boost::asio::error::not_connected)
                {
                    LOG_CTX_WARN(
                        ctx, "{} stage {} shutdown send error {}", mux::log_event::kFallback, direction, shutdown_ec.message());
                }
                co_return;
            }
            if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::connection_reset)
            {
                LOG_CTX_WARN(ctx, "{} stage {} read error {}", mux::log_event::kFallback, direction, ec.message());
            }
            close_tcp_socket(dst);
            co_return;
        }
        if (n == 0)
        {
            co_return;
        }

        const auto written = co_await mux::timeout_io::wait_write_with_timeout(
            dst, boost::asio::buffer(buf.data(), n), fallback_timeout, ec);
        if (ec)
        {
            record_fallback_write_failure(ec);
            LOG_CTX_WARN(ctx, "{} stage {} write error {}", mux::log_event::kFallback, direction, ec.message());
            co_return;
        }
        if (written != n)
        {
            ec = boost::asio::error::fault;
            record_fallback_write_failure(ec);
            LOG_CTX_WARN(ctx, "{} stage {} short write {} of {}", mux::log_event::kFallback, direction, written, n);
            co_return;
        }
    }
}

boost::asio::awaitable<void> fallback_executor::relay_bidirectional(boost::asio::ip::tcp::socket& client_socket,
                                                                    boost::asio::ip::tcp::socket& upstream_socket,
                                                                    const mux::connection_context& ctx) const
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    co_await (relay_data(client_socket, upstream_socket, ctx, "client_to_target") &&
              relay_data(upstream_socket, client_socket, ctx, "target_to_client"));
}

}    // namespace reality
