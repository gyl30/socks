#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "constants.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "remote_tcp_proxy_session.h"

namespace relay
{

remote_tcp_proxy_session::remote_tcp_proxy_session(boost::asio::io_context& io_context,
                                                   std::shared_ptr<proxy_reality_connection> connection,
                                                   const uint32_t conn_id,
                                                   const uint64_t trace_id,
                                                   const config& cfg)
    : conn_id_(conn_id), trace_id_(trace_id), cfg_(cfg), target_socket_(io_context), idle_timer_(io_context), connection_(std::move(connection))
{
    last_activity_time_ms_ = net::now_ms();
}

boost::asio::awaitable<void> remote_tcp_proxy_session::start(const proxy::tcp_connect_request& request) { co_await run(request); }

boost::asio::awaitable<void> remote_tcp_proxy_session::run(const proxy::tcp_connect_request& request)
{
    boost::system::error_code close_ec;
    const auto close_target = [&]()
    {
        close_ec.clear();
        close_ec = target_socket_.close(close_ec);
        (void)close_ec;
    };

    target_host_ = request.target_host;
    target_port_ = request.target_port;
    bind_host_ = "0.0.0.0";
    bind_port_ = 0;

    LOG_INFO("{} trace {:016x} conn {} target {}:{} remote {}:{} connecting",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             connection_ != nullptr ? std::string(connection_->remote_host()) : "unknown",
             connection_ != nullptr ? connection_->remote_port() : 0);

    boost::asio::ip::tcp::resolver resolver(target_socket_.get_executor());
    boost::asio::ip::tcp::resolver::results_type resolve_res;
    if (!(co_await resolve_target(resolver, resolve_res)))
    {
        close_target();
        co_return;
    }
    if (!(co_await connect_target(resolve_res)))
    {
        close_target();
        co_return;
    }
    if (!(co_await send_connect_reply(socks::kRepSuccess)))
    {
        close_target();
        co_return;
    }

    co_await relay_target();
    close_target();
    log_close_summary();
}

boost::asio::awaitable<bool> remote_tcp_proxy_session::resolve_target(boost::asio::ip::tcp::resolver& resolver,
                                                                      boost::asio::ip::tcp::resolver::results_type& resolve_res)
{
    boost::system::error_code ec;
    resolve_res = co_await net::wait_resolve_with_timeout(resolver, target_host_, std::to_string(target_port_), cfg_.timeout.connect, ec);
    if (ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(ec);
        LOG_WARN("{} trace {:016x} conn {} target {}:{} resolve failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 ec.message(),
                 rep);
        co_await send_connect_reply(rep);
        co_return false;
    }
    if (resolve_res.begin() == resolve_res.end())
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} resolve empty rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 socks::kRepHostUnreach);
        co_await send_connect_reply(socks::kRepHostUnreach);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> remote_tcp_proxy_session::connect_target(const boost::asio::ip::tcp::resolver::results_type& resolve_res)
{
    boost::system::error_code connect_ec = boost::asio::error::host_unreachable;
    co_await net::wait_connect_with_timeout(target_socket_, resolve_res, cfg_.timeout.connect, connect_ec);

    if (connect_ec)
    {
        const auto rep = socks::map_connect_error_to_socks_rep(connect_ec);
        LOG_WARN("{} trace {:016x} conn {} target {}:{} connect failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 connect_ec.message(),
                 rep);
        co_await send_connect_reply(rep);
        co_return false;
    }

    connect_ec = target_socket_.set_option(boost::asio::ip::tcp::no_delay(true), connect_ec);
    if (connect_ec)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} stage set_no_delay error {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 connect_ec.message());
    }

    const auto local_ep = target_socket_.local_endpoint(connect_ec);
    if (connect_ec)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} stage query_bind_endpoint error {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 connect_ec.message());
        co_await send_connect_reply(socks::kRepGenFail);
        co_return false;
    }

    bind_host_ = local_ep.address().to_string();
    bind_port_ = local_ep.port();
    LOG_INFO("{} trace {:016x} conn {} target {}:{} connected bind {}:{}",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_);
    co_return true;
}

boost::asio::awaitable<bool> remote_tcp_proxy_session::send_connect_reply(const uint8_t socks_rep)
{
    if (connection_ == nullptr)
    {
        co_return false;
    }
    proxy::tcp_connect_reply reply;
    reply.socks_rep = socks_rep;
    reply.bind_host = bind_host_;
    reply.bind_port = bind_port_;
    std::vector<uint8_t> packet;
    if (!proxy::encode_tcp_connect_reply(reply, packet))
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} bind {}:{} encode tcp connect reply failed rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 socks_rep);
        co_return false;
    }

    boost::system::error_code ec;
    co_await connection_->write_packet(packet, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} bind {}:{} send tcp connect reply failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 bind_host_,
                 bind_port_,
                 ec.message(),
                 socks_rep);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> remote_tcp_proxy_session::relay_target()
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;

    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_target() && target_to_client());
        co_return;
    }

    co_await ((client_to_target() && target_to_client()) || idle_watchdog());
}

boost::asio::awaitable<void> remote_tcp_proxy_session::client_to_target()
{
    if (connection_ == nullptr)
    {
        co_return;
    }

    std::vector<uint8_t> buffer(8192);
    for (;;)
    {
        boost::system::error_code ec;
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto bytes_read = co_await connection_->read_some(buffer, read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                (void)shutdown_ec;
            }
            else
            {
                LOG_INFO("{} trace {:016x} conn {} target {}:{} client_to_target finished {}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         target_host_,
                         target_port_,
                         ec.message());
            }
            break;
        }
        co_await net::wait_write_with_timeout(target_socket_, boost::asio::buffer(buffer.data(), bytes_read), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} target {}:{} client_to_target write failed {}",
                     log_event::kDataSend,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     ec.message());
            break;
        }
        tx_bytes_ += bytes_read;
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> remote_tcp_proxy_session::target_to_client()
{
    if (connection_ == nullptr)
    {
        co_return;
    }

    std::vector<uint8_t> buffer(8192);
    for (;;)
    {
        boost::system::error_code ec;
        const auto bytes_read =
            co_await target_socket_.async_read_some(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                co_await connection_->shutdown_send(shutdown_ec);
            }
            else
            {
                LOG_INFO("{} trace {:016x} conn {} target {}:{} target_to_client finished {}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         target_host_,
                         target_port_,
                         ec.message());
            }
            break;
        }
        co_await connection_->write(std::span<const uint8_t>(buffer.data(), bytes_read), ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} target {}:{} target_to_client write failed {}",
                     log_event::kDataSend,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     ec.message());
            break;
        }
        rx_bytes_ += bytes_read;
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> remote_tcp_proxy_session::idle_watchdog()
{
    const auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;
    while (true)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_WARN("{} trace {:016x} conn {} target {}:{} bind {}:{} idle timeout {}s",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     bind_host_,
                     bind_port_,
                     cfg_.timeout.idle);
            break;
        }
    }
}

void remote_tcp_proxy_session::log_close_summary() const
{
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} target {}:{} bind {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             bind_host_,
             bind_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

}    // namespace relay
