#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "outbound.h"
#include "router.h"
#include "trace_id.h"
#include "tcp_outbound_stream.h"
#include "constants.h"
#include "net_utils.h"
#include "tproxy_tcp_session.h"

namespace relay
{

namespace
{
std::string describe_endpoint(const boost::asio::ip::tcp::endpoint& endpoint)
{
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

std::string describe_endpoint_error(const boost::system::error_code& ec) { return std::string("<error:") + ec.message() + ">"; }

}    // namespace

tproxy_tcp_session::tproxy_tcp_session(boost::asio::ip::tcp::socket socket,
                                       std::shared_ptr<router> router,
                                       uint32_t sid,
                                       const config& cfg,
                                       const config::tproxy_t& settings)
    : trace_id_(generate_trace_id()),
      conn_id_(sid),
      socket_(std::move(socket)),
      idle_timer_(socket_.get_executor()),
      router_(std::move(router)),
      cfg_(cfg),
      settings_(settings)
{
    last_activity_time_ms_ = net::now_ms();
}

boost::asio::awaitable<void> tproxy_tcp_session::start() { co_await run(); }

void tproxy_tcp_session::stop()
{
    idle_timer_.cancel();

    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} shutdown client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_addr_.empty() ? "unknown" : client_addr_,
                 client_port_,
                 target_addr_.empty() ? "unknown" : target_addr_,
                 target_port_,
                 ec.message());
    }
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} close client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_addr_.empty() ? "unknown" : client_addr_,
                 client_port_,
                 target_addr_.empty() ? "unknown" : target_addr_,
                 target_port_,
                 ec.message());
    }
}

boost::asio::awaitable<void> tproxy_tcp_session::run()
{
    boost::asio::ip::tcp::endpoint target_ep;
    if (!resolve_target_endpoint(target_ep))
    {
        co_return;
    }

    boost::system::error_code local_ec;
    const auto local_ep = socket_.local_endpoint(local_ec);
    if (detect_routing_loop(target_ep, local_ec, local_ep))
    {
        co_return;
    }

    boost::system::error_code peer_ec;
    const auto peer_ep = socket_.remote_endpoint(peer_ec);
    update_session_endpoints(target_ep, local_ec, local_ep, peer_ec, peer_ep);
    log_redirected_connection();

    const auto target_addr = net::normalize_address(target_ep.address());
    const auto [decision, backend] = co_await select_backend(target_addr);
    if (backend == nullptr)
    {
        co_return;
    }
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             target_addr_,
             target_port_,
             decision.matched ? decision.outbound_tag : decision.outbound_type);
    if (!(co_await connect_backend(decision.route, backend)))
    {
        co_return;
    }

    co_await relay_backend(backend);
    co_await backend->close();
    close_client_socket();
    log_close_summary();
}

bool tproxy_tcp_session::resolve_target_endpoint(boost::asio::ip::tcp::endpoint& target_ep)
{
    boost::system::error_code ec;
    if (net::get_original_tcp_dst(socket_, target_ep, ec))
    {
        return true;
    }

    boost::system::error_code local_ec;
    const auto local_ep = socket_.local_endpoint(local_ec);
    boost::system::error_code peer_ec;
    const auto peer_ep = socket_.remote_endpoint(peer_ec);
    LOG_WARN("{} trace {:016x} conn {} original dst failed reason {} local {} peer {}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             ec.message(),
             local_ec ? describe_endpoint_error(local_ec) : describe_endpoint(local_ep),
             peer_ec ? describe_endpoint_error(peer_ec) : describe_endpoint(peer_ep));
    return false;
}

bool tproxy_tcp_session::detect_routing_loop(const boost::asio::ip::tcp::endpoint& target_ep,
                                             const boost::system::error_code& local_ec,
                                             const boost::asio::ip::tcp::endpoint& local_ep) const
{
    if (settings_.tcp_port == 0 || local_ec)
    {
        return false;
    }

    const auto target_addr = net::normalize_address(target_ep.address());
    const auto local_addr = net::normalize_address(local_ep.address());
    if (target_ep.port() != settings_.tcp_port || target_addr != local_addr)
    {
        return false;
    }

    LOG_WARN("{} trace {:016x} conn {} tproxy routing loop detected target {}:{} local {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             target_addr.to_string(),
             target_ep.port(),
             local_addr.to_string(),
             local_ep.port());
    return true;
}

void tproxy_tcp_session::update_session_endpoints(const boost::asio::ip::tcp::endpoint& target_ep,
                                                  const boost::system::error_code& local_ec,
                                                  const boost::asio::ip::tcp::endpoint& local_ep,
                                                  const boost::system::error_code& peer_ec,
                                                  const boost::asio::ip::tcp::endpoint& peer_ep)
{
    target_addr_ = net::normalize_address(target_ep.address()).to_string();
    target_port_ = target_ep.port();
    if (!local_ec)
    {
        local_addr_ = net::normalize_address(local_ep.address()).to_string();
        local_port_ = local_ep.port();
    }
    if (!peer_ec)
    {
        client_addr_ = net::normalize_address(peer_ep.address()).to_string();
        client_port_ = peer_ep.port();
    }
}

void tproxy_tcp_session::log_redirected_connection() const
{
    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} redirected",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_addr_.empty() ? "unknown" : client_addr_,
             client_port_,
             local_addr_.empty() ? "unknown" : local_addr_,
             local_port_,
             target_addr_,
             target_port_);
}

boost::asio::awaitable<std::pair<route_decision, std::shared_ptr<tcp_outbound_stream>>> tproxy_tcp_session::select_backend(const boost::asio::ip::address& addr)
{
    if (router_ == nullptr)
    {
        LOG_WARN(
            "{} trace {:016x} conn {} target {}:{} router unavailable", log_event::kRoute, trace_id_, conn_id_, target_addr_, target_port_);
        co_return std::make_pair(route_decision{}, std::shared_ptr<tcp_outbound_stream>(nullptr));
    }

    const auto decision = co_await router_->decide_ip_detail(addr);
    if (decision.route == route_type::kBlock)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} blocked", log_event::kRoute, trace_id_, conn_id_, addr.to_string(), target_port_);
        co_return std::make_pair(decision, std::shared_ptr<tcp_outbound_stream>(nullptr));
    }
    if (decision.route != route_type::kDirect && decision.route != route_type::kProxy)
    {
        co_return std::make_pair(route_decision{}, std::shared_ptr<tcp_outbound_stream>(nullptr));
    }
    const auto handler = make_outbound_handler(cfg_, decision.outbound_tag);
    if (handler == nullptr)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} out_tag {} outbound handler unavailable",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 addr.to_string(),
                 target_port_,
                 decision.outbound_tag);
        co_return std::make_pair(decision, std::shared_ptr<tcp_outbound_stream>(nullptr));
    }
    const auto backend = handler->create_tcp_upstream(socket_.get_executor(), conn_id_, trace_id_, cfg_);
    co_return std::make_pair(decision, backend);
}

boost::asio::awaitable<bool> tproxy_tcp_session::connect_backend(route_type route, const std::shared_ptr<tcp_outbound_stream>& backend)
{
    const auto connect_result = co_await backend->connect(target_addr_, target_port_);
    if (connect_result.ec)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} connect failed error {} rep {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 target_addr_,
                 target_port_,
                 relay::to_string(route),
                 connect_result.ec.message(),
                 connect_result.socks_rep);
        co_await backend->close();
        co_return false;
    }

    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             target_addr_,
             target_port_,
             relay::to_string(route));
    co_return true;
}

boost::asio::awaitable<void> tproxy_tcp_session::relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;

    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_upstream(backend) && upstream_to_client(backend));
        co_return;
    }

    co_await ((client_to_upstream(backend) && upstream_to_client(backend)) || idle_watchdog());
}

boost::asio::awaitable<void> tproxy_tcp_session::client_to_upstream(std::shared_ptr<tcp_outbound_stream> backend)
{
    std::vector<uint8_t> buf(8192);
    boost::system::error_code ec;
    for (;;)
    {
        const std::size_t n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                co_await backend->shutdown_send(shutdown_ec);
                if (shutdown_ec)
                {
                    LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} stage client_to_upstream shutdown backend send failed {}",
                             log_event::kSocks,
                             trace_id_,
                             conn_id_,
                             client_addr_.empty() ? "unknown" : client_addr_,
                             client_port_,
                             target_addr_.empty() ? "unknown" : target_addr_,
                             target_port_,
                             shutdown_ec.message());
                }
            }
            else
            {
                LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} stage client_to_upstream client read finished {}",
                         log_event::kSocks,
                         trace_id_,
                         conn_id_,
                         client_addr_.empty() ? "unknown" : client_addr_,
                         client_port_,
                         target_addr_.empty() ? "unknown" : target_addr_,
                         target_port_,
                         ec.message());
                co_await backend->close();
            }
            break;
        }
        const std::vector<uint8_t> data_buf(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await backend->write(data_buf, ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} stage client_to_upstream failed to write to backend {}",
                     log_event::kSocks,
                     trace_id_,
                     conn_id_,
                     client_addr_.empty() ? "unknown" : client_addr_,
                     client_port_,
                     target_addr_.empty() ? "unknown" : target_addr_,
                     target_port_,
                     ec.message());
            co_await backend->close();
            break;
        }
        tx_bytes_ += n;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} stage client_to_upstream finished tx_bytes {}",
             log_event::kSocks,
             trace_id_,
             conn_id_,
             client_addr_.empty() ? "unknown" : client_addr_,
             client_port_,
             target_addr_.empty() ? "unknown" : target_addr_,
             target_port_,
             tx_bytes_);
}

boost::asio::awaitable<void> tproxy_tcp_session::upstream_to_client(std::shared_ptr<tcp_outbound_stream> backend)
{
    std::vector<uint8_t> buf(8192);
    boost::system::error_code ec;
    for (;;)
    {
        const auto n = co_await backend->read(buf, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec && shutdown_ec != boost::asio::error::not_connected)
                {
                    LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} stage upstream_to_client shutdown client send failed {}",
                             log_event::kSocks,
                             trace_id_,
                             conn_id_,
                             client_addr_.empty() ? "unknown" : client_addr_,
                             client_port_,
                             target_addr_.empty() ? "unknown" : target_addr_,
                             target_port_,
                             shutdown_ec.message());
                }
            }
            else
            {
                if (net::is_channel_close_error(ec) || ec == boost::asio::error::connection_reset)
                {
                    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} stage upstream_to_client backend read stopped {} code {}",
                             log_event::kSocks,
                             trace_id_,
                             conn_id_,
                             client_addr_.empty() ? "unknown" : client_addr_,
                             client_port_,
                             target_addr_.empty() ? "unknown" : target_addr_,
                             target_port_,
                             ec.message(),
                             ec.value());
                }
                else
                {
                    LOG_WARN(
                        "{} trace {:016x} conn {} client {}:{} target {}:{} stage upstream_to_client failed to read from backend {} code "
                        "{}",
                        log_event::kSocks,
                        trace_id_,
                        conn_id_,
                        client_addr_.empty() ? "unknown" : client_addr_,
                        client_port_,
                        target_addr_.empty() ? "unknown" : target_addr_,
                        target_port_,
                        ec.message(),
                        ec.value());
                }
                ec = socket_.close(ec);
                if (ec)
                {
                    LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} close client failed {}",
                             log_event::kSocks,
                             trace_id_,
                             conn_id_,
                             client_addr_.empty() ? "unknown" : client_addr_,
                             client_port_,
                             target_addr_.empty() ? "unknown" : target_addr_,
                             target_port_,
                             ec.message());
                }
            }
            break;
        }
        boost::system::error_code write_ec;
        auto write_size = co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(buf.data(), n), cfg_.timeout.write, write_ec);
        if (write_ec)
        {
            LOG_WARN(
                "{} trace {:016x} conn {} client {}:{} target {}:{} stage upstream_to_client failed to write to client bytes {} code {} "
                "error {}",
                log_event::kSocks,
                trace_id_,
                conn_id_,
                client_addr_.empty() ? "unknown" : client_addr_,
                client_port_,
                target_addr_.empty() ? "unknown" : target_addr_,
                target_port_,
                n,
                write_ec.value(),
                write_ec.message());
            co_await backend->close();
            break;
        }
        rx_bytes_ += write_size;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} stage upstream_to_client finished rx_bytes {}",
             log_event::kSocks,
             trace_id_,
             conn_id_,
             client_addr_.empty() ? "unknown" : client_addr_,
             client_port_,
             target_addr_.empty() ? "unknown" : target_addr_,
             target_port_,
             rx_bytes_);
}

boost::asio::awaitable<void> tproxy_tcp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    const auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;

    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = net::now_ms() - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} idle_timeout_sec {} tcp session idle closing",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_addr_.empty() ? "unknown" : client_addr_,
                     client_port_,
                     target_addr_.empty() ? "unknown" : target_addr_,
                     target_port_,
                     cfg_.timeout.idle);
            break;
        }
    }
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} stage idle_watchdog close client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_addr_.empty() ? "unknown" : client_addr_,
                 client_port_,
                 target_addr_.empty() ? "unknown" : target_addr_,
                 target_port_,
                 ec.message());
    }
}

void tproxy_tcp_session::close_client_socket()
{
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} close client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_addr_.empty() ? "unknown" : client_addr_,
                 client_port_,
                 target_addr_.empty() ? "unknown" : target_addr_,
                 target_port_,
                 ec.message());
    }
}

void tproxy_tcp_session::log_close_summary() const
{
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_addr_.empty() ? "unknown" : client_addr_,
             client_port_,
             target_addr_.empty() ? "unknown" : target_addr_,
             target_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

}    // namespace relay
