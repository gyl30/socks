#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "outbound.h"
#include "router.h"
#include "protocol.h"
#include "trace_store.h"
#include "tcp_outbound_stream.h"
#include "net_utils.h"
#include "scoped_exit.h"
#include "socks_tcp_connect_session.h"

namespace relay
{

socks_tcp_connect_session::socks_tcp_connect_session(boost::asio::ip::tcp::socket socket,
                                                     std::shared_ptr<router> router,
                                                     uint32_t sid,
                                                     uint64_t trace_id,
                                                     std::string inbound_tag,
                                                     const config& cfg)
    : trace_id_(trace_id),
      conn_id_(sid),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      socket_(std::move(socket)),
      idle_timer_(socket_.get_executor()),
      router_(std::move(router))
{
    last_activity_time_ms_ = net::now_ms();
    net::load_tcp_socket_endpoints(socket_, local_host_, local_port_, client_host_, client_port_);
}

boost::asio::awaitable<void> socks_tcp_connect_session::start(const std::string& host, uint16_t port) { co_await run(host, port); }

void socks_tcp_connect_session::stop() { close_client_socket(); }

boost::asio::awaitable<void> socks_tcp_connect_session::run(const std::string& host, uint16_t port)
{
    DEFER(close_client_socket());

    if (router_ == nullptr)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kRouteDecideDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .target_host = host,
            .target_port = port,
            .local_host = local_host_,
            .local_port = local_port_,
            .remote_host = client_host_,
            .remote_port = client_port_,
            .error_message = "router unavailable",
        });
        LOG_ERROR("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} router unavailable",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  client_host_,
                  client_port_,
                  local_host_,
                  local_port_,
                  host,
                  port);
        co_await reply_error(socks::kRepGenFail);
        co_return;
    }

    boost::system::error_code ec;
    const auto target_addr = boost::asio::ip::make_address(host, ec);
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    if (ec)
    {
        decision = co_await router_->decide_domain_detail(host);
    }
    else
    {
        decision = co_await router_->decide_ip_detail(target_addr);
    }
    target_host_ = host;
    target_port_ = port;
    route_name_ = decision.matched ? decision.outbound_tag : decision.outbound_type;
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
    });

    const auto backend = create_backend(decision.route, decision.outbound_tag);
    if (backend == nullptr)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .target_host = host,
            .target_port = port,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .error_message = "route blocked",
        });
        LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} blocked",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 client_host_,
                 client_port_,
                 local_host_,
                 local_port_,
                 host,
                 port,
                 route_name_);
        co_await reply_error(socks::kRepNotAllowed);
        co_return;
    }
    const auto connect_result = co_await connect_backend(backend, host, port, decision.route, decision.outbound_type);
    if (connect_result.ec)
    {
        co_await backend->close();
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .target_host = host,
            .target_port = port,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .error_code = static_cast<int32_t>(connect_result.ec.value()),
            .error_message = connect_result.ec.message(),
        });
        co_return;
    }

    if (!co_await reply_success(connect_result))
    {
        co_await backend->close();
        co_return;
    }

    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             host,
             port,
             route_name_);

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRelayStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
    });

    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_outbound(backend) && outbound_to_client(backend));
    }
    else
    {
        co_await ((client_to_outbound(backend) && outbound_to_client(backend)) || idle_watchdog(backend));
    }

    co_await backend->close();
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .target_host = target_host_,
        .target_port = target_port_,
        .route_type = route_name_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
        .extra = {{"duration_ms", std::to_string(duration_ms)}},
    });
    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             target_host_,
             target_port_,
             route_name_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

std::shared_ptr<tcp_outbound_stream> socks_tcp_connect_session::create_backend(const route_type route, const std::string& outbound_tag)
{
    if (route != route_type::kDirect && route != route_type::kProxy)
    {
        return nullptr;
    }
    const auto handler = make_outbound_handler(cfg_, outbound_tag);
    if (handler == nullptr)
    {
        return nullptr;
    }
    return handler->create_tcp_outbound(socket_.get_executor(), conn_id_, trace_id_, cfg_);
}

boost::asio::awaitable<tcp_outbound_connect_result> socks_tcp_connect_session::connect_backend(const std::shared_ptr<tcp_outbound_stream>& backend,
                                                                                   const std::string& host,
                                                                                   uint16_t port,
                                                                                   const route_type route,
                                                                                   const std::string& outbound_type)
{
    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} connecting",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             host,
             port,
             relay::to_string(route));
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(route),
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
    });
    const auto result = co_await backend->connect(host, port);
    if (!result.ec)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .target_host = host,
            .target_port = port,
            .route_type = relay::to_string(route),
            .outbound_tag = route_name_,
            .outbound_type = outbound_type,
            .local_host = result.has_bind_endpoint ? result.bind_addr.to_string() : local_host_,
            .local_port = result.has_bind_endpoint ? result.bind_port : local_port_,
            .remote_host = host,
            .remote_port = port,
        });
        co_return result;
    }

    LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} connect failed error {} rep {}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             host,
             port,
             relay::to_string(route),
             result.ec.message(),
             result.socks_rep);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(route),
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = host,
        .remote_port = port,
        .error_code = static_cast<int32_t>(result.ec.value()),
        .error_message = result.ec.message(),
    });
    co_await reply_error(result.socks_rep);
    co_return result;
}

boost::asio::awaitable<void> socks_tcp_connect_session::reply_error(uint8_t code)
{
    uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(err), cfg_.timeout.write, ec);
    if (!ec)
    {
        co_return;
    }
    LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} write error response failed {}",
             log_event::kSocks,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             target_host_,
             target_port_,
             route_name_,
             ec.message());
}

boost::asio::awaitable<bool> socks_tcp_connect_session::reply_success(const tcp_outbound_connect_result& connect_result)
{
    std::vector<uint8_t> rep;
    rep.reserve(22);
    rep.push_back(socks::kVer);
    rep.push_back(socks::kRepSuccess);
    rep.push_back(0x00);
    if (!connect_result.has_bind_endpoint)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} backend bind endpoint unavailable fallback zero",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_host_,
                 client_port_,
                 local_host_,
                 local_port_,
                 target_host_,
                 target_port_,
                 route_name_);
        rep.push_back(socks::kAtypIpv4);
        rep.insert(rep.end(), {0, 0, 0, 0, 0, 0});
    }
    else
    {
        auto bind_addr = socks_codec::normalize_ip_address(connect_result.bind_addr);
        const auto bind_port = connect_result.bind_port;
        if (bind_addr.is_v4())
        {
            rep.push_back(socks::kAtypIpv4);
            const auto bytes = bind_addr.to_v4().to_bytes();
            rep.insert(rep.end(), bytes.begin(), bytes.end());
        }
        else
        {
            rep.push_back(socks::kAtypIpv6);
            const auto bytes = bind_addr.to_v6().to_bytes();
            rep.insert(rep.end(), bytes.begin(), bytes.end());
        }
        rep.push_back(static_cast<uint8_t>((bind_port >> 8) & 0xFF));
        rep.push_back(static_cast<uint8_t>(bind_port & 0xFF));
    }

    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(rep), cfg_.timeout.write, ec);
    if (!ec)
    {
        co_return true;
    }
    LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} write to client failed {}",
             log_event::kDataSend,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             target_host_,
             target_port_,
             route_name_,
             ec.message());
    co_return false;
}

void socks_tcp_connect_session::close_client_socket()
{
    boost::system::error_code ec;
    idle_timer_.cancel();
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} shutdown client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_host_,
                 client_port_,
                 local_host_,
                 local_port_,
                 target_host_,
                 target_port_,
                 route_name_,
                 ec.message());
    }

    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} close client failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 client_host_,
                 client_port_,
                 local_host_,
                 local_port_,
                 target_host_,
                 target_port_,
                 route_name_,
                 ec.message());
    }
}

boost::asio::awaitable<void> socks_tcp_connect_session::client_to_outbound(std::shared_ptr<tcp_outbound_stream> backend)
{
    boost::system::error_code ec;
    std::vector<uint8_t> buf(8192);
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
                    LOG_WARN(
                        "{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage client_to_outbound shutdown "
                        "backend send failed {}",
                        log_event::kSocks,
                        trace_id_,
                        conn_id_,
                        client_host_,
                        client_port_,
                        local_host_,
                        local_port_,
                        target_host_,
                        target_port_,
                        route_name_,
                        shutdown_ec.message());
                }
            }
            else
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage client_to_outbound read failed {}",
                         log_event::kSocks,
                         trace_id_,
                         conn_id_,
                         client_host_,
                         client_port_,
                         local_host_,
                         local_port_,
                         target_host_,
                         target_port_,
                         route_name_,
                         ec.message());
                co_await backend->close();
            }
            break;
        }
        const std::vector<uint8_t> data(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await backend->write(data, ec);
        if (ec)
        {
            LOG_WARN(
                "{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage client_to_outbound write to backend "
                "failed {}",
                log_event::kSocks,
                trace_id_,
                conn_id_,
                client_host_,
                client_port_,
                local_host_,
                local_port_,
                target_host_,
                target_port_,
                route_name_,
                ec.message());
            co_await backend->close();
            break;
        }
        tx_bytes_ += n;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage client_to_outbound finished tx_bytes {}",
             log_event::kDataSend,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             target_host_,
             target_port_,
             route_name_,
             tx_bytes_);
}

boost::asio::awaitable<void> socks_tcp_connect_session::outbound_to_client(std::shared_ptr<tcp_outbound_stream> backend)
{
    boost::system::error_code ec;
    std::vector<uint8_t> buf(8192);
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
                    LOG_WARN(
                        "{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage outbound_to_client shutdown "
                        "client send failed {}",
                        log_event::kSocks,
                        trace_id_,
                        conn_id_,
                        client_host_,
                        client_port_,
                        local_host_,
                        local_port_,
                        target_host_,
                        target_port_,
                        route_name_,
                        shutdown_ec.message());
                }
            }
            else
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage outbound_to_client read failed {}",
                         log_event::kSocks,
                         trace_id_,
                         conn_id_,
                         client_host_,
                         client_port_,
                         local_host_,
                         local_port_,
                         target_host_,
                         target_port_,
                         route_name_,
                         ec.message());
                close_client_socket();
            }
            break;
        }
        auto write_size = co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(buf.data(), n), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage outbound_to_client write failed {}",
                     log_event::kSocks,
                     trace_id_,
                     conn_id_,
                     client_host_,
                     client_port_,
                     local_host_,
                     local_port_,
                     target_host_,
                     target_port_,
                     route_name_,
                     ec.message());
            co_await backend->close();
            break;
        }
        rx_bytes_ += write_size;
        last_activity_time_ms_ = net::now_ms();
    }
    LOG_INFO("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} stage outbound_to_client finished rx_bytes {}",
             log_event::kDataRecv,
             trace_id_,
             conn_id_,
             client_host_,
             client_port_,
             local_host_,
             local_port_,
             target_host_,
             target_port_,
             route_name_,
             rx_bytes_);
}

boost::asio::awaitable<void> socks_tcp_connect_session::idle_watchdog(std::shared_ptr<tcp_outbound_stream> backend)
{
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
            LOG_WARN("{} trace {:016x} conn {} client {}:{} local {}:{} target {}:{} route {} idle_timeout_sec {} tcp session idle closing",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_host_,
                     client_port_,
                     local_host_,
                     local_port_,
                     target_host_,
                     target_port_,
                     route_name_,
                     cfg_.timeout.idle);
            co_await backend->close();
            boost::system::error_code ignore;
            ignore = socket_.close(ignore);
            (void)ignore;
            break;
        }
    }
}

}    // namespace relay
