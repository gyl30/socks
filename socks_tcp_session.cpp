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
#include "router.h"
#include "protocol.h"
#include "trace_store.h"
#include "tcp_outbound_stream.h"
#include "request_context.h"
#include "tcp_connect_flow.h"
#include "stream_relay.h"
#include "stream_relay_transport.h"
#include "net_utils.h"
#include "scoped_exit.h"
#include "socks_tcp_session.h"

namespace relay
{

socks_tcp_session::socks_tcp_session(boost::asio::ip::tcp::socket socket,
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

boost::asio::awaitable<void> socks_tcp_session::start(const std::string& host, uint16_t port) { co_await run(host, port); }

void socks_tcp_session::stop() { close_client_socket(); }

request_context socks_tcp_session::make_request_context(const std::string& host, const uint16_t port) const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kTcp,
        .command = request_command::kConnect,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = host,
        .target_port = port,
        .client_host = client_host_,
        .client_port = client_port_,
        .local_host = local_host_,
        .local_port = local_port_,
    };
}

void socks_tcp_session::apply_route_decision(const std::string& host, const uint16_t port, const route_decision& decision)
{
    target_host_ = host;
    target_port_ = port;
    route_name_ = decision.matched ? decision.outbound_tag : decision.outbound_type;
}

boost::asio::awaitable<void> socks_tcp_session::relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    tcp_socket_stream_relay_transport inbound_transport(socket_, cfg_.timeout);
    outbound_stream_relay_transport outbound_transport(backend);
    stream_relay_context relay_context{
        .inbound = inbound_transport,
        .outbound = outbound_transport,
        .idle_timer = idle_timer_,
        .timeout = cfg_.timeout,
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .log_event_name = log_event::kSocks,
        .last_activity_time_ms = last_activity_time_ms_,
        .tx_bytes = tx_bytes_,
        .rx_bytes = rx_bytes_,
    };
    (void)co_await relay_streams(relay_context);
}

boost::asio::awaitable<void> socks_tcp_session::finish_connected_session(
    const route_decision& decision, const std::shared_ptr<tcp_outbound_stream>& backend)
{
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRelayStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_host_,
        .target_port = target_port_,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
    });

    co_await relay_backend(backend);
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
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
        .route_type = route_name_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
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
    co_return;
}

boost::asio::awaitable<void> socks_tcp_session::run(const std::string& host, uint16_t port)
{
    DEFER(close_client_socket());

    const auto request = make_request_context(host, port);
    auto flow_result = co_await prepare_tcp_connect_flow(request, router_, socket_.get_executor(), cfg_);
    auto decision = std::move(flow_result.decision);
    apply_route_decision(host, port, decision);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = host,
        .target_port = port,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
    });

    const auto backend = flow_result.outbound;
    if (backend == nullptr)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = host,
            .target_port = port,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
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
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = host,
            .target_port = port,
            .local_host = local_host_,
            .local_port = local_port_,
            .remote_host = client_host_,
            .remote_port = client_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
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

    co_await finish_connected_session(decision, backend);
}

boost::asio::awaitable<tcp_outbound_connect_result> socks_tcp_session::connect_backend(const std::shared_ptr<tcp_outbound_stream>& backend,
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
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .target_host = host,
        .target_port = port,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = client_host_,
        .remote_port = client_port_,
        .route_type = relay::to_string(route),
    });
    const auto result = co_await backend->connect(host, port);
    if (!result.ec)
    {
        trace_event event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .outbound_tag = route_name_,
            .outbound_type = outbound_type,
            .target_host = host,
            .target_port = port,
            .local_host = result.has_bind_endpoint ? result.bind_addr.to_string() : local_host_,
            .local_port = result.has_bind_endpoint ? result.bind_port : local_port_,
            .remote_host = host,
            .remote_port = port,
            .route_type = relay::to_string(route),
        };
        if (result.has_resolved_target_endpoint)
        {
            event.resolved_target_host = result.resolved_target_addr.to_string();
            event.resolved_target_port = result.resolved_target_port;
        }
        trace_store::instance().record_event(std::move(event));
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
    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .target_host = host,
        .target_port = port,
        .local_host = local_host_,
        .local_port = local_port_,
        .remote_host = host,
        .remote_port = port,
        .route_type = relay::to_string(route),
        .error_code = static_cast<int32_t>(result.ec.value()),
        .error_message = result.ec.message(),
    };
    if (result.has_resolved_target_endpoint)
    {
        event.resolved_target_host = result.resolved_target_addr.to_string();
        event.resolved_target_port = result.resolved_target_port;
    }
    trace_store::instance().record_event(std::move(event));
    co_await reply_error(result.socks_rep);
    co_return result;
}

boost::asio::awaitable<void> socks_tcp_session::reply_error(uint8_t code)
{
    const auto err = socks::make_error_reply(code);
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

boost::asio::awaitable<bool> socks_tcp_session::reply_success(const tcp_outbound_connect_result& connect_result)
{
    boost::asio::ip::address bind_addr = boost::asio::ip::address_v4{};
    uint16_t bind_port = 0;
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
    }
    else
    {
        bind_addr = socks_codec::normalize_ip_address(connect_result.bind_addr);
        bind_port = connect_result.bind_port;
    }
    const auto rep = socks::make_reply(socks::kRepSuccess, bind_addr, bind_port);

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

void socks_tcp_session::close_client_socket()
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

}    // namespace relay
