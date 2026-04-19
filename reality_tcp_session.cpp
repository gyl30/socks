#include <chrono>
#include <memory>
#include <string>
#include <string_view>
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
#include "router.h"
#include "tcp_outbound_stream.h"
#include "request_context.h"
#include "tcp_connect_flow.h"
#include "constants.h"
#include "protocol.h"
#include "trace_store.h"
#include "net_utils.h"
#include "stream_relay.h"
#include "stream_relay_transport.h"
#include "proxy_protocol.h"
#include "reality_tcp_session.h"

namespace relay
{

reality_tcp_session::reality_tcp_session(boost::asio::io_context& io_context,
                                                         std::shared_ptr<proxy_reality_connection> connection,
                                                         std::shared_ptr<router> router,
                                                         const uint32_t conn_id,
                                                         const uint64_t trace_id,
                                                         std::string inbound_tag,
                                                         const config& cfg)
    : conn_id_(conn_id),
      trace_id_(trace_id),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      executor_(io_context.get_executor()),
      idle_timer_(io_context),
      connection_(std::move(connection)),
      router_(std::move(router))
{
    last_activity_time_ms_ = net::now_ms();
}

boost::asio::awaitable<void> reality_tcp_session::start(const proxy::tcp_connect_request& request) { co_await run(request); }

void reality_tcp_session::init_request_state(const proxy::tcp_connect_request& request)
{
    target_host_ = request.target_host;
    target_port_ = request.target_port;
    bind_host_ = "0.0.0.0";
    bind_port_ = 0;
    route_name_ = "unknown";
}

request_context reality_tcp_session::make_request_context() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kTcp,
        .command = request_command::kConnect,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = target_host_,
        .target_port = target_port_,
        .client_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .client_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .local_host = bind_host_,
        .local_port = bind_port_,
    };
}

void reality_tcp_session::apply_route_decision(const route_decision& decision)
{
    route_name_ = decision.matched ? decision.outbound_tag : decision.outbound_type;
}

boost::asio::awaitable<void> reality_tcp_session::relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    proxy_connection_stream_relay_transport inbound_transport(connection_, cfg_.timeout);
    outbound_stream_relay_transport outbound_transport(backend);
    stream_relay_context relay_context{
        .inbound = inbound_transport,
        .outbound = outbound_transport,
        .idle_timer = idle_timer_,
        .timeout = cfg_.timeout,
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .log_event_name = log_event::kRoute,
        .last_activity_time_ms = last_activity_time_ms_,
        .tx_bytes = tx_bytes_,
        .rx_bytes = rx_bytes_,
    };
    const auto relay_result = co_await relay_streams(relay_context);
    close_reason_ = relay_result.reason;
}

boost::asio::awaitable<void> reality_tcp_session::finish_connected_session(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    co_await relay_backend(backend);
    co_await backend->close();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .target_host = target_host_,
        .target_port = target_port_,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .route_type = route_name_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .extra = {{"duration_ms", std::to_string(
                                      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                                           start_time_)
                                          .count())},
                  {"close_reason", to_string(close_reason_)}},
    });
    log_close_summary();
    co_return;
}

boost::asio::awaitable<void> reality_tcp_session::run(const proxy::tcp_connect_request& request)
{
    init_request_state(request);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .target_host = target_host_,
        .target_port = target_port_,
    });

    LOG_INFO("{} trace {:016x} conn {} target {}:{} remote {}:{} connecting",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             connection_ != nullptr ? std::string(connection_->remote_host()) : "unknown",
             connection_ != nullptr ? connection_->remote_port() : 0);

    const auto request_ctx = make_request_context();
    auto flow_result = co_await prepare_tcp_connect_flow(request_ctx, router_, executor_, cfg_);
    auto decision = std::move(flow_result.decision);
    apply_route_decision(decision);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_host_,
        .target_port = target_port_,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
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
            .inbound_type = "reality",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_host_,
            .target_port = target_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .error_message = "route blocked",
        });
        LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} blocked",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 route_name_);
        (void)co_await send_connect_reply(socks::kRepNotAllowed, nullptr);
        co_return;
    }

    const auto connect_result = co_await connect_backend(backend, target_host_, target_port_, decision.route, decision.outbound_type);
    if (connect_result.ec)
    {
        co_await backend->close();
        co_return;
    }

    if (!(co_await send_connect_reply(socks::kRepSuccess, &connect_result)))
    {
        co_await backend->close();
        co_return;
    }

    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} connected bind {}:{}",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             route_name_,
             bind_host_,
             bind_port_);

    co_await finish_connected_session(backend);
}

boost::asio::awaitable<tcp_outbound_connect_result> reality_tcp_session::connect_backend(const std::shared_ptr<tcp_outbound_stream>& backend,
                                                                                     const std::string& host,
                                                                                     const uint16_t port,
                                                                                     const route_type route,
                                                                                     const std::string& outbound_type)
{
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} connecting",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             host,
             port,
             relay::to_string(route));
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .target_host = host,
        .target_port = port,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .route_type = relay::to_string(route),
    });
    const auto result = co_await backend->connect(host, port);
    if (!result.ec)
    {
        if (result.has_bind_endpoint)
        {
            bind_host_ = result.bind_addr.to_string();
            bind_port_ = result.bind_port;
        }
        trace_event event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .outbound_tag = route_name_,
            .outbound_type = outbound_type,
            .target_host = host,
            .target_port = port,
            .local_host = bind_host_,
            .local_port = bind_port_,
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

    LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} connect failed error {} rep {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
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
        .inbound_type = "reality",
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .target_host = host,
        .target_port = port,
        .local_host = bind_host_,
        .local_port = bind_port_,
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
    (void)co_await send_connect_reply(result.socks_rep, nullptr);
    co_return result;
}

boost::asio::awaitable<bool> reality_tcp_session::send_connect_reply(const uint8_t socks_rep, const tcp_outbound_connect_result* connect_result)
{
    if (connection_ == nullptr)
    {
        co_return false;
    }

    proxy::tcp_connect_reply reply;
    reply.socks_rep = socks_rep;
    if (connect_result != nullptr && connect_result->has_bind_endpoint)
    {
        reply.bind_host = connect_result->bind_addr.to_string();
        reply.bind_port = connect_result->bind_port;
        bind_host_ = reply.bind_host;
        bind_port_ = reply.bind_port;
    }
    else
    {
        reply.bind_host = bind_host_;
        reply.bind_port = bind_port_;
    }

    std::vector<uint8_t> packet;
    if (!proxy::encode_tcp_connect_reply(reply, packet))
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} bind {}:{} encode tcp connect reply failed rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 route_name_,
                 reply.bind_host,
                 reply.bind_port,
                 socks_rep);
        co_return false;
    }

    boost::system::error_code ec;
    co_await connection_->write_packet(packet, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} bind {}:{} send tcp connect reply failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_host_,
                 target_port_,
                 route_name_,
                 reply.bind_host,
                 reply.bind_port,
                 ec.message(),
                 socks_rep);
        co_return false;
    }
    co_return true;
}

void reality_tcp_session::log_close_summary() const
{
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} bind {}:{} close_reason {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             route_name_,
             bind_host_,
             bind_port_,
             to_string(close_reason_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

}    // namespace relay
