#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "trace_store.h"
#include "trace_id.h"
#include "tcp_outbound_stream.h"
#include "constants.h"
#include "net_utils.h"
#include "request_context.h"
#include "stream_relay.h"
#include "stream_relay_transport.h"
#include "tcp_connect_flow.h"
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
                                       std::string inbound_tag,
                                       const config& cfg,
                                       const config::tproxy_t& settings)
    : trace_id_(generate_trace_id()),
      conn_id_(sid),
      inbound_tag_(std::move(inbound_tag)),
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

bool tproxy_tcp_session::prepare_redirected_connection()
{
    boost::asio::ip::tcp::endpoint target_ep;
    if (!resolve_target_endpoint(target_ep))
    {
        return false;
    }

    boost::system::error_code local_ec;
    const auto local_ep = socket_.local_endpoint(local_ec);
    if (detect_routing_loop(target_ep, local_ec, local_ep))
    {
        return false;
    }

    boost::system::error_code peer_ec;
    const auto peer_ep = socket_.remote_endpoint(peer_ec);
    update_session_endpoints(target_ep, local_ec, local_ep, peer_ec, peer_ep);
    log_redirected_connection();
    return true;
}

request_context tproxy_tcp_session::make_request_context() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kTcp,
        .command = request_command::kConnect,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .target_host = target_addr_,
        .target_port = target_port_,
        .target_ip = std::make_optional(target_addr_),
        .target_domain = std::nullopt,
        .client_host = client_addr_.empty() ? "unknown" : client_addr_,
        .client_port = client_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
    };
}

boost::asio::awaitable<void> tproxy_tcp_session::run()
{
    if (!prepare_redirected_connection())
    {
        co_return;
    }

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = "",
        .match_type = "",
        .match_value = "",
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = "",
        .match_type = "",
        .match_value = "",
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });

    const auto request = make_request_context();
    auto flow_result = co_await prepare_tcp_connect_flow(request, router_, socket_.get_executor(), cfg_);
    auto decision = std::move(flow_result.decision);
    const auto backend = flow_result.outbound;
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    if (backend == nullptr)
    {
        const auto error_message = (decision.route == route_type::kBlock) ? std::string("route blocked") : std::string("outbound handler unavailable");
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_addr_,
            .target_port = target_port_,
            .local_host = "",
            .local_port = 0,
            .remote_host = "",
            .remote_port = 0,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = 0,
            .error_code = 0,
            .error_message = error_message,
            .extra = {},
        });
        co_return;
    }
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             target_addr_,
             target_port_,
             decision.matched ? decision.outbound_tag : decision.outbound_type);
    if (!(co_await connect_backend(decision, backend)))
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_addr_,
            .target_port = target_port_,
            .local_host = "",
            .local_port = 0,
            .remote_host = "",
            .remote_port = 0,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = 0,
            .error_code = 0,
            .error_message = "",
            .extra = {},
        });
        co_return;
    }

    co_await finish_connected_session(decision, backend);
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

boost::asio::awaitable<bool> tproxy_tcp_session::connect_backend(const route_decision& decision,
                                                                 const std::shared_ptr<tcp_outbound_stream>& backend)
{
    const auto connect_start = std::chrono::steady_clock::now();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    const auto connect_result = co_await backend->connect(target_addr_, target_port_);
    const auto latency_ms = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count());
    if (connect_result.ec)
    {
        trace_event event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = target_addr_,
            .target_port = target_port_,
            .local_host = local_addr_.empty() ? "unknown" : local_addr_,
            .local_port = local_port_,
            .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
            .remote_port = client_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = latency_ms,
            .error_code = connect_result.ec.value(),
            .error_message = connect_result.ec.message(),
            .extra = {},
        };
        if (connect_result.has_resolved_target_endpoint)
        {
            event.resolved_target_host = connect_result.resolved_target_addr.to_string();
            event.resolved_target_port = connect_result.resolved_target_port;
        }
        if (connect_result.has_bind_endpoint)
        {
            event.extra["bind_host"] = connect_result.bind_addr.to_string();
            event.extra["bind_port"] = std::to_string(connect_result.bind_port);
        }
        event.extra["socks_rep"] = std::to_string(connect_result.socks_rep);
        trace_store::instance().record_event(std::move(event));
        LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} connect failed error {} rep {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 target_addr_,
                 target_port_,
                 relay::to_string(decision.route),
                 connect_result.ec.message(),
                 connect_result.socks_rep);
        co_await backend->close();
        co_return false;
    }

    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = latency_ms,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    };
    if (connect_result.has_resolved_target_endpoint)
    {
        event.resolved_target_host = connect_result.resolved_target_addr.to_string();
        event.resolved_target_port = connect_result.resolved_target_port;
    }
    if (connect_result.has_bind_endpoint)
    {
        event.extra["bind_host"] = connect_result.bind_addr.to_string();
        event.extra["bind_port"] = std::to_string(connect_result.bind_port);
    }
    trace_store::instance().record_event(std::move(event));
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             target_addr_,
             target_port_,
             relay::to_string(decision.route));
    co_return true;
}

boost::asio::awaitable<void> tproxy_tcp_session::finish_connected_session(
    const route_decision& decision, const std::shared_ptr<tcp_outbound_stream>& backend)
{
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRelayStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    co_await relay_backend(backend);
    co_await backend->close();
    close_client_socket();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .target_host = target_addr_,
        .target_port = target_port_,
        .local_host = local_addr_.empty() ? "unknown" : local_addr_,
        .local_port = local_port_,
        .remote_host = client_addr_.empty() ? "unknown" : client_addr_,
        .remote_port = client_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {{"close_reason", to_string(close_reason_)}},
    });
    log_close_summary();
    co_return;
}

boost::asio::awaitable<void> tproxy_tcp_session::relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    tcp_socket_stream_relay_transport inbound_transport(socket_, cfg_.timeout);
    outbound_stream_relay_transport outbound_transport(backend);
    auto relay_context = stream_relay_context{
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
    const auto relay_result = co_await relay_streams(relay_context);
    close_reason_ = relay_result.reason;
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
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} close_reason {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_addr_.empty() ? "unknown" : client_addr_,
             client_port_,
             target_addr_.empty() ? "unknown" : target_addr_,
             target_port_,
             to_string(close_reason_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

}    // namespace relay
