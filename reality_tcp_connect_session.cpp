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
#include "outbound.h"
#include "router.h"
#include "tcp_outbound_stream.h"
#include "constants.h"
#include "protocol.h"
#include "trace_store.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "reality_tcp_connect_session.h"

namespace relay
{

reality_tcp_connect_session::reality_tcp_connect_session(boost::asio::io_context& io_context,
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

boost::asio::awaitable<void> reality_tcp_connect_session::start(const proxy::tcp_connect_request& request) { co_await run(request); }

boost::asio::awaitable<void> reality_tcp_connect_session::run(const proxy::tcp_connect_request& request)
{
    target_host_ = request.target_host;
    target_port_ = request.target_port;
    bind_host_ = "0.0.0.0";
    bind_port_ = 0;
    route_name_ = "unknown";
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

    if (router_ == nullptr)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kRouteDecideDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .target_host = target_host_,
            .target_port = target_port_,
            .local_host = bind_host_,
            .local_port = bind_port_,
            .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
            .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
            .error_message = "router unavailable",
        });
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} route unavailable",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  target_host_,
                  target_port_);
        (void)co_await send_connect_reply(socks::kRepGenFail, nullptr);
        co_return;
    }

    boost::system::error_code target_ec;
    const auto target_addr = boost::asio::ip::make_address(target_host_, target_ec);
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    if (target_ec)
    {
        decision = co_await router_->decide_domain_detail(target_host_);
    }
    else
    {
        decision = co_await router_->decide_ip_detail(target_addr);
    }
    route_name_ = decision.matched ? decision.outbound_tag : decision.outbound_type;
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .target_host = target_host_,
        .target_port = target_port_,
        .route_type = relay::to_string(decision.route),
        .match_type = decision.match_type,
        .match_value = decision.match_value,
        .outbound_tag = decision.outbound_tag,
        .outbound_type = decision.outbound_type,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
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
            .inbound_type = "reality",
            .target_host = target_host_,
            .target_port = target_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
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

    co_await relay_target(backend);
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
        .route_type = route_name_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .extra = {{"duration_ms", std::to_string(
                                      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                                           start_time_)
                                          .count())}},
    });
    log_close_summary();
}

std::shared_ptr<tcp_outbound_stream> reality_tcp_connect_session::create_backend(const route_type route, const std::string& outbound_tag) const
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
    return handler->create_tcp_outbound(executor_, conn_id_, trace_id_, cfg_);
}

boost::asio::awaitable<tcp_outbound_connect_result> reality_tcp_connect_session::connect_backend(const std::shared_ptr<tcp_outbound_stream>& backend,
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
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(route),
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
    });
    const auto result = co_await backend->connect(host, port);
    if (!result.ec)
    {
        if (result.has_bind_endpoint)
        {
            bind_host_ = result.bind_addr.to_string();
            bind_port_ = result.bind_port;
        }
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .target_host = host,
            .target_port = port,
            .route_type = relay::to_string(route),
            .outbound_tag = route_name_,
            .outbound_type = outbound_type,
            .local_host = bind_host_,
            .local_port = bind_port_,
            .remote_host = host,
            .remote_port = port,
        });
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
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .target_host = host,
        .target_port = port,
        .route_type = relay::to_string(route),
        .outbound_tag = route_name_,
        .outbound_type = outbound_type,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = host,
        .remote_port = port,
        .error_code = static_cast<int32_t>(result.ec.value()),
        .error_message = result.ec.message(),
    });
    (void)co_await send_connect_reply(result.socks_rep, nullptr);
    co_return result;
}

boost::asio::awaitable<bool> reality_tcp_connect_session::send_connect_reply(const uint8_t socks_rep, const tcp_outbound_connect_result* connect_result)
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

boost::asio::awaitable<void> reality_tcp_connect_session::relay_target(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;

    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_outbound(backend) && outbound_to_client(backend));
        co_return;
    }

    co_await ((client_to_outbound(backend) && outbound_to_client(backend)) || idle_watchdog(backend));
}

boost::asio::awaitable<void> reality_tcp_connect_session::client_to_outbound(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    if (connection_ == nullptr || backend == nullptr)
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
                co_await backend->shutdown_send(shutdown_ec);
            }
            else
            {
                LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} client_to_outbound finished {}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         target_host_,
                         target_port_,
                         route_name_,
                         ec.message());
            }
            break;
        }

        buffer.resize(bytes_read);
        co_await backend->write(buffer, ec);
        buffer.resize(8192);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} client_to_outbound write failed {}",
                     log_event::kDataSend,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     route_name_,
                     ec.message());
            break;
        }
        tx_bytes_ += bytes_read;
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> reality_tcp_connect_session::outbound_to_client(const std::shared_ptr<tcp_outbound_stream>& backend)
{
    if (connection_ == nullptr || backend == nullptr)
    {
        co_return;
    }

    std::vector<uint8_t> buffer(8192);
    for (;;)
    {
        boost::system::error_code ec;
        const auto bytes_read = co_await backend->read(buffer, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                co_await connection_->shutdown_send(shutdown_ec);
            }
            else
            {
                LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} outbound_to_client finished {}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         target_host_,
                         target_port_,
                         route_name_,
                         ec.message());
            }
            break;
        }
        co_await connection_->write(std::span<const uint8_t>(buffer.data(), bytes_read), ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} outbound_to_client write failed {}",
                     log_event::kDataSend,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     route_name_,
                     ec.message());
            break;
        }
        rx_bytes_ += bytes_read;
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> reality_tcp_connect_session::idle_watchdog(const std::shared_ptr<tcp_outbound_stream>& backend)
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
            LOG_WARN("{} trace {:016x} conn {} target {}:{} route {} bind {}:{} idle timeout {}s",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     target_host_,
                     target_port_,
                     route_name_,
                     bind_host_,
                     bind_port_,
                     cfg_.timeout.idle);
            if (backend != nullptr)
            {
                co_await backend->close();
            }
            if (connection_ != nullptr)
            {
                boost::system::error_code close_ec;
                connection_->close(close_ec);
            }
            break;
        }
    }
}

void reality_tcp_connect_session::log_close_summary() const
{
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} target {}:{} route {} bind {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             target_host_,
             target_port_,
             route_name_,
             bind_host_,
             bind_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

}    // namespace relay
