#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <functional>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "trace_store.h"
#include "context_pool.h"
#include "datagram_relay.h"
#include "request_context.h"
#include "proxy_protocol.h"
#include "udp_session_flow.h"
#include "udp_proxy_outbound.h"
#include "tproxy_udp_session.h"
#include "transparent_udp_session_flow.h"

namespace relay
{

namespace
{

void set_socket_reuse_port(int fd, boost::system::error_code& ec)
{
#ifdef __linux__
    constexpr int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
#else
    (void)fd;
    ec = boost::system::error_code(static_cast<int>(boost::system::errc::not_supported), boost::system::generic_category());
#endif
}

}    // namespace

tproxy_udp_session::tproxy_udp_session(io_worker& worker,
                                       std::shared_ptr<router> router,
                                       const boost::asio::ip::udp::endpoint& client_endpoint,
                                       const boost::asio::ip::udp::endpoint& target_endpoint,
                                       uint32_t conn_id,
                                       std::string inbound_tag,
                                       const config& cfg,
                                       std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(conn_id),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      worker_(worker),
      router_(std::move(router)),
      last_activity_time_ms_(net::now_ms()),
      idle_timer_(worker.io_context),
      upstream_socket_(worker.io_context),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close)),
      packet_channel_(worker.io_context, constants::udp::kPacketChannelCapacity),
      reply_sockets_(constants::udp::kMaxReplySockets)
{
}

void tproxy_udp_session::start()
{
    worker_.group.spawn([self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await self->run(); });
}

void tproxy_udp_session::stop() { close_impl(); }

boost::asio::awaitable<udp_enqueue_result> tproxy_udp_session::enqueue_packet(std::vector<uint8_t> payload)
{
    if (stopped_.load(std::memory_order_relaxed))
    {
        co_return udp_enqueue_result::kClosed;
    }

    if (payload.size() > constants::udp::kMaxPacketSize)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} drop udp packet because payload too large size {} max {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 payload.size(),
                 constants::udp::kMaxPacketSize);
        co_return udp_enqueue_result::kDroppedOverflow;
    }

    const auto [send_ec] =
        co_await packet_channel_.async_send(boost::system::error_code{}, std::move(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        if (stopped_.load(std::memory_order_relaxed) || net::is_basic_close_error(send_ec) ||
            send_ec == boost::asio::experimental::error::channel_errors::channel_closed)
        {
            co_return udp_enqueue_result::kClosed;
        }

        LOG_WARN("{} trace {:016x} conn {} enqueue udp packet failed {} client {}:{} target {}:{}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 send_ec.message(),
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port());
        co_return udp_enqueue_result::kClosed;
    }
    last_activity_time_ms_ = net::now_ms();
    co_return udp_enqueue_result::kEnqueued;
}

request_context tproxy_udp_session::make_request_context() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .target_ip = target_endpoint_.address().to_string(),
        .target_domain = std::nullopt,
        .client_host = client_endpoint_.address().to_string(),
        .client_port = client_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
    };
}

void tproxy_udp_session::apply_route_decision(const route_decision& decision)
{
    route_ = decision.route;
    outbound_tag_ = decision.outbound_tag;
    outbound_type_ = decision.outbound_type;
    match_type_ = decision.match_type;
    match_value_ = decision.match_value;
}

boost::asio::awaitable<bool> tproxy_udp_session::run_selected_mode()
{
    if (route_ == route_type::kDirect)
    {
        co_return co_await run_direct_mode();
    }
    co_return co_await run_proxy_mode();
}

boost::asio::awaitable<void> tproxy_udp_session::run()
{
    const auto request = make_request_context();

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
    });
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
    });
    const auto flow_result = co_await prepare_udp_route_flow(request, router_);
    apply_route_decision(flow_result.decision);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = (route_ == route_type::kBlock) ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
    });
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {} out_tag {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             relay::to_string(route_),
             outbound_tag_.empty() ? "-" : outbound_tag_);
    if (route_ == route_type::kBlock)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = outbound_tag_,
            .outbound_type = outbound_type_,
            .target_host = target_endpoint_.address().to_string(),
            .target_port = target_endpoint_.port(),
            .remote_host = client_endpoint_.address().to_string(),
            .remote_port = client_endpoint_.port(),
            .route_type = relay::to_string(route_),
            .match_type = match_type_,
            .match_value = match_value_,
            .error_message = "route blocked",
        });
        notify_closed();
        co_return;
    }
    const bool completed = co_await run_selected_mode();
    notify_closed();
    if (!completed)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = outbound_tag_,
            .outbound_type = outbound_type_,
            .target_host = target_endpoint_.address().to_string(),
            .target_port = target_endpoint_.port(),
            .remote_host = client_endpoint_.address().to_string(),
            .remote_port = client_endpoint_.port(),
            .route_type = relay::to_string(route_),
            .match_type = match_type_,
            .match_value = match_value_,
        });
        co_return;
    }
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .latency_ms = static_cast<uint32_t>(duration_ms),
    });
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             relay::to_string(route_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<bool> tproxy_udp_session::run_direct_mode()
{
    co_return co_await run_transparent_udp_mode(
        cfg_.timeout.idle,
        [this]() -> boost::asio::awaitable<bool> { co_return co_await open_direct_socket(); },
        [this]() -> boost::asio::awaitable<void> { co_await packets_to_direct(); },
        [this]() -> boost::asio::awaitable<void> { co_await direct_to_client(); },
        [this]() -> boost::asio::awaitable<void> { co_await idle_watchdog(); },
        []() -> boost::asio::awaitable<void> { co_return; });
}

boost::asio::awaitable<bool> tproxy_udp_session::run_proxy_mode()
{
    co_return co_await run_transparent_udp_mode(
        cfg_.timeout.idle,
        [this]() -> boost::asio::awaitable<bool> { co_return co_await open_proxy_outbound(); },
        [this]() -> boost::asio::awaitable<void> { co_await packets_to_proxy(); },
        [this]() -> boost::asio::awaitable<void> { co_await proxy_to_client(); },
        [this]() -> boost::asio::awaitable<void> { co_await idle_watchdog(); },
        [this]() -> boost::asio::awaitable<void>
        {
            if (proxy_outbound_ != nullptr)
            {
                co_await proxy_outbound_->close();
                proxy_outbound_.reset();
            }
        });
}

void tproxy_udp_session::record_open_direct_socket_result(const bool success,
                                                          const boost::system::error_code& ec,
                                                          const std::chrono::steady_clock::time_point connect_start) const
{
    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = success ? trace_result::kOk : trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = "direct",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .latency_ms = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
    };
    if (ec)
    {
        event.error_code = static_cast<int32_t>(ec.value());
        event.error_message = ec.message();
    }
    trace_store::instance().record_event(std::move(event));
}

boost::asio::awaitable<bool> tproxy_udp_session::open_direct_socket()
{
    const auto connect_start = std::chrono::steady_clock::now();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = "direct",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
    });
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    ec = upstream_socket_.open(protocol, ec);
    if (ec)
    {
        record_open_direct_socket_result(false, ec, connect_start);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} open direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    const auto connect_mark = resolve_socket_mark(cfg_);
    if (connect_mark != 0)
    {
        net::set_socket_mark(upstream_socket_.native_handle(), connect_mark, ec);
        if (ec)
        {
            record_open_direct_socket_result(false, ec, connect_start);
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} set direct udp mark failed {}",
                     log_event::kConnInit,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            co_return false;
        }
    }

    ec = upstream_socket_.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} bind direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }
    ec = upstream_socket_.connect(target_endpoint_, ec);
    if (ec)
    {
        record_open_direct_socket_result(false, ec, connect_start);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} connect direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    LOG_INFO("{} trace {:016x} conn {} opened direct udp socket client {}:{} target {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port());
    record_open_direct_socket_result(true, ec, connect_start);
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::open_proxy_outbound()
{
    const auto connect_start = std::chrono::steady_clock::now();
    const auto request = make_request_context();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
    });
    const auto connect_result = co_await connect_udp_proxy_flow(worker_.io_context.get_executor(), request, outbound_tag_, cfg_);
    co_return co_await apply_open_proxy_outbound_result(connect_result, connect_start);
}

boost::asio::awaitable<bool> tproxy_udp_session::apply_open_proxy_outbound_result(
    const udp_proxy_outbound_connect_result& connect_result, const std::chrono::steady_clock::time_point connect_start)
{
    if (connect_result.ec || connect_result.outbound == nullptr)
    {
        const auto ec = connect_result.ec ? connect_result.ec : boost::asio::error::operation_aborted;
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tproxy",
            .outbound_tag = outbound_tag_,
            .outbound_type = outbound_type_,
            .target_host = target_endpoint_.address().to_string(),
            .target_port = target_endpoint_.port(),
            .remote_host = client_endpoint_.address().to_string(),
            .remote_port = client_endpoint_.port(),
            .route_type = relay::to_string(route_),
            .match_type = match_type_,
            .match_value = match_value_,
            .latency_ms = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
            .error_code = static_cast<int32_t>(ec.value()),
            .error_message = ec.message(),
        });
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} open proxy udp outbound failed {} rep {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message(),
                 connect_result.socks_rep);
        co_return false;
    }

    proxy_outbound_ = connect_result.outbound;
    LOG_INFO("{} trace {:016x} conn {} opened proxy udp outbound client {}:{} target {}:{} bind {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             proxy_outbound_->bind_host(),
             proxy_outbound_->bind_port());
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tproxy",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .latency_ms = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
    });
    co_return true;
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_direct()
{
    packet_channel_send_relay_context relay_context{
        .last_activity_time_ms = last_activity_time_ms_,
        .tx_bytes = tx_bytes_,
    };
    co_await relay_packet_channel_payloads(
        packet_channel_,
        relay_context,
        [this](const std::vector<uint8_t>& payload, boost::system::error_code& ec) -> boost::asio::awaitable<void>
        {
            const auto sent =
                co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            (void)sent;
            co_return;
        },
        [this](const boost::system::error_code& ec)
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} send direct udp payload failed {}",
                     log_event::kRelay,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
        });
}

boost::asio::awaitable<void> tproxy_udp_session::direct_to_client()
{
    const auto normalized_target = net::normalize_endpoint(target_endpoint_);
    connected_udp_socket_reply_relay_context relay_context{
        .socket = upstream_socket_,
        .last_activity_time_ms = last_activity_time_ms_,
    };
    co_await relay_connected_udp_socket_replies(
        relay_context,
        [this, normalized_target](const uint8_t* payload, const std::size_t payload_len) -> boost::asio::awaitable<bool>
        {
            co_return co_await send_to_client(normalized_target, payload, payload_len);
        },
        [](const boost::system::error_code&) {});
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_proxy()
{
    if (proxy_outbound_ == nullptr)
    {
        co_return;
    }

    packet_channel_send_relay_context relay_context{
        .last_activity_time_ms = last_activity_time_ms_,
        .tx_bytes = tx_bytes_,
    };
    co_await relay_packet_channel_payloads(
        packet_channel_,
        relay_context,
        [this](const std::vector<uint8_t>& payload, boost::system::error_code& ec) -> boost::asio::awaitable<void>
        {
            co_await proxy_outbound_->send_datagram(target_endpoint_.address().to_string(), target_endpoint_.port(), payload.data(), payload.size(), ec);
            co_return;
        },
        [this](const boost::system::error_code& ec)
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} send proxy udp payload failed {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
        });
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_to_client()
{
    if (proxy_outbound_ == nullptr)
    {
        co_return;
    }

    proxy_outbound_reply_relay_context relay_context{
        .read_timeout_sec = cfg_.timeout.read,
        .last_activity_time_ms = last_activity_time_ms_,
        .rx_bytes = rx_bytes_,
    };
    co_await relay_proxy_outbound_replies(
        proxy_outbound_,
        relay_context,
        [this]() { return stopped_.load(std::memory_order_relaxed); },
        [this](const proxy::udp_datagram& datagram, boost::system::error_code& ec) -> boost::asio::awaitable<std::size_t>
        {
            boost::asio::ip::udp::endpoint source_endpoint;
            if (!parse_proxy_datagram_source_endpoint(datagram, source_endpoint))
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} invalid proxy udp source {}:{}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         client_endpoint_.address().to_string(),
                         client_endpoint_.port(),
                         target_endpoint_.address().to_string(),
                         target_endpoint_.port(),
                         datagram.target_host,
                         datagram.target_port);
                co_return 0;
            }

            if (!(co_await send_to_client(source_endpoint, datagram.payload.data(), datagram.payload.size())))
            {
                ec = boost::asio::error::operation_aborted;
                co_return 0;
            }
            co_return 0;
        },
        [](const boost::system::error_code&) {});
}

boost::asio::awaitable<void> tproxy_udp_session::idle_watchdog()
{
    datagram_idle_watchdog_context relay_context{
        .timer = idle_timer_,
        .idle_timeout_sec = cfg_.timeout.idle,
        .last_activity_time_ms = last_activity_time_ms_,
    };
    co_await run_datagram_idle_watchdog(
        relay_context,
        [this]()
        {
            LOG_INFO("{} trace {:016x} conn {} udp session idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
            close_impl();
        });
}

boost::asio::awaitable<bool> tproxy_udp_session::send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                                const uint8_t* payload,
                                                                std::size_t payload_len)
{
    if (stopped_.load(std::memory_order_relaxed))
    {
        co_return false;
    }

    boost::system::error_code ec;
    const auto key = endpoint_key(source);
    const auto reply_socket = get_or_create_reply_socket(source, ec);
    if (ec || reply_socket == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        if (stopped_.load(std::memory_order_relaxed) || net::is_socket_close_error(ec))
        {
            co_return false;
        }
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} source {}:{} get reply socket failed {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 ec.message());
        co_return true;
    }

    const auto [send_ec, bytes_sent] = co_await reply_socket->async_send_to(
        boost::asio::buffer(payload, payload_len), client_endpoint_, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        if (stopped_.load(std::memory_order_relaxed) || net::is_socket_close_error(send_ec))
        {
            co_return false;
        }

        boost::system::error_code close_ec;
        close_ec = reply_socket->close(close_ec);
        (void)close_ec;
        reply_sockets_.erase(key);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} source {}:{} send udp reply to client failed {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 send_ec.message());
        co_return true;
    }

    rx_bytes_ += bytes_sent;
    trace_store::instance().add_live_rx_bytes(bytes_sent);
    co_return true;
}

std::shared_ptr<boost::asio::ip::udp::socket> tproxy_udp_session::get_or_create_reply_socket(const boost::asio::ip::udp::endpoint& source,
                                                                                             boost::system::error_code& ec)
{
    const auto normalized_source = net::normalize_endpoint(source);
    const auto key = endpoint_key(normalized_source);
    if (auto* cached = reply_sockets_.get(key); cached != nullptr)
    {
        return *cached;
    }

    auto socket = std::make_shared<boost::asio::ip::udp::socket>(worker_.io_context);
    ec = socket->open(normalized_source.protocol(), ec);
    if (ec)
    {
        return nullptr;
    }

    ec = socket->set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return nullptr;
    }

    boost::system::error_code reuse_port_ec;
    set_socket_reuse_port(socket->native_handle(), reuse_port_ec);
    (void)reuse_port_ec;

    net::set_socket_transparent(socket->native_handle(), normalized_source.address().is_v6(), ec);
    if (ec)
    {
        return nullptr;
    }

    const auto connect_mark = resolve_socket_mark(cfg_);
    if (connect_mark != 0)
    {
        net::set_socket_mark(socket->native_handle(), connect_mark, ec);
        if (ec)
        {
            return nullptr;
        }
    }

    ec = socket->bind(normalized_source, ec);
    if (ec)
    {
        return nullptr;
    }

    if (auto evicted = reply_sockets_.put_and_evict(key, socket); evicted && evicted->second != nullptr)
    {
        boost::system::error_code close_ec;
        close_ec = evicted->second->close(close_ec);
        (void)close_ec;
    }
    return socket;
}

std::string tproxy_udp_session::endpoint_key(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized = net::normalize_endpoint(endpoint);
    return normalized.address().to_string() + "|" + std::to_string(normalized.port());
}

void tproxy_udp_session::close_impl()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    idle_timer_.cancel();
    packet_channel_.close();
    if (proxy_outbound_ != nullptr)
    {
        worker_.group.spawn([outbound = proxy_outbound_]() -> boost::asio::awaitable<void> { co_await outbound->close(); });
        proxy_outbound_.reset();
    }

    boost::system::error_code ec;
    ec = upstream_socket_.close(ec);
    (void)ec;

    reply_sockets_.evict_while(
        [](const auto&, const auto& socket)
        {
            if (socket != nullptr)
            {
                boost::system::error_code close_ec;
                close_ec = socket->close(close_ec);
                (void)close_ec;
            }
            return true;
        });
}

void tproxy_udp_session::notify_closed()
{
    close_impl();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

}    // namespace relay
