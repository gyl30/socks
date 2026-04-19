#include <chrono>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
#include "protocol.h"
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "trace_store.h"
#include "context_pool.h"
#include "datagram_relay.h"
#include "request_context.h"
#include "tun_udp_session.h"
#include "proxy_protocol.h"
#include "udp_session_flow.h"
#include "udp_proxy_outbound.h"
#include "transparent_udp_session_flow.h"

namespace relay
{

tun_udp_session::tun_udp_session(io_worker& worker,
                                 std::shared_ptr<router> router,
                                 udp_pcb* pcb,
                                 boost::asio::ip::udp::endpoint client_endpoint,
                                 boost::asio::ip::udp::endpoint target_endpoint,
                                 const uint32_t conn_id,
                                 std::string inbound_tag,
                                 const config& cfg,
                                 std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(conn_id),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      worker_(worker),
      router_(std::move(router)),
      pcb_(pcb),
      last_activity_time_ms_(net::now_ms()),
      idle_timer_(worker.io_context),
      upstream_socket_(worker.io_context),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close)),
      packet_channel_(worker.io_context, constants::udp::kPacketChannelCapacity)
{
    udp_recv(pcb_, &tun_udp_session::on_recv, this);
}

boost::asio::awaitable<void> tun_udp_session::start()
{
    const bool completed =
        co_await finish_transparent_udp_session([this]() -> boost::asio::awaitable<bool> { co_return co_await run(); },
                                                close_reason_,
                                                [this]() { notify_closed(); });
    if (!completed)
    {
        co_return;
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {} close_reason {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             relay::to_string(route_),
             to_string(close_reason_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

void tun_udp_session::stop() { close_impl(); }

void tun_udp_session::enqueue_packet(pbuf* packet)
{
    if (packet == nullptr)
    {
        return;
    }

    auto payload = tun::pbuf_to_vector(packet);
    pbuf_free(packet);

    if (stopped_.load(std::memory_order_relaxed))
    {
        return;
    }

    if (payload.size() > constants::udp::kMaxPayload)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} drop tun udp payload too large {} max {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 payload.size(),
                 constants::udp::kMaxPayload);
        return;
    }

    last_activity_time_ms_ = net::now_ms();
    packet_channel_.async_send(boost::system::error_code{},
                               std::move(payload),
                               [self = shared_from_this()](const boost::system::error_code& ec)
                               {
                                   if (!ec)
                                   {
                                       return;
                                   }
                                   if (self->stopped_.load(std::memory_order_relaxed) || net::is_basic_close_error(ec) ||
                                       ec == boost::asio::experimental::error::channel_errors::channel_closed)
                                   {
                                       return;
                                   }

                                   LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} enqueue tun udp packet failed {}",
                                            log_event::kRelay,
                                            self->trace_id_,
                                            self->conn_id_,
                                            self->client_endpoint_.address().to_string(),
                                            self->client_endpoint_.port(),
                                            self->target_endpoint_.address().to_string(),
                                            self->target_endpoint_.port(),
                                            ec.message());
                               });
}

void tun_udp_session::on_recv(void* arg, udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, u16_t port)
{
    (void)pcb;
    (void)addr;
    (void)port;

    auto* self = static_cast<tun_udp_session*>(arg);
    if (self == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return;
    }

    self->enqueue_packet(packet);
}

request_context tun_udp_session::make_request_context() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
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

void tun_udp_session::apply_route_decision(const route_decision& decision)
{
    route_ = decision.route;
    outbound_tag_ = decision.outbound_tag;
    outbound_type_ = decision.outbound_type;
    match_type_ = decision.match_type;
    match_value_ = decision.match_value;
}

boost::asio::awaitable<bool> tun_udp_session::run_selected_mode()
{
    if (route_ == route_type::kDirect)
    {
        co_return co_await run_direct_mode();
    }
    co_return co_await run_proxy_mode();
}

boost::asio::awaitable<bool> tun_udp_session::run()
{
    const auto request = make_request_context();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
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
        .inbound_type = "tun",
        .outbound_tag = "",
        .outbound_type = "",
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
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
    const auto flow_result = co_await prepare_udp_route_flow(request, router_);
    apply_route_decision(flow_result.decision);
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kRouteDecideDone,
        .result = (route_ == route_type::kBlock) ? trace_result::kFail : trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    if (route_ == route_type::kBlock)
    {
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kSessionError,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tun",
            .outbound_tag = outbound_tag_,
            .outbound_type = outbound_type_,
            .target_host = target_endpoint_.address().to_string(),
            .target_port = target_endpoint_.port(),
            .local_host = "",
            .local_port = 0,
            .remote_host = client_endpoint_.address().to_string(),
            .remote_port = client_endpoint_.port(),
            .route_type = relay::to_string(route_),
            .match_type = match_type_,
            .match_value = match_value_,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms = 0,
            .error_code = 0,
            .error_message = "route blocked",
            .extra = {},
        });
        close_reason_ = udp_close_reason::kRouteBlocked;
        LOG_WARN("{} trace {:016x} conn {} blocked tun udp target {}:{}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port());
        co_return false;
    }

    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             relay::to_string(route_));
    co_return co_await run_selected_mode();
}

boost::asio::awaitable<bool> tun_udp_session::open_direct_socket()
{
    const auto connect_start = std::chrono::steady_clock::now();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_.empty() ? std::string("direct") : outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    upstream_socket_.open(protocol, ec);
    if (ec)
    {
        record_open_direct_socket_result(false, ec, connect_start);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} open tun direct udp socket failed {}",
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
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} set tun direct udp mark failed {}",
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

    upstream_socket_.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} bind tun direct udp socket failed {}",
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

    upstream_socket_.connect(target_endpoint_, ec);
    if (ec)
    {
        record_open_direct_socket_result(false, ec, connect_start);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} connect tun direct udp socket failed {}",
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

    LOG_INFO("{} trace {:016x} conn {} opened tun direct udp client {}:{} target {}:{}",
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

void tun_udp_session::record_open_direct_socket_result(const bool success,
                                                       const boost::system::error_code& ec,
                                                       const std::chrono::steady_clock::time_point connect_start) const
{
    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = success ? trace_result::kOk : trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_.empty() ? std::string("direct") : outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
        .error_code = 0,
        .error_message = "",
        .extra = {},
    };
    if (ec)
    {
        event.error_code = ec.value();
        event.error_message = ec.message();
    }
    trace_store::instance().record_event(std::move(event));
}

boost::asio::awaitable<bool> tun_udp_session::open_proxy_outbound()
{
    const auto connect_start = std::chrono::steady_clock::now();
    const auto request = make_request_context();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "tun",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_.empty() ? std::string("proxy") : outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms = 0,
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    const auto connect_result = co_await connect_udp_proxy_flow(worker_.io_context.get_executor(), request, outbound_tag_, cfg_);
    co_return co_await apply_open_proxy_outbound_result(connect_result, connect_start);
}

boost::asio::awaitable<bool> tun_udp_session::apply_open_proxy_outbound_result(
    const udp_proxy_outbound_connect_result& connect_result, const std::chrono::steady_clock::time_point connect_start)
{
    if (connect_result.ec || connect_result.outbound == nullptr)
    {
        auto ec = connect_result.ec;
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kOutboundConnectDone,
            .result = trace_result::kFail,
            .inbound_tag = inbound_tag_,
            .inbound_type = "tun",
            .outbound_tag = outbound_tag_,
            .outbound_type = outbound_type_.empty() ? std::string("proxy") : outbound_type_,
            .target_host = target_endpoint_.address().to_string(),
            .target_port = target_endpoint_.port(),
            .local_host = "",
            .local_port = 0,
            .remote_host = client_endpoint_.address().to_string(),
            .remote_port = client_endpoint_.port(),
            .route_type = relay::to_string(route_),
            .match_type = match_type_,
            .match_value = match_value_,
            .bytes_tx = 0,
            .bytes_rx = 0,
            .latency_ms =
                static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
            .error_code = ec.value(),
            .error_message = ec.message(),
            .extra = {},
        });
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} open tun proxy udp outbound failed {} rep {}",
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
    LOG_INFO("{} trace {:016x} conn {} opened tun proxy udp outbound client {}:{} target {}:{} bind {}:{}",
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
        .inbound_type = "tun",
        .outbound_tag = outbound_tag_,
        .outbound_type = outbound_type_.empty() ? std::string("proxy") : outbound_type_,
        .target_host = target_endpoint_.address().to_string(),
        .target_port = target_endpoint_.port(),
        .local_host = "",
        .local_port = 0,
        .remote_host = client_endpoint_.address().to_string(),
        .remote_port = client_endpoint_.port(),
        .route_type = relay::to_string(route_),
        .match_type = match_type_,
        .match_value = match_value_,
        .bytes_tx = 0,
        .bytes_rx = 0,
        .latency_ms =
            static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - connect_start).count()),
        .error_code = 0,
        .error_message = "",
        .extra = {},
    });
    co_return true;
}

boost::asio::awaitable<bool> tun_udp_session::run_direct_mode()
{
    co_return co_await run_transparent_udp_mode(
        cfg_.timeout.idle,
        [this]() -> boost::asio::awaitable<bool> { co_return co_await open_direct_socket(); },
        [this]() -> boost::asio::awaitable<void> { co_await packets_to_direct(); },
        [this]() -> boost::asio::awaitable<void> { co_await direct_to_client(); },
        [this]() -> boost::asio::awaitable<void> { co_await idle_watchdog(); },
        []() -> boost::asio::awaitable<void> { co_return; });
}

boost::asio::awaitable<bool> tun_udp_session::run_proxy_mode()
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

boost::asio::awaitable<void> tun_udp_session::packets_to_direct()
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
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} send tun direct udp payload failed {}",
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

boost::asio::awaitable<void> tun_udp_session::direct_to_client()
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

boost::asio::awaitable<void> tun_udp_session::packets_to_proxy()
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
            LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} send tun proxy udp payload failed {}",
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

boost::asio::awaitable<void> tun_udp_session::proxy_to_client()
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
                LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} invalid tun proxy udp source {}:{}",
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

boost::asio::awaitable<void> tun_udp_session::idle_watchdog()
{
    datagram_idle_watchdog_context relay_context{
        .timer = idle_timer_,
        .idle_timeout_sec = cfg_.timeout.idle,
        .last_activity_time_ms = last_activity_time_ms_,
    };
    co_await run_datagram_idle_watchdog(
        relay_context,
        close_reason_,
        [this]()
        {
            LOG_INFO("{} trace {:016x} conn {} tun udp idle timeout client {}:{} target {}:{}",
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

boost::asio::awaitable<bool> tun_udp_session::send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                             const uint8_t* payload,
                                                             const std::size_t payload_len)
{
    if (stopped_.load(std::memory_order_relaxed) || pcb_ == nullptr)
    {
        co_return false;
    }

    ip_addr_t source_addr{};
    if (!tun::address_to_lwip(source.address(), source_addr))
    {
        co_return false;
    }

    auto* out = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload_len), PBUF_RAM);
    if (out == nullptr)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} source {}:{} alloc lwip udp payload failed {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 payload_len);
        co_return true;
    }

    if (pbuf_take(out, payload, static_cast<u16_t>(payload_len)) != ERR_OK)
    {
        pbuf_free(out);
        co_return false;
    }

    const auto send_err = udp_sendfrom(pcb_, out, &source_addr, source.port());
    pbuf_free(out);
    if (send_err != ERR_OK)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} source {}:{} send tun udp reply failed {}",
                 log_event::kRelay,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 tun::lwip_error_message(send_err));
        co_return false;
    }

    rx_bytes_ += payload_len;
    trace_store::instance().add_live_rx_bytes(payload_len);
    co_return true;
}

void tun_udp_session::close_impl()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }
    close_reason_ = stop_udp_close_reason(close_reason_);

    boost::system::error_code ec;
    idle_timer_.cancel();
    packet_channel_.close();
    if (proxy_outbound_ != nullptr)
    {
        worker_.group.spawn([outbound = proxy_outbound_]() -> boost::asio::awaitable<void> { co_await outbound->close(); });
        proxy_outbound_.reset();
    }
    upstream_socket_.close(ec);

    if (pcb_ != nullptr)
    {
        udp_recv(pcb_, nullptr, nullptr);
        udp_remove(pcb_);
        pcb_ = nullptr;
    }
}

void tun_udp_session::notify_closed()
{
    close_impl();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

}    // namespace relay
