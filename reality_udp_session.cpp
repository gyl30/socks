#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "outbound.h"
#include "constants.h"
#include "net_utils.h"
#include "trace_store.h"
#include "datagram_relay.h"
#include "request_context.h"
#include "proxy_protocol.h"
#include "udp_session_flow.h"
#include "udp_proxy_outbound.h"
#include "reality_udp_session.h"

namespace relay
{

reality_udp_session::reality_udp_session(boost::asio::io_context& io_context,
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
      idle_timer_(io_context),
      udp_socket_(io_context),
      udp_resolver_(io_context),
      connection_(std::move(connection)),
      router_(std::move(router)),
      resolved_targets_(constants::udp::kMaxCacheEntries),
      allowed_reply_peers_(constants::udp::kMaxCacheEntries)
{
    last_activity_time_ms_ = net::now_ms();
}

boost::asio::awaitable<void> reality_udp_session::start(const proxy::udp_associate_request& request) { co_await start_impl(request); }

bool reality_udp_session::open_bind_udp_socket()
{
    boost::system::error_code ec;
    ec = udp_socket_.open(boost::asio::ip::udp::v6(), ec);
    if (!ec)
    {
        ec = udp_socket_.set_option(boost::asio::ip::v6_only(false), ec);
        if (!ec)
        {
            ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
        }
        if (!ec)
        {
            return true;
        }

        LOG_WARN("{} trace {:016x} conn {} stage open_dual_stack_udp error {} fallback ipv4",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 ec.message());
        boost::system::error_code close_ec;
        close_ec = udp_socket_.close(close_ec);
        (void)close_ec;
    }
    else
    {
        LOG_WARN("{} trace {:016x} conn {} stage open_ipv6_udp error {} fallback ipv4",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 ec.message());
    }

    ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    if (ec)
    {
        return false;
    }
    ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
    return !ec;
}

void reality_udp_session::close_udp_socket()
{
    boost::system::error_code ec;
    ec = udp_socket_.close(ec);
    (void)ec;
}

boost::asio::awaitable<bool> reality_udp_session::send_udp_associate_reply(const uint8_t socks_rep)
{
    proxy::udp_associate_reply reply;
    reply.socks_rep = socks_rep;
    if (socks_rep == socks::kRepSuccess)
    {
        reply.bind_host = bind_host_;
        reply.bind_port = bind_port_;
    }

    std::vector<uint8_t> reply_packet;
    if (connection_ == nullptr || !proxy::encode_udp_associate_reply(reply, reply_packet))
    {
        co_return false;
    }

    boost::system::error_code ec;
    co_await connection_->write_packet(reply_packet, ec);
    co_return !ec;
}

boost::asio::awaitable<bool> reality_udp_session::establish_udp_associate()
{
    if (!open_bind_udp_socket())
    {
        (void)co_await send_udp_associate_reply(socks::kRepGenFail);
        co_return false;
    }

    boost::system::error_code ec;
    const auto local_ep = udp_socket_.local_endpoint(ec);
    if (ec)
    {
        (void)co_await send_udp_associate_reply(socks::kRepGenFail);
        close_udp_socket();
        co_return false;
    }

    bind_host_ = local_ep.address().to_string();
    bind_port_ = local_ep.port();
    if (!(co_await send_udp_associate_reply(socks::kRepSuccess)))
    {
        close_udp_socket();
        co_return false;
    }
    co_return true;
}

request_context reality_udp_session::make_route_request(const proxy::udp_datagram& datagram) const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = datagram.target_host,
        .target_port = datagram.target_port,
        .client_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .client_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .local_host = bind_host_,
        .local_port = bind_port_,
    };
}

request_context reality_udp_session::make_proxy_outbound_request() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = "unknown",
        .target_port = 0,
        .client_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .client_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
        .local_host = bind_host_,
        .local_port = bind_port_,
    };
}

boost::asio::awaitable<void> reality_udp_session::start_impl(const proxy::udp_associate_request&)
{
    if (!(co_await establish_udp_associate()))
    {
        co_return;
    }

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
    });
    LOG_INFO("{} trace {:016x} conn {} udp associate ready bind {}:{}",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_);

    const bool completed = co_await finish_udp_session(
        [this]() -> boost::asio::awaitable<bool>
        {
            using boost::asio::experimental::awaitable_operators::operator||;
            if (cfg_.timeout.idle == 0)
            {
                co_await (connection_to_udp() || udp_to_connection());
            }
            else
            {
                co_await (connection_to_udp() || udp_to_connection() || idle_watchdog());
            }
            co_return true;
        },
        close_reason_,
        [this](const bool) -> boost::asio::awaitable<void>
        {
            stopping_.store(true);
            close_udp_socket();
            co_await close_proxy_outbounds();
            if (connection_ != nullptr)
            {
                boost::system::error_code close_ec;
                connection_->close(close_ec);
            }
            co_return;
        });
    (void)completed;

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    record_udp_session_close_trace(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .outbound_tag = "unknown",
        .outbound_type = "proxy",
        .target_host = "unknown",
        .target_port = 0,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
    },
                                   tx_bytes_,
                                   rx_bytes_,
                                   duration_ms,
                                   close_reason_);
    LOG_INFO("{} trace {:016x} conn {} bind {}:{} close_reason {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_,
             to_string(close_reason_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<route_decision> reality_udp_session::decide_route(const proxy::udp_datagram& datagram) const
{
    const auto request = make_route_request(datagram);
    const auto flow_result = co_await prepare_udp_route_flow(request, router_);
    co_return flow_result.decision;
}

boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> reality_udp_session::get_proxy_outbound(const std::string& outbound_tag)
{
    if (stopping_.load())
    {
        co_return nullptr;
    }

    if (const auto it = proxy_outbounds_.find(outbound_tag); it != proxy_outbounds_.end())
    {
        co_return it->second;
    }

    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .outbound_tag = outbound_tag,
        .outbound_type = "proxy",
        .target_host = "unknown",
        .target_port = 0,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
    });
    const auto request = make_proxy_outbound_request();
    const auto connect_result = co_await connect_udp_proxy_flow(udp_socket_.get_executor(), request, outbound_tag, cfg_);
    co_return co_await apply_proxy_outbound_connect_result(outbound_tag, connect_result);
}

void reality_udp_session::record_proxy_outbound_connect_result(const std::string& outbound_tag,
                                                               const bool success,
                                                               const boost::system::error_code& ec) const
{
    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = success ? trace_result::kOk : trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "reality",
        .outbound_tag = outbound_tag,
        .outbound_type = "proxy",
        .target_host = "unknown",
        .target_port = 0,
        .local_host = bind_host_,
        .local_port = bind_port_,
        .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
        .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
    };
    if (ec)
    {
        event.error_code = static_cast<int32_t>(ec.value());
        event.error_message = ec.message();
    }
    trace_store::instance().record_event(std::move(event));
}

boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> reality_udp_session::apply_proxy_outbound_connect_result(
    const std::string& outbound_tag, const udp_proxy_outbound_connect_result& connect_result)
{
    if (connect_result.ec || connect_result.outbound == nullptr)
    {
        LOG_WARN("{} trace {:016x} conn {} out_tag {} open proxy udp outbound failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 outbound_tag,
                 connect_result.ec ? connect_result.ec.message() : "not_connected",
                 connect_result.socks_rep);
        record_proxy_outbound_connect_result(
            outbound_tag, false, connect_result.ec ? connect_result.ec : boost::asio::error::operation_aborted);
        co_return nullptr;
    }

    proxy_outbounds_.insert_or_assign(outbound_tag, connect_result.outbound);
    record_proxy_outbound_connect_result(outbound_tag, true, {});
    LOG_INFO("{} trace {:016x} conn {} out_tag {} proxy udp outbound ready bind {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             outbound_tag,
             connect_result.outbound->bind_host(),
             connect_result.outbound->bind_port());

    boost::asio::co_spawn(udp_socket_.get_executor(),
                          [self = shared_from_this(), outbound_tag, outbound = connect_result.outbound]() -> boost::asio::awaitable<void>
                          {
                              co_await self->proxy_to_connection(outbound_tag, outbound);
                          },
                          boost::asio::detached);

    co_return connect_result.outbound;
}

boost::asio::awaitable<void> reality_udp_session::close_proxy_outbounds()
{
    std::vector<std::shared_ptr<udp_proxy_outbound>> outbounds;
    outbounds.reserve(proxy_outbounds_.size());
    for (const auto& [outbound_tag, outbound] : proxy_outbounds_)
    {
        (void)outbound_tag;
        if (outbound != nullptr)
        {
            outbounds.push_back(outbound);
        }
    }
    proxy_outbounds_.clear();

    for (const auto& outbound : outbounds)
    {
        if (outbound != nullptr)
        {
            co_await outbound->close();
        }
    }
}

boost::asio::awaitable<bool> reality_udp_session::forward_direct_datagram(const proxy::udp_datagram& datagram, const std::string& route_name)
{
    boost::system::error_code ec;
    const auto target_ep = co_await resolve_target_endpoint(datagram.target_host, datagram.target_port, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} target {}:{} route {} resolve failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 datagram.target_host,
                 datagram.target_port,
                 route_name,
                 ec.message());
        co_return false;
    }

    const auto payload_len = datagram.payload.size();
    co_await udp_socket_.async_send_to(
        boost::asio::buffer(datagram.payload.data(), payload_len), target_ep, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} target {}:{} route {} send udp failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 target_ep.address().to_string(),
                 target_ep.port(),
                 route_name,
                 ec.message());
        co_return false;
    }

    tx_bytes_ += payload_len;
    trace_store::instance().add_live_tx_bytes(payload_len);
    const auto normalized_target = net::normalize_endpoint(target_ep);
    const auto now_ms = net::now_ms();
    allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
    allowed_reply_peers_.put(normalized_target, peer_cache_entry{now_ms + constants::udp::kCacheTtlMs});
    co_return true;
}

boost::asio::awaitable<bool> reality_udp_session::forward_proxy_datagram(const proxy::udp_datagram& datagram,
                                                                         const route_decision& decision,
                                                                         const std::string& route_name)
{
    const auto outbound = co_await get_proxy_outbound(decision.outbound_tag);
    if (outbound == nullptr)
    {
        co_return false;
    }

    boost::system::error_code ec;
    co_await outbound->send_datagram(datagram.target_host, datagram.target_port, datagram.payload.data(), datagram.payload.size(), ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} target {}:{} route {} send proxy udp failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 datagram.target_host,
                 datagram.target_port,
                 route_name,
                 ec.message());
        co_return false;
    }

    const auto payload_len = datagram.payload.size();
    tx_bytes_ += payload_len;
    trace_store::instance().add_live_tx_bytes(payload_len);
    LOG_INFO("{} trace {:016x} conn {} bind {}:{} target {}:{} route {} forwarded proxy udp bytes {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_,
             datagram.target_host,
             datagram.target_port,
             route_name,
             payload_len);
    co_return true;
}

boost::asio::awaitable<bool> reality_udp_session::process_connection_datagram(const proxy::udp_datagram& datagram,
                                                                              const route_decision& decision,
                                                                              const std::string& route_name)
{
    if (decision.route == route_type::kBlock)
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} target {}:{} route {} drop udp datagram",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 datagram.target_host,
                 datagram.target_port,
                 route_name);
        co_return true;
    }

    if (decision.route == route_type::kDirect)
    {
        (void)co_await forward_direct_datagram(datagram, route_name);
        co_return true;
    }

    (void)co_await forward_proxy_datagram(datagram, decision, route_name);
    co_return true;
}

boost::asio::awaitable<std::size_t> reality_udp_session::forward_proxy_reply_to_connection(
    const proxy::udp_datagram& datagram, const std::string& outbound_tag, boost::system::error_code& ec)
{
    std::vector<uint8_t> packet;
    if (!proxy::encode_udp_datagram(datagram, packet))
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} out_tag {} encode proxy udp datagram failed target {}:{}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 outbound_tag,
                 datagram.target_host,
                 datagram.target_port);
        co_return 0;
    }

    co_await connection_->write_packet(packet, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} bind {}:{} out_tag {} write proxy udp reply failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 bind_host_,
                 bind_port_,
                 outbound_tag,
                 ec.message());
        co_return 0;
    }

    LOG_INFO("{} trace {:016x} conn {} bind {}:{} out_tag {} recv proxy udp target {}:{} bytes {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_,
             outbound_tag,
             datagram.target_host,
             datagram.target_port,
             datagram.payload.size());
    co_return datagram.payload.size();
}

boost::asio::awaitable<void> reality_udp_session::connection_to_udp()
{
    if (connection_ == nullptr)
    {
        co_return;
    }

    for (;;)
    {
        boost::system::error_code ec;
        const auto packet = co_await connection_->read_packet(cfg_.timeout.read, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            break;
        }

        proxy::udp_datagram datagram;
        if (!proxy::decode_udp_datagram(packet.data(), packet.size(), datagram))
        {
            LOG_WARN("{} trace {:016x} conn {} bind {}:{} invalid udp datagram payload_size {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     bind_host_,
                     bind_port_,
                     packet.size());
            break;
        }

        last_activity_time_ms_ = net::now_ms();
        if (const auto payload_len = datagram.payload.size(); payload_len > constants::udp::kMaxPayload)
        {
            LOG_WARN("{} trace {:016x} conn {} bind {}:{} target {}:{} drop udp datagram payload too large size {} max {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     bind_host_,
                     bind_port_,
                     datagram.target_host,
                     datagram.target_port,
                     payload_len,
                     constants::udp::kMaxPayload);
            continue;
        }

        const auto decision = co_await decide_route(datagram);
        const auto route_name = decision.matched ? decision.outbound_tag : decision.outbound_type;
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kRouteDecideDone,
            .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = datagram.target_host,
            .target_port = datagram.target_port,
            .local_host = bind_host_,
            .local_port = bind_port_,
            .remote_host = std::string(connection_ != nullptr ? connection_->remote_host() : std::string_view("unknown")),
            .remote_port = static_cast<uint16_t>(connection_ != nullptr ? connection_->remote_port() : 0U),
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
        });
        (void)co_await process_connection_datagram(datagram, decision, route_name);
    }
}

boost::asio::awaitable<void> reality_udp_session::udp_to_connection()
{
    if (connection_ == nullptr)
    {
        co_return;
    }

    udp_socket_reply_relay_context relay_context{
        .socket = udp_socket_,
        .last_activity_time_ms = last_activity_time_ms_,
        .rx_bytes = rx_bytes_,
    };
    co_await relay_udp_socket_replies(
        relay_context,
        [this](const boost::asio::ip::udp::endpoint& endpoint, const uint64_t now_ms)
        {
            const auto normalized_ep = net::normalize_endpoint(endpoint);
            allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
            auto* peer = allowed_reply_peers_.get(normalized_ep);
            return peer != nullptr && peer->expires_at > now_ms;
        },
        [this](const boost::asio::ip::udp::endpoint& endpoint, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec)
            -> boost::asio::awaitable<std::size_t>
        {
            const auto normalized_ep = net::normalize_endpoint(endpoint);
            proxy::udp_datagram datagram;
            datagram.target_host = normalized_ep.address().to_string();
            datagram.target_port = normalized_ep.port();
            datagram.payload.assign(payload, payload + payload_len);
            std::vector<uint8_t> packet;
            if (!proxy::encode_udp_datagram(datagram, packet))
            {
                co_return 0;
            }

            co_await connection_->write_packet(packet, ec);
            if (ec)
            {
                co_return 0;
            }

            const auto now_ms = net::now_ms();
            if (auto* refreshed_peer = allowed_reply_peers_.get(normalized_ep); refreshed_peer != nullptr)
            {
                refreshed_peer->expires_at = now_ms + constants::udp::kCacheTtlMs;
            }
            co_return payload_len;
        },
        [](const boost::system::error_code&) {});
}

boost::asio::awaitable<void> reality_udp_session::proxy_to_connection(const std::string& outbound_tag,
                                                                      const std::shared_ptr<udp_proxy_outbound>& outbound)
{
    if (connection_ == nullptr || outbound == nullptr)
    {
        co_return;
    }

    proxy_outbound_reply_relay_context relay_context{
        .read_timeout_sec = cfg_.timeout.read,
        .last_activity_time_ms = last_activity_time_ms_,
        .rx_bytes = rx_bytes_,
    };
    co_await relay_proxy_outbound_replies(
        outbound,
        relay_context,
        [this]() { return stopping_.load(); },
        [this, &outbound_tag](const proxy::udp_datagram& datagram, boost::system::error_code& ec) -> boost::asio::awaitable<std::size_t>
        {
            co_return co_await forward_proxy_reply_to_connection(datagram, outbound_tag, ec);
        },
        [this, &outbound_tag](const boost::system::error_code& ec)
        {
            if (stopping_.load() || net::is_socket_close_error(ec))
            {
                return;
            }
            LOG_WARN("{} trace {:016x} conn {} bind {}:{} out_tag {} receive proxy udp failed {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     bind_host_,
                     bind_port_,
                     outbound_tag,
                     ec.message());
        });

    if (const auto it = proxy_outbounds_.find(outbound_tag); it != proxy_outbounds_.end() && it->second == outbound)
    {
        proxy_outbounds_.erase(it);
    }
    if (!stopping_.load())
    {
        co_await outbound->close();
    }
}

boost::asio::awaitable<void> reality_udp_session::idle_watchdog()
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
            LOG_INFO("{} trace {:016x} conn {} udp session idle timeout bind {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     bind_host_,
                     bind_port_);
            stopping_.store(true);
            boost::system::error_code close_ec;
            udp_socket_.close(close_ec);
            if (connection_ != nullptr)
            {
                connection_->close(close_ec);
            }
        });
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> reality_udp_session::resolve_target_endpoint(const std::string& host,
                                                                                                    const uint16_t port,
                                                                                                    boost::system::error_code& ec)
{
    const auto key = host + ":" + std::to_string(port);
    const auto now_ms = net::now_ms();
    resolved_targets_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
    auto* cached = resolved_targets_.get(key);
    if (cached != nullptr)
    {
        if (cached->expires_at <= now_ms)
        {
            resolved_targets_.erase(key);
        }
        else if (cached->negative)
        {
            ec = cached->last_error;
            co_return boost::asio::ip::udp::endpoint{};
        }
        else
        {
            co_return cached->endpoint;
        }
    }

    boost::asio::ip::udp::endpoint endpoint;
    boost::system::error_code address_ec;
    const auto address = boost::asio::ip::make_address(host, address_ec);
    if (!address_ec)
    {
        endpoint = {socks_codec::normalize_ip_address(address), port};
        resolved_targets_.put(
            key, endpoint_cache_entry{.endpoint = endpoint, .expires_at = now_ms + constants::udp::kCacheTtlMs, .last_error = {}, .negative = false});
        co_return endpoint;
    }

    const auto results = co_await net::wait_resolve_with_timeout(udp_resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec || results.begin() == results.end())
    {
        if (!ec)
        {
            ec = boost::asio::error::host_not_found;
        }
        resolved_targets_.put(key,
                              endpoint_cache_entry{
                                  .endpoint = {},
                                  .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs,
                                  .last_error = ec,
                                  .negative = true,
                              });
        co_return boost::asio::ip::udp::endpoint{};
    }

    endpoint = net::normalize_endpoint(*results.begin());
    resolved_targets_.put(
        key, endpoint_cache_entry{.endpoint = endpoint, .expires_at = now_ms + constants::udp::kCacheTtlMs, .last_error = {}, .negative = false});
    co_return endpoint;
}

}    // namespace relay
