#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "outbound.h"
#include "router.h"
#include "protocol.h"
#include "constants.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "udp_proxy_outbound.h"
#include "reality_udp_session.h"

namespace relay
{

reality_udp_session::reality_udp_session(boost::asio::io_context& io_context,
                                         std::shared_ptr<proxy_reality_connection> connection,
                                         std::shared_ptr<router> router,
                                         const uint32_t conn_id,
                                         const uint64_t trace_id,
                                         const config& cfg)
    : conn_id_(conn_id),
      trace_id_(trace_id),
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

boost::asio::awaitable<void> reality_udp_session::start_impl(const proxy::udp_associate_request&)
{
    boost::system::error_code ec;
    const auto close_socket = [&]()
    {
        ec = udp_socket_.close(ec);
        (void)ec;
    };

    auto bind_udp_socket = [&]() -> bool
    {
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
            LOG_WARN(
                "{} trace {:016x} conn {} stage open_ipv6_udp error {} fallback ipv4", log_event::kRoute, trace_id_, conn_id_, ec.message());
        }

        ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
        {
            return false;
        }
        ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        return !ec;
    };

    if (!bind_udp_socket())
    {
        proxy::udp_associate_reply reply;
        reply.socks_rep = socks::kRepGenFail;
        std::vector<uint8_t> reply_packet;
        if (connection_ != nullptr && proxy::encode_udp_associate_reply(reply, reply_packet))
        {
            co_await connection_->write_packet(reply_packet, ec);
        }
        co_return;
    }

    const auto local_ep = udp_socket_.local_endpoint(ec);
    if (ec)
    {
        proxy::udp_associate_reply reply;
        reply.socks_rep = socks::kRepGenFail;
        std::vector<uint8_t> reply_packet;
        if (connection_ != nullptr && proxy::encode_udp_associate_reply(reply, reply_packet))
        {
            co_await connection_->write_packet(reply_packet, ec);
        }
        close_socket();
        co_return;
    }

    bind_host_ = local_ep.address().to_string();
    bind_port_ = local_ep.port();

    proxy::udp_associate_reply reply;
    reply.socks_rep = socks::kRepSuccess;
    reply.bind_host = bind_host_;
    reply.bind_port = bind_port_;
    std::vector<uint8_t> reply_packet;
    if (!proxy::encode_udp_associate_reply(reply, reply_packet))
    {
        close_socket();
        co_return;
    }
    co_await connection_->write_packet(reply_packet, ec);
    if (ec)
    {
        close_socket();
        co_return;
    }

    LOG_INFO("{} trace {:016x} conn {} udp associate ready bind {}:{}",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_);

    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (connection_to_udp() || udp_to_connection());
    }
    else
    {
        co_await (connection_to_udp() || udp_to_connection() || idle_watchdog());
    }

    stopping_.store(true);
    close_socket();
    co_await close_proxy_upstreams();
    if (connection_ != nullptr)
    {
        boost::system::error_code close_ec;
        connection_->close(close_ec);
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} bind {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             bind_host_,
             bind_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<route_decision> reality_udp_session::decide_route(const proxy::udp_datagram& datagram) const
{
    route_decision decision;
    decision.route = route_type::kBlock;
    decision.outbound_type = "no_route";
    if (router_ == nullptr)
    {
        LOG_ERROR("{} trace {:016x} conn {} target {}:{} route unavailable",
                  log_event::kRoute,
                  trace_id_,
                  conn_id_,
                  datagram.target_host.empty() ? "unknown" : datagram.target_host,
                  datagram.target_port);
        co_return decision;
    }

    boost::system::error_code ec;
    const auto target_addr = boost::asio::ip::make_address(datagram.target_host, ec);
    if (ec)
    {
        decision = co_await router_->decide_domain_detail(datagram.target_host);
    }
    else
    {
        decision = co_await router_->decide_ip_detail(target_addr);
    }
    co_return decision;
}

boost::asio::awaitable<std::shared_ptr<udp_proxy_outbound>> reality_udp_session::get_proxy_upstream(const std::string& outbound_tag)
{
    if (stopping_.load())
    {
        co_return nullptr;
    }

    if (const auto it = proxy_upstreams_.find(outbound_tag); it != proxy_upstreams_.end())
    {
        co_return it->second;
    }

    const auto connect_result = co_await connect_udp_proxy_outbound(udp_socket_.get_executor(), conn_id_, trace_id_, cfg_, outbound_tag);
    if (connect_result.ec || connect_result.upstream == nullptr)
    {
        LOG_WARN("{} trace {:016x} conn {} out_tag {} open proxy udp upstream failed {} rep {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 outbound_tag,
                 connect_result.ec ? connect_result.ec.message() : "not_connected",
                 connect_result.socks_rep);
        co_return nullptr;
    }

    proxy_upstreams_.insert_or_assign(outbound_tag, connect_result.upstream);
    LOG_INFO("{} trace {:016x} conn {} out_tag {} proxy udp upstream ready bind {}:{}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             outbound_tag,
             connect_result.upstream->bind_host(),
             connect_result.upstream->bind_port());

    boost::asio::co_spawn(udp_socket_.get_executor(),
                          [self = shared_from_this(), outbound_tag, upstream = connect_result.upstream]() -> boost::asio::awaitable<void>
                          {
                              co_await self->proxy_to_connection(outbound_tag, upstream);
                          },
                          boost::asio::detached);

    co_return connect_result.upstream;
}

boost::asio::awaitable<void> reality_udp_session::close_proxy_upstreams()
{
    std::vector<std::shared_ptr<udp_proxy_outbound>> upstreams;
    upstreams.reserve(proxy_upstreams_.size());
    for (const auto& [outbound_tag, upstream] : proxy_upstreams_)
    {
        (void)outbound_tag;
        if (upstream != nullptr)
        {
            upstreams.push_back(upstream);
        }
    }
    proxy_upstreams_.clear();

    for (const auto& upstream : upstreams)
    {
        if (upstream != nullptr)
        {
            co_await upstream->close();
        }
    }
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
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto packet = co_await connection_->read_packet(read_timeout, ec);
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
        const auto payload_len = datagram.payload.size();
        if (payload_len > constants::udp::kMaxPayload)
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
            continue;
        }

        if (decision.route == route_type::kDirect)
        {
            auto target_ep = co_await resolve_target_endpoint(datagram.target_host, datagram.target_port, ec);
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
                continue;
            }

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
                continue;
            }

            tx_bytes_ += payload_len;
            const auto normalized_target = net::normalize_endpoint(target_ep);
            const auto now_ms = net::now_ms();
            allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
            allowed_reply_peers_.put(normalized_target, peer_cache_entry{now_ms + constants::udp::kCacheTtlMs});
            continue;
        }

        const auto upstream = co_await get_proxy_upstream(decision.outbound_tag);
        if (upstream == nullptr)
        {
            continue;
        }

        co_await upstream->send_datagram(datagram.target_host, datagram.target_port, datagram.payload.data(), datagram.payload.size(), ec);
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
            continue;
        }

        tx_bytes_ += payload_len;
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
    }
}

boost::asio::awaitable<void> reality_udp_session::udp_to_connection()
{
    if (connection_ == nullptr)
    {
        co_return;
    }

    std::vector<uint8_t> buffer(65535);
    boost::asio::ip::udp::endpoint endpoint;
    for (;;)
    {
        boost::system::error_code ec;
        const auto bytes_read = co_await udp_socket_.async_receive_from(
            boost::asio::buffer(buffer), endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        const auto normalized_ep = net::normalize_endpoint(endpoint);
        const auto now_ms = net::now_ms();
        allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
        auto* peer = allowed_reply_peers_.get(normalized_ep);
        if (peer == nullptr || peer->expires_at <= now_ms)
        {
            continue;
        }

        proxy::udp_datagram datagram;
        datagram.target_host = normalized_ep.address().to_string();
        datagram.target_port = normalized_ep.port();
        datagram.payload.assign(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(bytes_read));
        std::vector<uint8_t> packet;
        if (!proxy::encode_udp_datagram(datagram, packet))
        {
            continue;
        }

        co_await connection_->write_packet(packet, ec);
        if (ec)
        {
            break;
        }

        if (auto* refreshed_peer = allowed_reply_peers_.get(normalized_ep); refreshed_peer != nullptr)
        {
            refreshed_peer->expires_at = now_ms + constants::udp::kCacheTtlMs;
        }
        last_activity_time_ms_ = now_ms;
        rx_bytes_ += bytes_read;
    }
}

boost::asio::awaitable<void> reality_udp_session::proxy_to_connection(const std::string& outbound_tag,
                                                                      const std::shared_ptr<udp_proxy_outbound>& upstream)
{
    if (connection_ == nullptr || upstream == nullptr)
    {
        co_return;
    }

    for (;;)
    {
        if (stopping_.load())
        {
            break;
        }

        boost::system::error_code ec;
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto datagram = co_await upstream->receive_datagram(read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            LOG_WARN("{} trace {:016x} conn {} bind {}:{} out_tag {} receive proxy udp failed {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     bind_host_,
                     bind_port_,
                     outbound_tag,
                     ec.message());
            break;
        }

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
            continue;
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
            break;
        }

        last_activity_time_ms_ = net::now_ms();
        rx_bytes_ += datagram.payload.size();
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
    }

    if (const auto it = proxy_upstreams_.find(outbound_tag); it != proxy_upstreams_.end() && it->second == upstream)
    {
        proxy_upstreams_.erase(it);
    }
    if (!stopping_.load())
    {
        co_await upstream->close();
    }
}

boost::asio::awaitable<void> reality_udp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

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
            break;
        }
    }
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
