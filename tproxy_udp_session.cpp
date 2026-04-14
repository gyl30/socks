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
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "proxy_protocol.h"
#include "proxy_udp_upstream.h"
#include "context_pool.h"
#include "tproxy_udp_session.h"
namespace mux
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
                                       const boost::asio::ip::udp::endpoint& client_endpoint,
                                       const boost::asio::ip::udp::endpoint& target_endpoint,
                                       const route_type route,
                                       uint32_t conn_id,
                                       const config& cfg,
                                       std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(conn_id),
      cfg_(cfg),
      worker_(worker),
      route_(route),
      last_activity_time_ms_(net::now_ms()),
      idle_timer_(worker.io_context),
      upstream_socket_(worker.io_context),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close)),
      packet_channel_(worker.io_context, constants::udp::kPacketChannelCapacity),
      reply_sockets_(constants::udp::kMaxReplySockets)
{}

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
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} drop udp packet because payload too large size {} max {}",
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

        LOG_WARN("event {} trace_id {:016x} conn_id {} enqueue udp packet failed {} client {}:{} target {}:{}",
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

boost::asio::awaitable<void> tproxy_udp_session::run()
{
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} udp session started",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             mux::to_string(route_));
    const bool completed = (route_ == route_type::kDirect) ? co_await run_direct_mode() : co_await run_proxy_mode();
    notify_closed();
    if (!completed)
    {
        co_return;
    }
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             mux::to_string(route_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<bool> tproxy_udp_session::run_direct_mode()
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (!(co_await open_direct_socket()))
    {
        co_return false;
    }

    if (cfg_.timeout.idle == 0)
    {
        co_await (packets_to_direct() || direct_to_client());
    }
    else
    {
        co_await (packets_to_direct() || direct_to_client() || idle_watchdog());
    }
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::run_proxy_mode()
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (!(co_await open_proxy_upstream()))
    {
        co_return false;
    }

    if (cfg_.timeout.idle == 0)
    {
        co_await (packets_to_proxy() || proxy_to_client());
    }
    else
    {
        co_await (packets_to_proxy() || proxy_to_client() || idle_watchdog());
    }
    if (proxy_upstream_ != nullptr)
    {
        co_await proxy_upstream_->close();
        proxy_upstream_.reset();
    }
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::open_direct_socket()
{
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    ec = upstream_socket_.open(protocol, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} open direct udp socket failed {}",
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

    if (cfg_.tproxy.mark != 0)
    {
        net::set_socket_mark(upstream_socket_.native_handle(), cfg_.tproxy.mark, ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} set direct udp mark failed {}",
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} bind direct udp socket failed {}",
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} connect direct udp socket failed {}",
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

    LOG_INFO("event {} trace_id {:016x} conn_id {} opened direct udp socket client {}:{} target {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port());
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::open_proxy_upstream()
{
    const auto connect_result = co_await proxy_udp_upstream::connect(worker_.io_context.get_executor(), conn_id_, trace_id_, cfg_);
    if (connect_result.ec || connect_result.upstream == nullptr)
    {
        const auto ec = connect_result.ec ? connect_result.ec : boost::asio::error::operation_aborted;
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} open proxy udp upstream failed {} rep {}",
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
    proxy_upstream_ = connect_result.upstream;
    LOG_INFO("event {} trace_id {:016x} conn_id {} opened proxy udp upstream client {}:{} target {}:{} bind {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             proxy_upstream_->bind_host(),
             proxy_upstream_->bind_port());
    co_return true;
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_direct()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        const auto sent =
            co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        (void)sent;
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} send direct udp payload failed {}",
                     log_event::kRelay,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            break;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::direct_to_client()
{
    std::vector<uint8_t> buffer(65535);
    const auto normalized_target = net::normalize_endpoint(target_endpoint_);
    boost::system::error_code ec;
    for (;;)
    {
        const auto bytes_recv =
            co_await upstream_socket_.async_receive(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        if (!(co_await send_to_client(normalized_target, buffer.data(), bytes_recv)))
        {
            break;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_proxy()
{
    if (proxy_upstream_ == nullptr)
    {
        co_return;
    }

    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }
        co_await proxy_upstream_->send_datagram(
            target_endpoint_.address().to_string(), target_endpoint_.port(), payload.data(), payload.size(), ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} send proxy udp payload failed {}",
                     log_event::kRoute,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            break;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_to_client()
{
    if (proxy_upstream_ == nullptr)
    {
        co_return;
    }

    for (;;)
    {
        boost::system::error_code ec;
        const auto datagram = co_await proxy_upstream_->receive_datagram(cfg_.timeout.read, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            break;
        }

        boost::system::error_code addr_ec;
        const auto source_addr = boost::asio::ip::make_address(datagram.target_host, addr_ec);
        if (addr_ec)
        {
            continue;
        }

        const auto source_endpoint = boost::asio::ip::udp::endpoint(socks_codec::normalize_ip_address(source_addr), datagram.target_port);
        if (!(co_await send_to_client(source_endpoint, datagram.payload.data(), datagram.payload.size())))
        {
            break;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::idle_watchdog()
{
    const auto idle_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_.load(std::memory_order_relaxed))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} udp session idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
            break;
        }
    }
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} source {}:{} get reply socket failed {}",
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} source {}:{} send udp reply to client failed {}",
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

    if (cfg_.tproxy.mark != 0)
    {
        net::set_socket_mark(socket->native_handle(), cfg_.tproxy.mark, ec);
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
    if (proxy_upstream_ != nullptr)
    {
        worker_.group.spawn(
            [upstream = proxy_upstream_]() -> boost::asio::awaitable<void>
            {
                co_await upstream->close();
            });
        proxy_upstream_.reset();
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

}    // namespace mux
