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
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "context_pool.h"
#include "proxy_protocol.h"
#include "tun_udp_session.h"
#include "proxy_udp_upstream.h"

namespace mux
{

tun_udp_session::tun_udp_session(io_worker& worker,
                                 std::shared_ptr<router> router,
                                 udp_pcb* pcb,
                                 boost::asio::ip::udp::endpoint client_endpoint,
                                 boost::asio::ip::udp::endpoint target_endpoint,
                                 const uint32_t conn_id,
                                 const config& cfg,
                                 std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(conn_id),
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
    const bool completed = co_await run();
    notify_closed();
    if (!completed)
    {
        co_return;
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("{} trace {:016x} conn {} client {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
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

boost::asio::awaitable<bool> tun_udp_session::run()
{
    route_ = co_await decide_route();
    if (route_ == route_type::kBlock)
    {
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
             mux::to_string(route_));

    if (route_ == route_type::kDirect)
    {
        co_return co_await run_direct_mode();
    }
    co_return co_await run_proxy_mode();
}

boost::asio::awaitable<route_type> tun_udp_session::decide_route() const
{
    if (router_ == nullptr)
    {
        co_return route_type::kBlock;
    }
    co_return co_await router_->decide_ip(target_endpoint_.address());
}

boost::asio::awaitable<bool> tun_udp_session::open_direct_socket()
{
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    upstream_socket_.open(protocol, ec);
    if (ec)
    {
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

    const auto connect_mark = cfg_.tproxy.enabled ? cfg_.tproxy.mark : 0U;
    if (connect_mark != 0)
    {
        net::set_socket_mark(upstream_socket_.native_handle(), connect_mark, ec);
        if (ec)
        {
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
    co_return true;
}

boost::asio::awaitable<bool> tun_udp_session::open_proxy_upstream()
{
    const auto connect_result = co_await proxy_udp_upstream::connect(worker_.io_context.get_executor(), conn_id_, trace_id_, cfg_);
    if (connect_result.ec || connect_result.upstream == nullptr)
    {
        auto ec = connect_result.ec;
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        LOG_WARN("{} trace {:016x} conn {} client {}:{} target {}:{} open tun proxy udp upstream failed {} rep {}",
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
    LOG_INFO("{} trace {:016x} conn {} opened tun proxy udp upstream client {}:{} target {}:{} bind {}:{}",
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

boost::asio::awaitable<bool> tun_udp_session::run_direct_mode()
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

boost::asio::awaitable<bool> tun_udp_session::run_proxy_mode()
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

boost::asio::awaitable<void> tun_udp_session::packets_to_direct()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        const auto sent =
            co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        (void)sent;
        if (ec)
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
            co_return;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::direct_to_client()
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
            co_return;
        }

        if (!(co_await send_to_client(normalized_target, buffer.data(), bytes_recv)))
        {
            co_return;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::packets_to_proxy()
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

        co_await proxy_upstream_->send_datagram(target_endpoint_.address().to_string(), target_endpoint_.port(), payload.data(), payload.size(), ec);
        if (ec)
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
            break;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::proxy_to_client()
{
    if (proxy_upstream_ == nullptr)
    {
        co_return;
    }

    const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
    for (;;)
    {
        boost::system::error_code ec;
        const auto datagram = co_await proxy_upstream_->receive_datagram(read_timeout, ec);
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

boost::asio::awaitable<void> tun_udp_session::idle_watchdog()
{
    const auto idle_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_.load(std::memory_order_relaxed))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            co_return;
        }

        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_INFO("{} trace {:016x} conn {} tun udp idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
            co_return;
        }
    }
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
    co_return true;
}

void tun_udp_session::close_impl()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    boost::system::error_code ec;
    idle_timer_.cancel();
    packet_channel_.close();
    if (proxy_upstream_ != nullptr)
    {
        worker_.group.spawn([upstream = proxy_upstream_]() -> boost::asio::awaitable<void> { co_await upstream->close(); });
        proxy_upstream_.reset();
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

}    // namespace mux
