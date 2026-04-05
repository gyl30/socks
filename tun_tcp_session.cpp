#include <chrono>
#include <limits>
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
#include "trace_id.h"
#include "constants.h"
#include "net_utils.h"
#include "tun_tcp_session.h"
#include "client_tunnel_pool.h"
#include "connection_tracker.h"
namespace mux
{

namespace
{

void tcp_recved_all(tcp_pcb* pcb, std::size_t size)
{
    while (pcb != nullptr && size > 0)
    {
        const auto chunk = static_cast<u16_t>(std::min<std::size_t>(size, std::numeric_limits<u16_t>::max()));
        tcp_recved(pcb, chunk);
        size -= chunk;
    }
}

}    // namespace

tun_tcp_session::tun_tcp_session(const boost::asio::any_io_executor& executor,
                                 std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                 std::shared_ptr<router> router,
                                 tcp_pcb* pcb,
                                 const uint32_t sid,
                                 const config& cfg,
                                 std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(sid),
      cfg_(cfg),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      pcb_(pcb),
      on_close_(std::move(on_close)),
      active_guard_(acquire_active_connection_guard()),
      idle_timer_(executor),
      client_wait_timer_(executor),
      send_wait_timer_(executor),
      client_addr_(tun::lwip_ip_to_string(pcb_->remote_ip)),
      client_port_(pcb_->remote_port),
      target_addr_(tun::lwip_ip_to_string(pcb_->local_ip)),
      target_port_(pcb_->local_port),
      last_activity_time_ms_(net::now_ms())
{
    tcp_arg(pcb_, this);
    tcp_recv(pcb_, &tun_tcp_session::on_recv);
    tcp_sent(pcb_, &tun_tcp_session::on_sent);
    tcp_err(pcb_, &tun_tcp_session::on_err);
    tcp_poll(pcb_, &tun_tcp_session::on_poll, 2);
    tcp_nagle_disable(pcb_);
}

boost::asio::awaitable<void> tun_tcp_session::start()
{
    co_await run();
    notify_closed();
}

void tun_tcp_session::stop()
{
    if (stopped_)
    {
        return;
    }

    stopped_ = true;
    close_client_connection(true);
    signal_all_events();
}

boost::asio::awaitable<void> tun_tcp_session::run()
{
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} tun tcp accepted",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_);

    const auto [route, backend] = co_await select_backend();
    if (backend == nullptr)
    {
        co_return;
    }

    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {}",
             log_event::kRoute,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             mux::to_string(route));

    const auto connect_result = co_await backend->connect(target_addr_, target_port_);
    if (connect_result.ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} connect failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_,
                 mux::to_string(route),
                 connect_result.ec.message());
        co_await backend->close();
        close_client_connection(true);
        co_return;
    }

    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} connected",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             mux::to_string(route));

    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_upstream(backend) && upstream_to_client(backend));
    }
    else
    {
        co_await ((client_to_upstream(backend) && upstream_to_client(backend)) || idle_watchdog());
    }

    co_await backend->close();
    close_client_connection(false);

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_addr_,
             client_port_,
             target_addr_,
             target_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> tun_tcp_session::select_backend()
{
    const auto target_ip = boost::asio::ip::make_address(target_addr_);
    const auto route = co_await router_->decide_ip(target_ip);
    if (route == route_type::kBlock)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} blocked",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_);
        co_return std::make_pair(route, std::shared_ptr<upstream>(nullptr));
    }
    if (route == route_type::kDirect)
    {
        co_return std::make_pair(route, make_direct_upstream(idle_timer_.get_executor(), conn_id_, trace_id_, cfg_));
    }
    if (route == route_type::kProxy && tunnel_pool_ != nullptr)
    {
        co_return std::make_pair(route, make_proxy_upstream(tunnel_pool_, conn_id_, trace_id_, cfg_));
    }
    if (route == route_type::kProxy)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route proxy tunnel pool unavailable",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_);
    }
    co_return std::make_pair(route_type::kBlock, std::shared_ptr<upstream>(nullptr));
}

boost::asio::awaitable<void> tun_tcp_session::client_to_upstream(const std::shared_ptr<upstream>& backend)
{
    boost::system::error_code ec;
    for (;;)
    {
        while (queue_ == nullptr && !peer_eof_ && pcb_ != nullptr && !stopped_)
        {
            co_await wait_client_event();
        }

        if (queue_ != nullptr)
        {
            pbuf* packet = queue_;
            queue_ = nullptr;
            auto payload = tun::pbuf_to_vector(packet);
            pbuf_free(packet);

            if (!payload.empty())
            {
                co_await backend->write(payload, ec);
                if (ec)
                {
                    LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stage client_to_upstream write backend failed {}",
                             log_event::kDataSend,
                             trace_id_,
                             conn_id_,
                             client_addr_,
                             client_port_,
                             target_addr_,
                             target_port_,
                             ec.message());
                    close_client_connection(true);
                    co_return;
                }
                tx_bytes_ += payload.size();
                last_activity_time_ms_ = net::now_ms();
                if (pcb_ != nullptr)
                {
                    tcp_recved_all(pcb_, payload.size());
                }
            }
            continue;
        }

        if (peer_eof_)
        {
            boost::system::error_code shutdown_ec;
            co_await backend->shutdown_send(shutdown_ec);
            co_return;
        }

        co_return;
    }
}

boost::asio::awaitable<void> tun_tcp_session::upstream_to_client(const std::shared_ptr<upstream>& backend)
{
    std::vector<uint8_t> buffer(8192);
    boost::system::error_code ec;

    for (;;)
    {
        const auto bytes_recv = co_await backend->read(buffer, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                graceful_shutdown_to_client();
            }
            else
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stage upstream_to_client read backend failed {}",
                         log_event::kDataRecv,
                         trace_id_,
                         conn_id_,
                         client_addr_,
                         client_port_,
                         target_addr_,
                         target_port_,
                         ec.message());
                close_client_connection(true);
            }
            co_return;
        }

        std::size_t offset = 0;
        while (offset < bytes_recv)
        {
            if (pcb_ == nullptr || stopped_)
            {
                co_return;
            }

            const auto writable = static_cast<std::size_t>(tcp_sndbuf(pcb_));
            if (writable == 0)
            {
                co_await wait_send_event();
                continue;
            }

            const auto chunk = std::min<std::size_t>({bytes_recv - offset, writable, static_cast<std::size_t>(std::numeric_limits<u16_t>::max())});
            const auto write_err =
                tcp_write(pcb_, buffer.data() + static_cast<std::ptrdiff_t>(offset), static_cast<u16_t>(chunk), TCP_WRITE_FLAG_COPY);
            if (write_err == ERR_MEM)
            {
                co_await wait_send_event();
                continue;
            }
            if (write_err != ERR_OK)
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stage upstream_to_client tcp_write failed {}",
                         log_event::kDataRecv,
                         trace_id_,
                         conn_id_,
                         client_addr_,
                         client_port_,
                         target_addr_,
                         target_port_,
                         tun::lwip_error_message(write_err));
                close_client_connection(true);
                co_return;
            }

            const auto output_err = tcp_output(pcb_);
            if (output_err != ERR_OK && output_err != ERR_MEM)
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stage upstream_to_client tcp_output failed {}",
                         log_event::kDataRecv,
                         trace_id_,
                         conn_id_,
                         client_addr_,
                         client_port_,
                         target_addr_,
                         target_port_,
                         tun::lwip_error_message(output_err));
                close_client_connection(true);
                co_return;
            }

            offset += chunk;
            rx_bytes_ += chunk;
            last_activity_time_ms_ = net::now_ms();
        }
    }
}

boost::asio::awaitable<void> tun_tcp_session::idle_watchdog()
{
    const auto idle_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            co_return;
        }

        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} tun tcp idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_addr_,
                     client_port_,
                     target_addr_,
                     target_port_);
            close_client_connection(true);
            co_return;
        }
    }
}

boost::asio::awaitable<void> tun_tcp_session::wait_client_event()
{
    client_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    const auto [ec] = co_await client_wait_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)ec;
}

boost::asio::awaitable<void> tun_tcp_session::wait_send_event()
{
    send_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    const auto [ec] = co_await send_wait_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)ec;
}

void tun_tcp_session::signal_client_event()
{
    client_wait_timer_.cancel();
}

void tun_tcp_session::signal_send_event()
{
    send_wait_timer_.cancel();
}

void tun_tcp_session::signal_all_events()
{
    signal_client_event();
    signal_send_event();
    idle_timer_.cancel();
}

void tun_tcp_session::close_client_connection(const bool abort_connection)
{
    if (pcb_ == nullptr)
    {
        return;
    }

    auto* pcb = pcb_;
    pcb_ = nullptr;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);
    if (abort_connection)
    {
        tcp_abort(pcb);
    }
    else
    {
        const auto close_err = tcp_close(pcb);
        if (close_err != ERR_OK)
        {
            tcp_abort(pcb);
        }
    }

    if (queue_ != nullptr)
    {
        pbuf_free(queue_);
        queue_ = nullptr;
    }

    stopped_ = true;
    signal_all_events();
}

void tun_tcp_session::graceful_shutdown_to_client()
{
    if (pcb_ == nullptr)
    {
        return;
    }

    const auto shutdown_err = tcp_shutdown(pcb_, 0, 1);
    if (shutdown_err != ERR_OK && shutdown_err != ERR_CLSD)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} tcp shutdown failed {}",
                 log_event::kConnClose,
                 trace_id_,
                 conn_id_,
                 client_addr_,
                 client_port_,
                 target_addr_,
                 target_port_,
                 tun::lwip_error_message(shutdown_err));
    }
}

void tun_tcp_session::notify_closed()
{
    stop();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

err_t tun_tcp_session::on_recv(void* arg, tcp_pcb* pcb, pbuf* packet, const err_t err)
{
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return ERR_OK;
    }

    if (err != ERR_OK)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        self->close_client_connection(true);
        return err;
    }

    if (packet == nullptr)
    {
        self->peer_eof_ = true;
        self->signal_client_event();
        return ERR_OK;
    }

    (void)pcb;
    if (self->queue_ == nullptr)
    {
        self->queue_ = packet;
    }
    else
    {
        if (self->pcb_ != nullptr && self->queue_->tot_len > TCP_WND_MAX(self->pcb_))
        {
            return ERR_WOULDBLOCK;
        }
        pbuf_cat(self->queue_, packet);
    }
    self->last_activity_time_ms_ = net::now_ms();
    self->signal_client_event();
    return ERR_OK;
}

err_t tun_tcp_session::on_sent(void* arg, tcp_pcb* pcb, const u16_t len)
{
    (void)pcb;
    (void)len;
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self != nullptr)
    {
        self->last_activity_time_ms_ = net::now_ms();
        self->signal_send_event();
    }
    return ERR_OK;
}

void tun_tcp_session::on_err(void* arg, const err_t err)
{
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self == nullptr)
    {
        return;
    }

    self->pcb_ = nullptr;
    self->peer_eof_ = true;
    self->stopped_ = true;
    self->signal_all_events();
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} lwip tcp error {}",
             log_event::kConnClose,
             self->trace_id_,
             self->conn_id_,
             self->client_addr_,
             self->client_port_,
             self->target_addr_,
             self->target_port_,
             tun::lwip_error_message(err));
}

err_t tun_tcp_session::on_poll(void* arg, tcp_pcb* pcb)
{
    (void)pcb;
    auto* self = static_cast<tun_tcp_session*>(arg);
    if (self != nullptr)
    {
        self->signal_all_events();
    }
    return ERR_OK;
}

}    // namespace mux
