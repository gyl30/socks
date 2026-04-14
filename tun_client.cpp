#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <vector>
#include <cstring>
#include <utility>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
#include "constants.h"
#include "net_utils.h"
#include "tun_client.h"
namespace mux
{

tun_client::tun_client(io_context_pool& pool, const config& cfg)
    : cfg_(cfg), owner_worker_(pool.get_io_worker()), router_(std::make_shared<router>())
{
}

void tun_client::start()
{
    if (!cfg_.tun.enabled)
    {
        LOG_INFO("event {} stage start tun client disabled", log_event::kConnInit);
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("event {} stage start load router data for tun client failed", log_event::kConnInit);
        std::exit(EXIT_FAILURE);
    }

    boost::system::error_code ec;
    if (!device_.open(cfg_.tun, ec))
    {
        LOG_ERROR("event {} stage start open tun device name {} mtu {} failed {}",
                  log_event::kConnInit,
                  cfg_.tun.name.empty() ? "auto" : cfg_.tun.name,
                  cfg_.tun.mtu,
                  ec.message());
        std::exit(EXIT_FAILURE);
    }

#ifdef _WIN32
    auto* read_handle = static_cast<HANDLE>(device_.read_wait_handle());
    if (read_handle == nullptr)
    {
        LOG_ERROR("event {} device {} index {} get wintun read event failed", log_event::kConnInit, device_.name(), device_.index());
        std::exit(EXIT_FAILURE);
    }

    HANDLE duplicated = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), read_handle, GetCurrentProcess(), &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        LOG_ERROR("event {} device {} index {} duplicate wintun read event failed {}",
                  log_event::kConnInit,
                  device_.name(),
                  device_.index(),
                  GetLastError());
        std::exit(EXIT_FAILURE);
    }
    tun_wait_handle_.assign(duplicated, ec);
    if (ec)
    {
        LOG_ERROR(
            "event {} device {} index {} assign wintun wait handle failed {}", log_event::kConnInit, device_.name(), device_.index(), ec.message());
        std::exit(EXIT_FAILURE);
    }
#else
    const int wait_fd = ::dup(device_.native_handle());
    if (wait_fd < 0)
    {
        LOG_ERROR("event {} device {} index {} dup tun fd failed errno {}", log_event::kConnInit, device_.name(), device_.index(), errno);
        std::exit(EXIT_FAILURE);
    }
    tun_stream_.assign(wait_fd, ec);
    if (ec)
    {
        LOG_ERROR("event {} device {} index {} assign tun fd failed {}", log_event::kConnInit, device_.name(), device_.index(), ec.message());
        std::exit(EXIT_FAILURE);
    }
#endif

    if (!init_stack())
    {
        LOG_ERROR("event {} device {} index {} initialize tun lwip stack failed", log_event::kConnInit, device_.name(), device_.index());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("event {} device {} index {} tun stack ready", log_event::kConnInit, device_.name(), device_.index());
    owner_worker_.group.spawn([self = shared_from_this()]() { return self->read_loop(); });
    owner_worker_.group.spawn([self = shared_from_this()]() { return self->timer_loop(); });
    LOG_INFO("event {} device {} index {} tun client started", log_event::kConnEstablished, device_.name(), device_.index());
}

void tun_client::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(owner_worker_.io_context,
                      [self = shared_from_this()]()
                      {
                          LOG_INFO(
                              "event {} device {} index {} tun client stopping", log_event::kConnClose, self->device_.name(), self->device_.index());
                          boost::system::error_code ec;
#ifdef _WIN32
                          self->tun_wait_handle_.close(ec);
#else
                          self->tun_stream_.close(ec);
#endif
                          self->shutdown_stack();
                          self->device_.close();
                      });
}

bool tun_client::init_stack()
{
    lwip_init();

    if (netif_add_noaddr(&netif_, this, &tun_client::netif_init_handler, ip_input) == nullptr)
    {
        return false;
    }

    ip4_addr_t loopback4;
    ip4_addr_t mask4;
    ip4_addr_t gw4;
    ip4_addr_set_loopback(&loopback4);
    ip4_addr_set_any(&mask4);
    ip4_addr_set_any(&gw4);
    netif_set_addr(&netif_, &loopback4, &mask4, &gw4);

    ip6_addr_t loopback6;
    ip6_addr_set_loopback(&loopback6);
    netif_add_ip6_address(&netif_, &loopback6, nullptr);

    netif_set_up(&netif_);
    netif_set_link_up(&netif_);
    netif_set_default(&netif_);
    netif_set_flags(&netif_, NETIF_FLAG_PRETEND_TCP);

    tcp_listener_ = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (tcp_listener_ == nullptr)
    {
        shutdown_stack();
        return false;
    }
    tcp_bind_netif(tcp_listener_, &netif_);
    if (tcp_bind(tcp_listener_, nullptr, 0) != ERR_OK)
    {
        shutdown_stack();
        return false;
    }
    tcp_listener_ = tcp_listen(tcp_listener_);
    if (tcp_listener_ == nullptr)
    {
        shutdown_stack();
        return false;
    }
    tcp_arg(tcp_listener_, this);
    tcp_accept(tcp_listener_, &tun_client::tcp_accept_handler);

    udp_listener_ = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (udp_listener_ == nullptr)
    {
        shutdown_stack();
        return false;
    }
    udp_bind_netif(udp_listener_, &netif_);
    if (udp_bind(udp_listener_, nullptr, 0) != ERR_OK)
    {
        shutdown_stack();
        return false;
    }
    udp_recv(udp_listener_, &tun_client::udp_recv_handler, this);

    stack_ready_ = true;
    return true;
}

void tun_client::shutdown_stack()
{
    for (auto& [_, session] : tcp_sessions_)
    {
        if (session != nullptr)
        {
            session->stop();
        }
    }
    tcp_sessions_.clear();

    for (auto& [_, session] : udp_sessions_)
    {
        if (session != nullptr)
        {
            session->stop();
        }
    }
    udp_sessions_.clear();

    if (udp_listener_ != nullptr)
    {
        udp_recv(udp_listener_, nullptr, nullptr);
        udp_remove(udp_listener_);
        udp_listener_ = nullptr;
    }

    if (tcp_listener_ != nullptr)
    {
        tcp_accept(tcp_listener_, nullptr);
        tcp_arg(tcp_listener_, nullptr);
        const auto close_err = tcp_close(tcp_listener_);
        if (close_err != ERR_OK)
        {
            tcp_abort(tcp_listener_);
        }
        tcp_listener_ = nullptr;
    }

    if (stack_ready_)
    {
        netif_remove(&netif_);
        stack_ready_ = false;
    }
}

boost::asio::awaitable<void> tun_client::read_loop()
{
    std::vector<uint8_t> buffer(65535);
    boost::system::error_code ec;

    while (!stopping_.load(std::memory_order_relaxed))
    {
#ifdef _WIN32
        co_await tun_wait_handle_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
#else
        co_await tun_stream_.async_wait(boost::asio::posix::descriptor_base::wait_read, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
#endif
        if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor)
        {
            break;
        }
        if (ec)
        {
            LOG_ERROR("event {} device {} index {} tun read wait failed {}", log_event::kConnInit, device_.name(), device_.index(), ec.message());
            break;
        }

        while (!stopping_.load(std::memory_order_relaxed))
        {
            const auto bytes_read = device_.read_packet(buffer.data(), buffer.size(), ec);
            if (ec)
            {
                if (ec == boost::system::errc::make_error_code(boost::system::errc::resource_unavailable_try_again) ||
                    ec == boost::asio::error::would_block || ec == boost::asio::error::try_again)
                {
                    ec.clear();
                    break;
                }
                if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor)
                {
                    co_return;
                }
                LOG_WARN(
                    "event {} device {} index {} read tun packet failed {}", log_event::kConnInit, device_.name(), device_.index(), ec.message());
                break;
            }
            if (bytes_read <= 0)
            {
                break;
            }

            auto* packet = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(bytes_read), PBUF_RAM);
            if (packet == nullptr)
            {
                LOG_WARN("event {} device {} index {} alloc lwip pbuf failed size {}", log_event::kRelay, device_.name(), device_.index(), bytes_read);
                continue;
            }

            if (pbuf_take(packet, buffer.data(), static_cast<u16_t>(bytes_read)) != ERR_OK)
            {
                pbuf_free(packet);
                continue;
            }

            if (netif_.input(packet, &netif_) != ERR_OK)
            {
                pbuf_free(packet);
            }
        }
    }
}

boost::asio::awaitable<void> tun_client::timer_loop()
{
    boost::asio::steady_timer timer(owner_worker_.io_context);
    uint32_t tick = 0;

    while (!stopping_.load(std::memory_order_relaxed))
    {
        timer.expires_after(std::chrono::milliseconds(TCP_TMR_INTERVAL));
        const auto [wait_ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }

        ++tick;
        tcp_tmr();
        if ((tick & 0x3U) == 0)
        {
#if IP_REASSEMBLY
            ip_reass_tmr();
#endif
#if LWIP_IPV6
            nd6_tmr();
#if LWIP_IPV6_REASS
            ip6_reass_tmr();
#endif
#endif
        }
    }
}

err_t tun_client::write_packet_to_tun(const pbuf* packet)
{
    auto payload = tun::pbuf_to_vector(packet);
    if (payload.empty())
    {
        return ERR_OK;
    }

    boost::system::error_code ec;
    const auto written = device_.write_packet(payload.data(), payload.size(), ec);
    if (ec)
    {
        if (ec == boost::system::errc::make_error_code(boost::system::errc::resource_unavailable_try_again))
        {
            return ERR_WOULDBLOCK;
        }
        LOG_WARN("event {} device {} index {} write tun packet failed {}", log_event::kRelay, device_.name(), device_.index(), ec.message());
        return ERR_IF;
    }
    if (written != static_cast<std::ptrdiff_t>(payload.size()))
    {
        return ERR_IF;
    }
    return ERR_OK;
}

void tun_client::on_tcp_accept(tcp_pcb* pcb)
{
    const auto conn_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    std::weak_ptr<tun_client> weak_self = shared_from_this();
    auto session = std::make_shared<tun_tcp_session>(owner_worker_.io_context.get_executor(),
                                                     router_,
                                                     pcb,
                                                     conn_id,
                                                     cfg_,
                                                     [weak_self, conn_id]()
                                                     {
                                                         if (auto self = weak_self.lock())
                                                         {
                                                             self->erase_tcp_session(conn_id);
                                                         }
                                                     });
    tcp_sessions_.insert_or_assign(conn_id, session);
    owner_worker_.group.spawn([session]() { return session->start(); });
}

void tun_client::on_udp_accept(udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, const u16_t port)
{
    if (pcb == nullptr || packet == nullptr || addr == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        if (pcb != nullptr)
        {
            udp_remove(pcb);
        }
        return;
    }

    const auto client_endpoint = tun::lwip_to_udp_endpoint(pcb->remote_ip, pcb->remote_port);
    const auto target_endpoint = tun::lwip_to_udp_endpoint(*addr, port);
    if (client_endpoint.port() == 0 || target_endpoint.port() == 0)
    {
        pbuf_free(packet);
        udp_remove(pcb);
        return;
    }

    const auto conn_id = next_session_id_.fetch_add(1, std::memory_order_relaxed);
    std::weak_ptr<tun_client> weak_self = shared_from_this();
    auto session = std::make_shared<tun_udp_session>(owner_worker_,
                                                     router_,
                                                     pcb,
                                                     client_endpoint,
                                                     target_endpoint,
                                                     conn_id,
                                                     cfg_,
                                                     [weak_self, conn_id]()
                                                     {
                                                         if (auto self = weak_self.lock())
                                                         {
                                                             self->erase_udp_session(conn_id);
                                                         }
                                                     });
    udp_sessions_.insert_or_assign(conn_id, session);

    // For pretend UDP, lwIP re-dispatches the first packet to the newly created
    // connected pcb after this callback returns. The session consumes it there.
    owner_worker_.group.spawn([session]() { return session->start(); });
}

void tun_client::erase_tcp_session(const uint32_t conn_id) { tcp_sessions_.erase(conn_id); }

void tun_client::erase_udp_session(const uint32_t conn_id) { udp_sessions_.erase(conn_id); }

err_t tun_client::netif_init_handler(netif* netif)
{
    netif->output = &tun_client::netif_output_v4_handler;
    netif->output_ip6 = &tun_client::netif_output_v6_handler;
    return ERR_OK;
}

err_t tun_client::netif_output_v4_handler(netif* netif, pbuf* packet, const ip4_addr_t* ipaddr)
{
    (void)ipaddr;
    auto* self = static_cast<tun_client*>(netif->state);
    if (self != nullptr)
    {
        return self->write_packet_to_tun(packet);
    }
    return ERR_IF;
}

err_t tun_client::netif_output_v6_handler(netif* netif, pbuf* packet, const ip6_addr_t* ipaddr)
{
    (void)ipaddr;
    auto* self = static_cast<tun_client*>(netif->state);
    if (self != nullptr)
    {
        return self->write_packet_to_tun(packet);
    }
    return ERR_IF;
}

err_t tun_client::tcp_accept_handler(void* arg, tcp_pcb* pcb, const err_t err)
{
    auto* self = static_cast<tun_client*>(arg);
    if (self == nullptr || err != ERR_OK || pcb == nullptr || self->stopping_.load(std::memory_order_relaxed))
    {
        return ERR_RST;
    }

    self->on_tcp_accept(pcb);
    return ERR_OK;
}

void tun_client::udp_recv_handler(void* arg, udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, const u16_t port)
{
    auto* self = static_cast<tun_client*>(arg);
    if (self == nullptr || self->stopping_.load(std::memory_order_relaxed))
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        if (pcb != nullptr)
        {
            udp_remove(pcb);
        }
        return;
    }

    self->on_udp_accept(pcb, packet, addr, port);
}

}    // namespace mux
