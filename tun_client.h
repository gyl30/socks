#ifndef TUN_CLIENT_H
#define TUN_CLIENT_H

#include <atomic>
#include <memory>
#include <cstdint>
#include <unordered_map>

#include <boost/asio/awaitable.hpp>

#ifdef _WIN32
#include <boost/asio/windows/object_handle.hpp>
#else
#include <boost/asio/posix/stream_descriptor.hpp>
#endif

#include "router.h"
#include "config.h"
#include "tun_lwip.h"
#include "tun_device.h"
#include "context_pool.h"
#include "tun_tcp_session.h"
#include "tun_udp_session.h"
namespace mux
{

class tun_client : public std::enable_shared_from_this<tun_client>
{
   public:
    tun_client(io_context_pool& pool, const config& cfg);

    void start();
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> read_loop();
    [[nodiscard]] boost::asio::awaitable<void> timer_loop();
    [[nodiscard]] bool init_stack();
    void shutdown_stack();
    [[nodiscard]] err_t write_packet_to_tun(const pbuf* packet);
    void on_tcp_accept(tcp_pcb* pcb);
    void on_udp_accept(udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, u16_t port);
    void erase_tcp_session(uint32_t conn_id);
    void erase_udp_session(uint32_t conn_id);

    static err_t netif_init_handler(netif* netif);
    static err_t netif_output_v4_handler(netif* netif, pbuf* packet, const ip4_addr_t* ipaddr);
    static err_t netif_output_v6_handler(netif* netif, pbuf* packet, const ip6_addr_t* ipaddr);
    static err_t tcp_accept_handler(void* arg, tcp_pcb* pcb, err_t err);
    static void udp_recv_handler(void* arg, udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, u16_t port);

   private:
    config cfg_;
    io_worker& owner_worker_;
    std::shared_ptr<router> router_;
    tun_device device_;
#ifdef _WIN32
    boost::asio::windows::object_handle tun_wait_handle_{owner_worker_.io_context};
#else
    boost::asio::posix::stream_descriptor tun_stream_{owner_worker_.io_context};
#endif
    netif netif_{};
    tcp_pcb* tcp_listener_ = nullptr;
    udp_pcb* udp_listener_ = nullptr;
    std::unordered_map<uint32_t, std::shared_ptr<tun_tcp_session>> tcp_sessions_;
    std::unordered_map<uint32_t, std::shared_ptr<tun_udp_session>> udp_sessions_;
    std::atomic<uint32_t> next_session_id_{1};
    std::atomic<bool> stopping_{false};
    bool stack_ready_ = false;
};

}    // namespace mux

#endif
