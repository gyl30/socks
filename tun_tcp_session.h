#ifndef TUN_TCP_SESSION_H
#define TUN_TCP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>
#include <functional>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include "config.h"
#include "router.h"
#include "tun_lwip.h"
#include "upstream.h"
namespace mux
{

class client_tunnel_pool;

class tun_tcp_session : public std::enable_shared_from_this<tun_tcp_session>
{
   public:
    tun_tcp_session(const boost::asio::any_io_executor& executor,
                    std::shared_ptr<client_tunnel_pool> tunnel_pool,
                    std::shared_ptr<router> router,
                    tcp_pcb* pcb,
                    uint32_t sid,
                    const config& cfg,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> select_backend();
    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();

    [[nodiscard]] boost::asio::awaitable<void> wait_client_event();
    [[nodiscard]] boost::asio::awaitable<void> wait_send_event();
    void signal_client_event();
    void signal_send_event();
    void signal_all_events();

    void close_client_connection(bool abort_connection);
    void graceful_shutdown_to_client();
    void notify_closed();

    static err_t on_recv(void* arg, tcp_pcb* pcb, pbuf* packet, err_t err);
    static err_t on_sent(void* arg, tcp_pcb* pcb, u16_t len);
    static void on_err(void* arg, err_t err);
    static err_t on_poll(void* arg, tcp_pcb* pcb);

   private:
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    const config& cfg_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    tcp_pcb* pcb_ = nullptr;
    pbuf* queue_ = nullptr;
    std::function<void()> on_close_;
    std::shared_ptr<void> active_guard_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::steady_timer client_wait_timer_;
    boost::asio::steady_timer send_wait_timer_;
    std::string client_addr_;
    uint16_t client_port_ = 0;
    std::string target_addr_;
    uint16_t target_port_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    uint64_t last_activity_time_ms_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    bool peer_eof_ = false;
    bool stopped_ = false;
};

}    // namespace mux

#endif
