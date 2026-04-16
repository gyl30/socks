#ifndef TUN_UDP_SESSION_H
#define TUN_UDP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "context_pool.h"
#include "request_context.h"
#include "router.h"
#include "tun_lwip.h"
#include "udp_proxy_outbound.h"

namespace relay
{

class tun_udp_session : public std::enable_shared_from_this<tun_udp_session>
{
   public:
    using packet_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<uint8_t>)>;

    tun_udp_session(io_worker& worker,
                    std::shared_ptr<router> router,
                    udp_pcb* pcb,
                    boost::asio::ip::udp::endpoint client_endpoint,
                    boost::asio::ip::udp::endpoint target_endpoint,
                    uint32_t conn_id,
                    std::string inbound_tag,
                    const config& cfg,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();
    void enqueue_packet(pbuf* packet);

    static void on_recv(void* arg, udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, u16_t port);

   private:
    [[nodiscard]] boost::asio::awaitable<bool> run();
    [[nodiscard]] request_context make_request_context() const;
    void apply_route_decision(const route_decision& decision);
    [[nodiscard]] boost::asio::awaitable<bool> run_selected_mode();
    [[nodiscard]] boost::asio::awaitable<bool> open_direct_socket();
    [[nodiscard]] boost::asio::awaitable<bool> open_proxy_outbound();
    [[nodiscard]] boost::asio::awaitable<bool> apply_open_proxy_outbound_result(
        const udp_proxy_outbound_connect_result& connect_result,
        std::chrono::steady_clock::time_point connect_start);
    void record_open_direct_socket_result(bool success,
                                          const boost::system::error_code& ec,
                                          std::chrono::steady_clock::time_point connect_start) const;
    [[nodiscard]] boost::asio::awaitable<bool> run_direct_mode();
    [[nodiscard]] boost::asio::awaitable<bool> run_proxy_mode();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_direct();
    [[nodiscard]] boost::asio::awaitable<void> direct_to_client();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_proxy();
    [[nodiscard]] boost::asio::awaitable<void> proxy_to_client();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<bool> send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                              const uint8_t* payload,
                                                              std::size_t payload_len);
    void close_impl();
    void notify_closed();

   private:
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string inbound_tag_;
    const config& cfg_;
    io_worker& worker_;
    std::shared_ptr<router> router_;
    udp_pcb* pcb_ = nullptr;
    route_type route_ = route_type::kBlock;
    std::string outbound_tag_;
    std::string outbound_type_;
    std::string match_type_;
    std::string match_value_;
    std::atomic<bool> stopped_{false};
    uint64_t last_activity_time_ms_ = 0;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket upstream_socket_;
    std::shared_ptr<udp_proxy_outbound> proxy_outbound_;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::ip::udp::endpoint client_endpoint_;
    boost::asio::ip::udp::endpoint target_endpoint_;
    std::function<void()> on_close_;
    packet_channel_type packet_channel_;
};

}    // namespace relay

#endif
