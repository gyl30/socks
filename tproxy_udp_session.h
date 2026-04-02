#ifndef TPROXY_UDP_SESSION_H
#define TPROXY_UDP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <functional>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "lru_cache.h"
#include "client_tunnel_pool.h"
namespace mux
{

enum class udp_enqueue_result : uint8_t
{
    kEnqueued,
    kDroppedOverflow,
    kClosed,
};

class tproxy_udp_session : public std::enable_shared_from_this<tproxy_udp_session>
{
   public:
    tproxy_udp_session(io_worker& worker,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       const boost::asio::ip::udp::endpoint& client_endpoint,
                       const boost::asio::ip::udp::endpoint& target_endpoint,
                       route_type route,
                       uint32_t conn_id,
                       const config& cfg,
                       std::function<void()> on_close);

    void start();
    void stop();
    [[nodiscard]] boost::asio::awaitable<udp_enqueue_result> enqueue_packet(std::vector<uint8_t> payload);

   private:
    using packet_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<uint8_t>)>;

    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<bool> open_direct_socket();
    [[nodiscard]] boost::asio::awaitable<bool> open_proxy_stream();
    [[nodiscard]] boost::asio::awaitable<bool> run_direct_mode();
    [[nodiscard]] boost::asio::awaitable<bool> run_proxy_mode();
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<mux_connection>> wait_for_proxy_tunnel(boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::awaitable<void> packets_to_direct();
    [[nodiscard]] boost::asio::awaitable<void> direct_to_client();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_proxy();
    [[nodiscard]] boost::asio::awaitable<void> proxy_to_client();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<bool> send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                              const uint8_t* payload,
                                                              std::size_t payload_len);
    [[nodiscard]] std::shared_ptr<boost::asio::ip::udp::socket> get_or_create_reply_socket(const boost::asio::ip::udp::endpoint& source,
                                                                                           boost::system::error_code& ec);
    [[nodiscard]] static std::string endpoint_key(const boost::asio::ip::udp::endpoint& endpoint);
    void notify_closed();
    void close_impl();

   private:
    uint32_t conn_id_ = 0;
    const config& cfg_;
    io_worker& worker_;
    std::shared_ptr<void> active_guard_;
    route_type route_;
    std::atomic<bool> stopped_{false};
    uint64_t last_activity_time_ms_ = 0;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket upstream_socket_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<mux_connection> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    std::atomic<uint8_t> stream_close_command_{0};
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::ip::udp::endpoint client_endpoint_;
    boost::asio::ip::udp::endpoint target_endpoint_;
    std::function<void()> on_close_;
    packet_channel_type packet_channel_;
    lru_cache<std::string, std::shared_ptr<boost::asio::ip::udp::socket>> reply_sockets_;
};

}    // namespace mux

#endif
