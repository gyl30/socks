#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "protocol.h"
#include "lru_cache.h"
#include "net_utils.h"
#include "proxy_udp_upstream.h"
namespace mux
{

namespace detail
{
std::vector<uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, uint16_t udp_bind_port);
}

class udp_socks_session : public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(boost::asio::ip::tcp::socket socket,
                      io_worker& worker,
                      std::shared_ptr<router> router,
                      uint32_t sid,
                      uint64_t trace_id,
                      const config& cfg,
                      std::shared_ptr<void> active_connection_guard = nullptr);

    void start(const std::string& host, uint16_t port);

   private:
    boost::asio::awaitable<void> run(const std::string& host, uint16_t port);

   private:
    void apply_request_peer_constraint(const std::string& host, uint16_t port) const;
    [[nodiscard]] std::string current_client_host() const;
    [[nodiscard]] uint16_t current_client_port() const;
    [[nodiscard]] boost::asio::awaitable<route_type> decide_udp_route(const socks_udp_header& header) const;
    [[nodiscard]] boost::asio::awaitable<bool> ensure_proxy_upstream(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                 uint16_t port,
                                                                                                 boost::system::error_code& ec);
    boost::asio::awaitable<void> udp_socket_loop();
    boost::asio::awaitable<void> direct_udp_socket_loop(boost::asio::ip::udp::socket& direct_socket);
    void start_direct_udp_socket_loops();
    boost::asio::awaitable<void> forward_direct_packet(const socks_udp_header& header,
                                                       const uint8_t* payload,
                                                       std::size_t payload_len,
                                                       boost::system::error_code& ec);
    boost::asio::awaitable<void> forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                const uint8_t* payload,
                                                                std::size_t payload_len,
                                                                boost::system::error_code& ec);
    void open_direct_udp_socket(boost::asio::ip::udp::socket& direct_socket,
                                const boost::asio::ip::udp& protocol,
                                const char* family,
                                boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::ip::udp::socket* select_direct_udp_socket(const boost::asio::ip::udp::endpoint& target);
    void clear_proxy_upstream_if_current(const std::shared_ptr<proxy_udp_upstream>& upstream);
    boost::asio::awaitable<void> wait_and_proxy_to_udp_sock();
    boost::asio::awaitable<void> proxy_to_udp_sock(std::shared_ptr<proxy_udp_upstream> upstream);
    boost::asio::awaitable<void> keep_tcp_alive();
    boost::asio::awaitable<void> idle_watchdog();
    void close_impl();

   private:
    struct endpoint_cache_entry
    {
        boost::asio::ip::udp::endpoint endpoint;
        uint64_t expires_at = 0;
        boost::system::error_code last_error;
        bool negative = false;
    };

    struct peer_cache_entry
    {
        uint64_t expires_at = 0;
    };

    using proxy_upstream_channel_type =
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::shared_ptr<proxy_udp_upstream>)>;

    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    const config& cfg_;
    io_worker& worker_;
    boost::asio::steady_timer timer_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::socket direct_udp_socket_v4_;
    boost::asio::ip::udp::socket direct_udp_socket_v6_;
    std::shared_ptr<router> router_;
    std::shared_ptr<proxy_udp_upstream> proxy_upstream_;
    uint64_t last_activity_time_ms_{0};
    bool stopped_ = false;
    bool proxy_upstream_started_ = false;
    bool has_client_ip_ = false;
    bool has_client_addr_ = false;
    bool has_last_target_ = false;
    bool direct_udp_v4_running_ = false;
    bool direct_udp_v6_running_ = false;
    std::string tcp_peer_host_ = "unknown";
    uint16_t tcp_peer_port_ = 0;
    std::string udp_bind_host_ = "unknown";
    uint16_t udp_bind_port_ = 0;
    boost::asio::ip::address client_ip_;
    boost::asio::ip::udp::endpoint client_addr_;
    std::string last_target_addr_;
    uint16_t last_target_port_ = 0;
    lru_cache<std::string, endpoint_cache_entry> resolved_targets_;
    lru_cache<boost::asio::ip::udp::endpoint, peer_cache_entry, net::udp_endpoint_hash, net::udp_endpoint_equal> direct_peers_;
    std::shared_ptr<void> active_connection_guard_;
    proxy_upstream_channel_type proxy_upstream_channel_;
};

}    // namespace mux

#endif
