#ifndef SOCKS_UDP_ASSOCIATE_SESSION_H
#define SOCKS_UDP_ASSOCIATE_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "lru_cache.h"
#include "net_utils.h"
#include "protocol.h"
#include "request_context.h"
#include "router.h"
#include "session_result.h"
#include "run_loop_spawner.h"
#include "udp_proxy_outbound.h"

namespace relay
{

namespace detail
{
std::vector<uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, uint16_t udp_bind_port);
}

class socks_udp_session : public std::enable_shared_from_this<socks_udp_session>
{
   public:
    socks_udp_session(
        boost::asio::ip::tcp::socket socket,
        io_worker& worker,
        std::shared_ptr<router> router,
        uint32_t sid,
        uint64_t trace_id,
        std::string inbound_tag,
        const config& cfg);

    void start(const std::string& host, uint16_t port);

   private:
    boost::asio::awaitable<void> run(const std::string& host, uint16_t port);
    [[nodiscard]] boost::asio::awaitable<bool> prepare_udp_associate(const std::string& host, uint16_t port);
    [[nodiscard]] boost::asio::awaitable<bool> send_udp_associate_reply(const boost::asio::ip::address& local_addr, uint16_t udp_port);

   private:
    void apply_request_peer_constraint(const std::string& host, uint16_t port) const;
    [[nodiscard]] std::string current_client_host() const;
    [[nodiscard]] uint16_t current_client_port() const;
    [[nodiscard]] request_context make_proxy_outbound_request() const;
    [[nodiscard]] boost::asio::awaitable<route_decision> decide_udp_route(const socks_udp_header& header) const;
    [[nodiscard]] boost::asio::awaitable<bool> process_udp_packet(const socks_udp_header& header,
                                                                  const route_decision& decision,
                                                                  const uint8_t* payload,
                                                                  std::size_t payload_len);
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint_uncached(
        const std::string& key,
        const std::string& host,
        uint16_t port,
        uint64_t now_ms_value,
        boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> ensure_proxy_outbound(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> connect_proxy_outbound(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<bool> apply_proxy_outbound_connect_result(
        const udp_proxy_outbound_connect_result& connect_result,
        boost::system::error_code& ec);
    void record_proxy_outbound_connect_result(bool success, const boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::awaitable<bool> start_proxy_outbound_reader(boost::system::error_code& ec);
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
    boost::asio::awaitable<std::size_t> forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                       const uint8_t* payload,
                                                                       std::size_t payload_len,
                                                                       boost::system::error_code& ec);
    boost::asio::awaitable<std::size_t> forward_proxy_reply_to_client(const proxy::udp_datagram& datagram,
                                                                      boost::system::error_code& ec,
                                                                      bool& send_reply_failed);
    void open_direct_udp_socket(boost::asio::ip::udp::socket& direct_socket,
                                const boost::asio::ip::udp& protocol,
                                const char* family,
                                boost::system::error_code& ec) const;
    [[nodiscard]] boost::asio::ip::udp::socket* select_direct_udp_socket(const boost::asio::ip::udp::endpoint& target);
    void clear_proxy_outbound_if_current(const std::shared_ptr<udp_proxy_outbound>& upstream);
    boost::asio::awaitable<void> wait_and_proxy_to_udp_sock();
    boost::asio::awaitable<void> proxy_to_udp_sock(std::shared_ptr<udp_proxy_outbound> upstream);
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

    using proxy_outbound_channel_type =
        boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::shared_ptr<udp_proxy_outbound>)>;

    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string inbound_tag_;
    std::string inbound_type_ = "socks";
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
    std::shared_ptr<udp_proxy_outbound> proxy_outbound_;
    std::string proxy_outbound_tag_;
    uint64_t last_activity_time_ms_{0};
    bool stopped_ = false;
    bool proxy_outbound_started_ = false;
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
    proxy_outbound_channel_type proxy_outbound_channel_;
    udp_close_reason close_reason_ = udp_close_reason::kUnknown;
};

}    // namespace relay

#endif
