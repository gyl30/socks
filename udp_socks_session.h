#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "protocol.h"
#include "router.h"
#include "mux_tunnel.h"
#include "task_group.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;
class client_tunnel_pool;
namespace detail
{
std::vector<std::uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, std::uint16_t udp_bind_port);
}

class udp_socks_session : public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(boost::asio::ip::tcp::socket socket,
                      boost::asio::io_context& io_context,
                      std::shared_ptr<client_tunnel_pool> tunnel_pool,
                      std::shared_ptr<router> router,
                      std::uint32_t sid,
                      const config& cfg,
                      task_group& group,
                      std::shared_ptr<void> active_connection_guard = nullptr);

    void start(const std::string& host, std::uint16_t port);
    void stop();

   private:
    boost::asio::awaitable<void> run(const std::string& host, std::uint16_t port);

   private:
    void apply_request_peer_constraint(const std::string& host, std::uint16_t port);
    [[nodiscard]] boost::asio::awaitable<route_type> decide_udp_route(const socks_udp_header& header) const;
    [[nodiscard]] boost::asio::awaitable<bool> ensure_proxy_stream(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_target_endpoint(const std::string& host,
                                                                                                  std::uint16_t port,
                                                                                                  boost::system::error_code& ec);
    boost::asio::awaitable<void> udp_socket_loop();
    boost::asio::awaitable<void> direct_udp_socket_loop(boost::asio::ip::udp::socket& direct_socket);
    void start_direct_udp_socket_loops();
    boost::asio::awaitable<void> forward_direct_packet(const socks_udp_header& header,
                                                       const std::uint8_t* payload,
                                                       std::size_t payload_len,
                                                       boost::system::error_code& ec);
    boost::asio::awaitable<void> forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                const std::uint8_t* payload,
                                                                std::size_t payload_len,
                                                                boost::system::error_code& ec);
    void open_direct_udp_socket(boost::asio::ip::udp::socket& direct_socket,
                                const boost::asio::ip::udp& protocol,
                                const char* family,
                                boost::system::error_code& ec);
    [[nodiscard]] boost::asio::ip::udp::socket* select_direct_udp_socket(const boost::asio::ip::udp::endpoint& target);
    void clear_proxy_stream_if_current(const std::shared_ptr<mux_stream>& stream);
    boost::asio::awaitable<void> wait_and_stream_to_udp_sock();
    boost::asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream);
    boost::asio::awaitable<void> keep_tcp_alive();
    boost::asio::awaitable<void> idle_watchdog();
    void close_impl();

   private:
    using proxy_stream_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::shared_ptr<mux_stream>)>;

    connection_context ctx_;
    const config& cfg_;
    task_group& group_;
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer timer_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::socket direct_udp_socket_v4_;
    boost::asio::ip::udp::socket direct_udp_socket_v6_;
    std::shared_ptr<router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<mux_tunnel_impl> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    std::atomic<std::uint8_t> stream_close_command_{0};
    std::uint64_t last_activity_time_ms_{0};
    bool stopped_ = false;
    bool proxy_stream_started_ = false;
    bool has_client_addr_ = false;
    bool direct_udp_v4_running_ = false;
    bool direct_udp_v6_running_ = false;
    boost::asio::ip::udp::endpoint client_addr_;
    std::unordered_map<std::string, boost::asio::ip::udp::endpoint> resolved_targets_;
    std::unordered_map<std::string, std::uint64_t> resolved_expires_;
    std::deque<std::pair<std::string, std::uint64_t>> resolved_order_;
    std::unordered_set<std::string> direct_peers_;
    std::unordered_map<std::string, std::uint64_t> direct_peers_expires_;
    std::deque<std::pair<std::string, std::uint64_t>> direct_peers_order_;
    std::shared_ptr<void> active_connection_guard_;
    proxy_stream_channel_type proxy_stream_channel_;
};

}    // namespace mux

#endif
