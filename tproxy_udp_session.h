#ifndef TPROXY_UDP_SESSION_H
#define TPROXY_UDP_SESSION_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "task_group.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class mux_stream;
class client_tunnel_pool;

class tproxy_udp_session : public std::enable_shared_from_this<tproxy_udp_session>
{
   public:
    tproxy_udp_session(boost::asio::io_context& io_context,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       boost::asio::ip::udp::endpoint client_endpoint,
                       boost::asio::ip::udp::endpoint target_endpoint,
                       route_type route,
                       connection_context ctx,
                       const config& cfg,
                       task_group& group,
                       std::function<void()> on_close);

    void start();
    void stop();
    [[nodiscard]] boost::asio::awaitable<bool> enqueue_packet(std::vector<std::uint8_t> payload);

   private:
    using packet_channel_type = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<bool> open_direct_socket();
    [[nodiscard]] boost::asio::awaitable<bool> open_proxy_stream();
    [[nodiscard]] boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl>> wait_for_proxy_tunnel(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> packets_to_direct();
    [[nodiscard]] boost::asio::awaitable<void> direct_to_client();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_proxy();
    [[nodiscard]] boost::asio::awaitable<void> proxy_to_client();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    [[nodiscard]] boost::asio::awaitable<void> send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                              const std::uint8_t* payload,
                                                              std::size_t payload_len);
    [[nodiscard]] std::shared_ptr<boost::asio::ip::udp::socket> get_or_create_reply_socket(const boost::asio::ip::udp::endpoint& source,
                                                                                            boost::system::error_code& ec);
    [[nodiscard]] static std::string endpoint_key(const boost::asio::ip::udp::endpoint& endpoint);
    void close_impl();

   private:
    connection_context ctx_;
    const config& cfg_;
    task_group& group_;
    route_type route_;
    bool stopped_ = false;
    std::uint64_t last_activity_time_ms_ = 0;
    boost::asio::io_context& io_context_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::ip::udp::socket upstream_socket_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<mux_tunnel_impl> tunnel_;
    std::shared_ptr<mux_stream> stream_;
    std::atomic<std::uint8_t> stream_close_command_{0};
    boost::asio::ip::udp::endpoint client_endpoint_;
    boost::asio::ip::udp::endpoint target_endpoint_;
    std::function<void()> on_close_;
    packet_channel_type packet_channel_;
    std::unordered_map<std::string, std::shared_ptr<boost::asio::ip::udp::socket>> reply_sockets_;
};

}    // namespace mux

#endif
