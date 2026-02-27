#ifndef TPROXY_CLIENT_H
#define TPROXY_CLIENT_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "tproxy_udp_sender.h"
#include "client_tunnel_pool.h"
#include "tproxy_udp_session.h"

namespace mux
{

struct tproxy_udp_dispatch_item
{
    boost::asio::ip::udp::endpoint src_ep;
    boost::asio::ip::udp::endpoint dst_ep;
    std::vector<std::uint8_t> payload;
};

using tproxy_udp_dispatch_channel = boost::asio::experimental::concurrent_channel<void(boost::system::error_code, tproxy_udp_dispatch_item)>;

class tproxy_client : public std::enable_shared_from_this<tproxy_client>
{
   public:
    using udp_session_map_t = std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>;

    tproxy_client(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::uint16_t tcp_port() const { return tcp_port_; }

    [[nodiscard]] std::uint16_t udp_port() const { return udp_port_; }
    [[nodiscard]] bool running() const
    {
        return started_.load(std::memory_order_acquire) && !stop_.load(std::memory_order_acquire) && tcp_acceptor_.is_open() && udp_socket_.is_open();
    }

    [[nodiscard]] static bool enqueue_udp_packet(tproxy_udp_dispatch_channel& dispatch_channel,
                                                 const boost::asio::ip::udp::endpoint& src_ep,
                                                 const boost::asio::ip::udp::endpoint& dst_ep,
                                                 const std::vector<std::uint8_t>& buffer,
                                                 std::size_t packet_len);

   private:
    boost::asio::awaitable<void> accept_tcp_loop();

    boost::asio::awaitable<void> udp_loop();

    boost::asio::awaitable<void> udp_cleanup_loop();

    boost::asio::awaitable<void> udp_dispatch_loop();

    [[nodiscard]] static std::string endpoint_key(const boost::asio::ip::udp::endpoint& ep);
    void rollback_start_state();
    [[nodiscard]] bool validate_start_prerequisites(std::shared_ptr<client_tunnel_pool>& tunnel_pool, std::shared_ptr<router>& router);
    [[nodiscard]] bool setup_runtime_sockets(std::string& tcp_listen_host, std::string& udp_listen_host);
    void start_runtime_loops(const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                             const std::string& tcp_listen_host,
                             const std::string& udp_listen_host);

   private:
    std::atomic<bool> stop_{false};
    std::atomic<bool> started_{false};
    std::atomic<std::uint64_t> lifecycle_epoch_{0};
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor tcp_acceptor_;
    boost::asio::ip::udp::socket udp_socket_;
    std::shared_ptr<boost::asio::cancellation_signal> stop_signal_ = std::make_shared<boost::asio::cancellation_signal>();
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    std::shared_ptr<tproxy_udp_sender> sender_;
    std::shared_ptr<udp_session_map_t> udp_sessions_ = std::make_shared<udp_session_map_t>();
    std::shared_ptr<tproxy_udp_dispatch_channel> udp_dispatch_channel_;
    std::atomic<bool> udp_dispatch_started_{false};
    config cfg_;
    config::tproxy_t tproxy_config_;
    std::uint16_t tcp_port_ = 0;
    std::uint16_t udp_port_ = 0;
    std::uint32_t udp_idle_timeout_sec_ = 0;
};

}    // namespace mux

#endif
