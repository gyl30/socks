#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include "router.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_stream_interface.h"

namespace mux
{

class mux_stream;

class udp_socks_session : public mux_stream_interface, public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(asio::ip::tcp::socket socket,
                      asio::io_context& io_context,
                      std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                      std::uint32_t sid,
                      const config::timeout_t& timeout_cfg);

    void start(const std::string& host, std::uint16_t port);

   private:
    asio::awaitable<void> run(const std::string& host, std::uint16_t port);

   public:
    void on_data(std::vector<std::uint8_t> data) override;
    void on_close() override;
    void on_reset() override;

   private:
    asio::awaitable<void> udp_sock_to_stream(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep);

    asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep);

    asio::awaitable<void> keep_tcp_alive();
    asio::awaitable<void> idle_watchdog();
    void close_impl();

   private:
    connection_context ctx_;
    asio::io_context& io_context_;
    asio::steady_timer timer_;
    asio::steady_timer idle_timer_;
    asio::ip::tcp::socket socket_;
    asio::ip::udp::socket udp_socket_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::atomic<bool> closed_{false};
    asio::ip::udp::endpoint client_ep_;
    bool has_client_ep_ = false;
    config::timeout_t timeout_config_;
};

}    // namespace mux

#endif
