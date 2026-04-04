#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "upstream.h"
#include "constants.h"
namespace mux
{

class tcp_socks_session : public std::enable_shared_from_this<tcp_socks_session>
{
   public:
    tcp_socks_session(boost::asio::ip::tcp::socket socket,
                      std::shared_ptr<client_tunnel_pool> tunnel_pool,
                      std::shared_ptr<router> router,
                      uint32_t sid,
                      uint64_t trace_id,
                      const config& cfg,
                      std::shared_ptr<void> active_connection_guard);

    [[nodiscard]] boost::asio::awaitable<void> start(const std::string& host, uint16_t port);
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const std::string& host, uint16_t port);

    [[nodiscard]] boost::asio::awaitable<void> reply_error(uint8_t code);
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect_backend(const std::shared_ptr<upstream>& backend,
                                                                                  const std::string& host,
                                                                                  uint16_t port,
                                                                                  route_type route);
    [[nodiscard]] boost::asio::awaitable<bool> reply_success(const upstream_connect_result& connect_result);

    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);

    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog(std::shared_ptr<upstream> backend);
    [[nodiscard]] std::shared_ptr<upstream> create_backend(route_type route);

    void close_client_socket();

   private:
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    std::string local_host_ = "unknown";
    uint16_t local_port_ = 0;
    std::string client_host_ = "unknown";
    uint16_t client_port_ = 0;
    const config& cfg_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    uint64_t last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
    std::string target_host_;
    uint16_t target_port_ = 0;
    std::string route_name_ = "unknown";
    std::shared_ptr<router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<void> active_connection_guard_;
};

}    // namespace mux

#endif
