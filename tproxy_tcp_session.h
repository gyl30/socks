#ifndef TPROXY_TCP_SESSION_H
#define TPROXY_TCP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include "router.h"
#include "upstream.h"
namespace mux
{

class tproxy_tcp_session : public std::enable_shared_from_this<tproxy_tcp_session>
{
   public:
    tproxy_tcp_session(boost::asio::ip::tcp::socket socket,
                       std::shared_ptr<router> router,
                       uint32_t sid,
                       const config& cfg);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] bool resolve_target_endpoint(boost::asio::ip::tcp::endpoint& target_ep);
    [[nodiscard]] bool detect_routing_loop(const boost::asio::ip::tcp::endpoint& target_ep,
                                           const boost::system::error_code& local_ec,
                                           const boost::asio::ip::tcp::endpoint& local_ep) const;
    void update_session_endpoints(const boost::asio::ip::tcp::endpoint& target_ep,
                                  const boost::system::error_code& local_ec,
                                  const boost::asio::ip::tcp::endpoint& local_ep,
                                  const boost::system::error_code& peer_ec,
                                  const boost::asio::ip::tcp::endpoint& peer_ep);
    void log_redirected_connection() const;
    [[nodiscard]] boost::asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> select_backend(const boost::asio::ip::address& addr);
    [[nodiscard]] boost::asio::awaitable<bool> connect_backend(route_type route, const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> relay_backend(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void close_client_socket();
    void log_close_summary() const;

   private:
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string client_addr_;
    uint16_t client_port_ = 0;
    std::string local_addr_;
    uint16_t local_port_ = 0;
    std::string target_addr_;
    uint16_t target_port_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<router> router_;
    const config& cfg_;
    uint64_t last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
};

}    // namespace mux

#endif
