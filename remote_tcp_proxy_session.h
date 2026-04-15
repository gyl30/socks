#ifndef REMOTE_TCP_PROXY_SESSION_H
#define REMOTE_TCP_PROXY_SESSION_H

#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"

namespace relay
{

class remote_tcp_proxy_session : public std::enable_shared_from_this<remote_tcp_proxy_session>
{
   public:
    remote_tcp_proxy_session(boost::asio::io_context& io_context,
                             std::shared_ptr<proxy_reality_connection> connection,
                             uint32_t conn_id,
                             uint64_t trace_id,
                             const config& cfg);

    boost::asio::awaitable<void> start(const proxy::tcp_connect_request& request);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const proxy::tcp_connect_request& request);
    [[nodiscard]] boost::asio::awaitable<bool> resolve_target(boost::asio::ip::tcp::resolver& resolver,
                                                              boost::asio::ip::tcp::resolver::results_type& resolve_res);
    [[nodiscard]] boost::asio::awaitable<bool> connect_target(const boost::asio::ip::tcp::resolver::results_type& resolve_res);
    [[nodiscard]] boost::asio::awaitable<bool> send_connect_reply(uint8_t socks_rep);
    [[nodiscard]] boost::asio::awaitable<void> relay_target();
    [[nodiscard]] boost::asio::awaitable<void> client_to_target();
    [[nodiscard]] boost::asio::awaitable<void> target_to_client();
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void log_close_summary() const;

   private:
    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    const config& cfg_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::ip::tcp::socket target_socket_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<proxy_reality_connection> connection_;
    uint64_t last_activity_time_ms_{0};
};

}    // namespace relay

#endif
