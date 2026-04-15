#ifndef REALITY_TCP_SESSION_H
#define REALITY_TCP_SESSION_H

#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "upstream.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"

namespace relay
{

class reality_tcp_session : public std::enable_shared_from_this<reality_tcp_session>
{
   public:
    reality_tcp_session(boost::asio::io_context& io_context,
                        std::shared_ptr<proxy_reality_connection> connection,
                        std::shared_ptr<router> router,
                        uint32_t conn_id,
                        uint64_t trace_id,
                        const config& cfg);

    boost::asio::awaitable<void> start(const proxy::tcp_connect_request& request);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const proxy::tcp_connect_request& request);
    [[nodiscard]] boost::asio::awaitable<bool> send_connect_reply(uint8_t socks_rep, const upstream_connect_result* connect_result);
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect_backend(const std::shared_ptr<upstream>& backend,
                                                                                  const std::string& host,
                                                                                  uint16_t port,
                                                                                  route_type route);
    [[nodiscard]] std::shared_ptr<upstream> create_backend(route_type route, const std::string& outbound_tag) const;
    [[nodiscard]] boost::asio::awaitable<void> relay_target(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog(const std::shared_ptr<upstream>& backend);
    void log_close_summary() const;

   private:
    uint32_t conn_id_ = 0;
    uint64_t trace_id_ = 0;
    const config& cfg_;
    std::string target_host_ = "unknown";
    uint16_t target_port_ = 0;
    std::string bind_host_ = "unknown";
    uint16_t bind_port_ = 0;
    std::string route_name_ = "unknown";
    uint64_t tx_bytes_ = 0;
    uint64_t rx_bytes_ = 0;
    std::chrono::steady_clock::time_point start_time_ = std::chrono::steady_clock::now();
    boost::asio::any_io_executor executor_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<proxy_reality_connection> connection_;
    std::shared_ptr<router> router_;
    uint64_t last_activity_time_ms_{0};
};

}    // namespace relay

#endif
