#ifndef SOCKS_TCP_CONNECT_SESSION_H
#define SOCKS_TCP_CONNECT_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "constants.h"
#include "request_context.h"
#include "session_result.h"
#include "tcp_outbound_stream.h"

namespace relay
{

class socks_tcp_session : public std::enable_shared_from_this<socks_tcp_session>
{
   public:
    socks_tcp_session(boost::asio::ip::tcp::socket socket,
                              std::shared_ptr<router> router,
                              uint32_t sid,
                              uint64_t trace_id,
                              std::string inbound_tag,
                              const config& cfg);

    [[nodiscard]] boost::asio::awaitable<void> start(const std::string& host, uint16_t port);
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const std::string& host, uint16_t port);
    [[nodiscard]] request_context make_request_context(const std::string& host, uint16_t port) const;
    void apply_route_decision(const std::string& host, uint16_t port, const route_decision& decision);
    [[nodiscard]] boost::asio::awaitable<void> relay_backend(const std::shared_ptr<tcp_outbound_stream>& backend);
    [[nodiscard]] boost::asio::awaitable<void> finish_connected_session(const route_decision& decision,
                                                                         const std::shared_ptr<tcp_outbound_stream>& backend);

    [[nodiscard]] boost::asio::awaitable<void> reply_error(uint8_t code);
    [[nodiscard]] boost::asio::awaitable<tcp_outbound_connect_result> connect_backend(const std::shared_ptr<tcp_outbound_stream>& backend,
                                                                                  const std::string& host,
                                                                                  uint16_t port,
                                                                                  route_type route,
                                                                                  const std::string& outbound_type);
    [[nodiscard]] boost::asio::awaitable<bool> reply_success(const tcp_outbound_connect_result& connect_result);

    void close_client_socket();

   private:
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string inbound_tag_;
    std::string inbound_type_ = "socks";
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
    stream_relay_result::close_reason close_reason_ = stream_relay_result::close_reason::kUnknown;
};

}    // namespace relay

#endif
