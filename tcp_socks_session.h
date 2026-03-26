#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <atomic>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "upstream.h"
#include "connection_context.h"

namespace mux
{

class tcp_socks_session : public std::enable_shared_from_this<tcp_socks_session>
{
   public:
    tcp_socks_session(boost::asio::ip::tcp::socket socket,
                      std::shared_ptr<client_tunnel_pool> tunnel_pool,
                      std::shared_ptr<router> router,
                      std::uint32_t sid,
                      const config& cfg,
                      std::shared_ptr<void> active_connection_guard);

    [[nodiscard]] boost::asio::awaitable<void> start(const std::string& host, std::uint16_t port);
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const std::string& host, std::uint16_t port);

    [[nodiscard]] boost::asio::awaitable<void> reply_error(std::uint8_t code);
    [[nodiscard]] boost::asio::awaitable<upstream_connect_result> connect_backend(const std::shared_ptr<upstream>& backend,
                                                                                  const std::string& host,
                                                                                  std::uint16_t port,
                                                                                  route_type route);
    [[nodiscard]] boost::asio::awaitable<bool> reply_success(const upstream_connect_result& connect_result);

    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);

    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog(std::shared_ptr<upstream> backend);
    [[nodiscard]] std::shared_ptr<upstream> create_backend(route_type route);

    void close_client_socket();

   private:
    connection_context ctx_;
    const config& cfg_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::uint64_t last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
    std::shared_ptr<router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<void> active_connection_guard_;
};

}    // namespace mux

#endif
