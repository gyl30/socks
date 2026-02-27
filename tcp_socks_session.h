#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <atomic>
#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include "config.h"
#include "router.h"
#include "upstream.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class tcp_socks_session : public std::enable_shared_from_this<tcp_socks_session>
{
   public:
    tcp_socks_session(boost::asio::ip::tcp::socket socket,
                      boost::asio::io_context& io_context,
                      std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                      std::shared_ptr<router> router,
                      std::uint32_t sid,
                      const config::timeout_t& timeout_cfg,
                      std::shared_ptr<void> active_connection_guard = nullptr,
                      std::shared_ptr<boost::asio::cancellation_signal> stop_signal = nullptr);

    void start(const std::string& host, std::uint16_t port);
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run(const std::string& host, std::uint16_t port);

    [[nodiscard]] boost::asio::awaitable<void> reply_error(std::uint8_t code);
    [[nodiscard]] boost::asio::awaitable<bool> connect_backend(const std::shared_ptr<upstream>& backend,
                                                               const std::string& host,
                                                               std::uint16_t port,
                                                               route_type route);
    [[nodiscard]] boost::asio::awaitable<bool> reply_success(const std::shared_ptr<upstream>& backend);

    [[nodiscard]] static boost::asio::awaitable<void> run_detached(std::shared_ptr<tcp_socks_session> self, std::string host, std::uint16_t port);

    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);

    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog(std::shared_ptr<upstream> backend);
    [[nodiscard]] static boost::asio::awaitable<void> idle_watchdog_detached(std::shared_ptr<tcp_socks_session> self,
                                                                             std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> close_backend_once(const std::shared_ptr<upstream>& backend);
    [[nodiscard]] std::shared_ptr<upstream> create_backend(route_type route) const;

    void start_idle_watchdog(const std::shared_ptr<upstream>& backend);
    void close_client_socket();

   private:
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    std::shared_ptr<void> active_connection_guard_;
    std::shared_ptr<boost::asio::cancellation_signal> stop_signal_;
    config::timeout_t timeout_config_;
};

}    // namespace mux

#endif
