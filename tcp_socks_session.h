#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>

#include "router.h"
#include "protocol.h"
#include "upstream.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class tcp_socks_session : public std::enable_shared_from_this<tcp_socks_session>
{
   public:
    tcp_socks_session(asio::ip::tcp::socket socket,
                      std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                      std::shared_ptr<router> router,
                      const std::uint32_t sid,
                      const config::timeout_t& timeout_cfg);

    void start(const std::string& host, const std::uint16_t port);

   private:
    [[nodiscard]] asio::awaitable<void> run(const std::string& host, const std::uint16_t port);

    [[nodiscard]] asio::awaitable<void> reply_error(const std::uint8_t code);

    [[nodiscard]] asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);

    [[nodiscard]] asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] asio::awaitable<void> idle_watchdog(std::shared_ptr<upstream> backend);
    [[nodiscard]] asio::awaitable<void> close_backend_once(const std::shared_ptr<upstream>& backend);

   private:
    connection_context ctx_;
    asio::ip::tcp::socket socket_;
    asio::steady_timer idle_timer_;
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    config::timeout_t timeout_config_;
};

}    // namespace mux

#endif
