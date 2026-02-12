#ifndef TPROXY_TCP_SESSION_H
#define TPROXY_TCP_SESSION_H

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <cstdint>
#include <system_error>

#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>
#include <asio/steady_timer.hpp>

#include "config.h"
#include "router.h"
#include "upstream.h"
#include "log_context.h"
#include "client_tunnel_pool.h"

namespace mux
{

class tproxy_tcp_session : public std::enable_shared_from_this<tproxy_tcp_session>
{
   public:
    tproxy_tcp_session(asio::ip::tcp::socket socket,
                       asio::io_context& io_context,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       std::shared_ptr<router> router,
                       std::uint32_t sid,
                       const config& cfg,
                       const asio::ip::tcp::endpoint& dst_ep);

    void start();

   private:
    [[nodiscard]] asio::awaitable<void> run();
    [[nodiscard]] asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> select_backend(const std::string& host);
    [[nodiscard]] asio::awaitable<bool> connect_backend(const std::shared_ptr<upstream>& backend,
                                                        const std::string& host,
                                                        std::uint16_t port,
                                                        route_type route);

    [[nodiscard]] asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);
    [[nodiscard]] bool should_stop_client_read(const std::error_code& ec, std::uint32_t n) const;
    [[nodiscard]] asio::awaitable<bool> write_client_chunk_to_backend(const std::shared_ptr<upstream>& backend,
                                                                      const std::vector<std::uint8_t>& buf,
                                                                      std::uint32_t n);

    [[nodiscard]] asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] bool should_stop_backend_read(const std::error_code& ec, std::uint32_t n) const;
    [[nodiscard]] asio::awaitable<bool> write_backend_chunk_to_client(const std::vector<std::uint8_t>& buf, std::uint32_t n);
    void shutdown_client_send();

    [[nodiscard]] asio::awaitable<void> idle_watchdog(std::shared_ptr<upstream> backend);
    [[nodiscard]] asio::awaitable<void> close_backend_once(const std::shared_ptr<upstream>& backend);

    void start_idle_watchdog(const std::shared_ptr<upstream>& backend);
    void close_client_socket();

   private:
    connection_context ctx_;
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    asio::steady_timer idle_timer_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    asio::ip::tcp::endpoint dst_ep_;
    config::timeout_t timeout_config_;
    std::uint32_t mark_ = 0;
    std::atomic<std::uint64_t> last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
};

}    // namespace mux

#endif
