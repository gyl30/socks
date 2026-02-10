#ifndef TPROXY_TCP_SESSION_H
#define TPROXY_TCP_SESSION_H

#include <memory>
#include <string>
#include <cstdint>
#include <chrono>

#include <asio/ip/tcp.hpp>
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
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       std::shared_ptr<router> router,
                       std::uint32_t sid,
                       const config& cfg,
                       const asio::ip::tcp::endpoint& dst_ep);

    void start();

   private:
    [[nodiscard]] asio::awaitable<void> run();

    [[nodiscard]] asio::awaitable<void> client_to_upstream(upstream* backend);

    [[nodiscard]] asio::awaitable<void> upstream_to_client(upstream* backend);

    [[nodiscard]] asio::awaitable<void> idle_watchdog(upstream* backend);

   private:
    connection_context ctx_;
    asio::ip::tcp::socket socket_;
    asio::steady_timer idle_timer_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    asio::ip::tcp::endpoint dst_ep_;
    config::timeout_t timeout_config_;
    std::uint32_t mark_ = 0;
    std::chrono::steady_clock::time_point last_activity_time_;
};

}    // namespace mux

#endif
