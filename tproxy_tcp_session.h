#ifndef TPROXY_TCP_SESSION_H
#define TPROXY_TCP_SESSION_H

#include <atomic>
#include <memory>
#include <cstdint>
#include <utility>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include "router.h"
#include "upstream.h"
#include "connection_context.h"

namespace mux
{

class tproxy_tcp_session : public std::enable_shared_from_this<tproxy_tcp_session>
{
   public:
    tproxy_tcp_session(boost::asio::ip::tcp::socket socket,
                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                       std::shared_ptr<router> router,
                       std::uint32_t sid,
                       const config& cfg);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

   private:
    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> select_backend(const boost::asio::ip::address& addr);
    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(std::shared_ptr<upstream> backend);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();

   private:
    connection_context ctx_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::steady_timer idle_timer_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    const config& cfg_;
    std::shared_ptr<void> active_guard_;
    std::uint64_t last_activity_time_ms_{0};
    std::atomic<bool> backend_closed_{false};
};

}    // namespace mux

#endif
