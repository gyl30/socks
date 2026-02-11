#ifndef SOCKS_CLIENT_H
#define SOCKS_CLIENT_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "client_tunnel_pool.h"

namespace mux
{

class socks_session;

class socks_client : public std::enable_shared_from_this<socks_client>
{
   public:
    socks_client(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::uint16_t listen_port() const { return listen_port_.load(std::memory_order_acquire); }

   private:
    asio::awaitable<void> accept_local_loop();

  private:
    std::atomic<bool> stop_{false};
    std::atomic<std::uint16_t> listen_port_{0};
    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<mux::router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::vector<std::weak_ptr<socks_session>> sessions_;
    config::timeout_t timeout_config_;
    config::socks_t socks_config_;
};

}    // namespace mux

#endif
