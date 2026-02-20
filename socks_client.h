#ifndef SOCKS_CLIENT_H
#define SOCKS_CLIENT_H

#include <atomic>
#include <memory>
#include <vector>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>

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
    [[nodiscard]] bool running() const
    {
        return started_.load(std::memory_order_acquire) && !stop_.load(std::memory_order_acquire) && acceptor_.is_open();
    }

   private:
    [[nodiscard]] static boost::asio::awaitable<void> accept_local_loop_detached(std::shared_ptr<socks_client> self);
    boost::asio::awaitable<void> accept_local_loop();

  private:
    std::atomic<bool> stop_{false};
    std::atomic<bool> started_{false};
    std::atomic<std::uint16_t> listen_port_{0};
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<mux::router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<std::vector<std::weak_ptr<socks_session>>> sessions_ =
        std::make_shared<std::vector<std::weak_ptr<socks_session>>>();
    config::timeout_t timeout_config_;
    config::queues_t queue_config_;
    config::socks_t socks_config_;
};

}    // namespace mux

#endif
