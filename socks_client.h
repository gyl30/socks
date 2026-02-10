#ifndef SOCKS_CLIENT_H
#define SOCKS_CLIENT_H

#include <memory>
#include <string>
#include <cstdint>

#include <asio/ip/tcp.hpp>
#include <asio/awaitable.hpp>
#include <asio/experimental/concurrent_channel.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "client_tunnel_pool.h"

namespace mux
{

class socks_client : public std::enable_shared_from_this<socks_client>
{
   public:
    socks_client(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::uint16_t listen_port() const { return listen_port_; }

   private:
    asio::awaitable<void> accept_local_loop();

    asio::awaitable<void> wait_stop();

   private:
    bool stop_ = false;
    io_context_pool& pool_;
    std::uint16_t listen_port_;
    asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<mux::router> router_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    asio::experimental::concurrent_channel<void(std::error_code, int)> stop_channel_;
    config::timeout_t timeout_config_;
    config::socks_t socks_config_;
};

}    // namespace mux

#endif
