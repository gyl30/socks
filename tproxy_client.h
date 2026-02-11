#ifndef TPROXY_CLIENT_H
#define TPROXY_CLIENT_H

#include <atomic>
#include <memory>
#include <string>
#include <cstdint>
#include <unordered_map>

#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>
#include <asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "tproxy_udp_sender.h"
#include "client_tunnel_pool.h"
#include "tproxy_tcp_session.h"
#include "tproxy_udp_session.h"

namespace mux
{

class tproxy_client : public std::enable_shared_from_this<tproxy_client>
{
   public:
    tproxy_client(io_context_pool& pool, const config& cfg);

    void start();

    void stop();

    [[nodiscard]] std::uint16_t tcp_port() const { return tcp_port_; }

    [[nodiscard]] std::uint16_t udp_port() const { return udp_port_; }

   private:
    asio::awaitable<void> accept_tcp_loop();

    asio::awaitable<void> udp_loop();

    asio::awaitable<void> udp_cleanup_loop();

    [[nodiscard]] std::string endpoint_key(const asio::ip::udp::endpoint& ep) const;

   private:
    std::atomic<bool> stop_{false};
    asio::io_context::executor_type ex_;
    asio::ip::tcp::acceptor tcp_acceptor_;
    asio::ip::udp::socket udp_socket_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
    std::shared_ptr<router> router_;
    std::shared_ptr<tproxy_udp_sender> sender_;
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>> udp_sessions_;
    config cfg_;
    config::tproxy_t tproxy_config_;
    std::uint16_t tcp_port_ = 0;
    std::uint16_t udp_port_ = 0;
    std::uint32_t udp_idle_timeout_sec_ = 0;
};

}    // namespace mux

#endif
