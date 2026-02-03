#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <asio.hpp>

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
                      uint32_t sid);

    void start(const std::string& host, uint16_t port);

   private:
    asio::awaitable<void> run(std::string host, uint16_t port);

    asio::awaitable<void> reply_error(uint8_t code);

    asio::awaitable<void> client_to_upstream(upstream* backend);

    asio::awaitable<void> upstream_to_client(upstream* backend);

   private:
    connection_context ctx_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
