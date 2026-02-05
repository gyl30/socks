#ifndef TCP_SOCKS_SESSION_H
#define TCP_SOCKS_SESSION_H

#include <cstdint>
#include <memory>
#include <string>

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>

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
                      const std::uint32_t sid);

    void start(const std::string& host, const std::uint16_t port);

   private:
    [[nodiscard]] asio::awaitable<void> run(const std::string& host, const std::uint16_t port);

    [[nodiscard]] asio::awaitable<void> reply_error(const std::uint8_t code);

    [[nodiscard]] asio::awaitable<void> client_to_upstream(upstream* backend);

    [[nodiscard]] asio::awaitable<void> upstream_to_client(upstream* backend);

   private:
    connection_context ctx_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
