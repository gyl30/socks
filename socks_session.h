#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include <memory>
#include <string>
#include <cstdint>

#include <asio.hpp>

#include "config.h"
#include "router.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"

namespace mux
{

class router;

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(asio::ip::tcp::socket socket,
                  std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                  std::shared_ptr<router> router,
                  std::uint32_t sid,
                  const config::socks_t& socks_cfg = {});

    void start();

   private:
    asio::awaitable<void> run();

    asio::awaitable<bool> handshake();

    asio::awaitable<bool> do_password_auth();

    struct request_info
    {
        bool ok;
        std::string host;
        std::uint16_t port;
        std::uint8_t cmd;
    };

    asio::awaitable<request_info> read_request();

   private:
    std::uint32_t sid_;
    std::string username_;
    std::string password_;
    bool auth_enabled_ = false;
    connection_context ctx_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux

#endif
