#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include <asio.hpp>
#include <cstdint>
#include <memory>
#include <string>

#include "config.h"
#include "log_context.h"
#include "mux_tunnel.h"
#include "protocol.h"
#include "router.h"
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
                  uint32_t sid,
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
        uint16_t port;
        uint8_t cmd;
    };

    asio::awaitable<request_info> read_request();

   private:
    uint32_t sid_;
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
