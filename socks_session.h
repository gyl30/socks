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
    friend class socks_session_tester;

   public:
    socks_session(asio::ip::tcp::socket socket,
                  asio::io_context& io_context,
                  std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                  std::shared_ptr<router> router,
                  std::uint32_t sid,
                  const config::socks_t& socks_cfg = {},
                  const config::timeout_t& timeout_cfg = {});

    ~socks_session();

    void start();

    void stop();

   private:
    asio::awaitable<void> run();

    asio::awaitable<bool> handshake();

    asio::awaitable<bool> do_password_auth();

    asio::awaitable<bool> read_auth_field(std::string& out, const char* field_name);

    asio::awaitable<void> delay_invalid_request() const;

    [[nodiscard]] static bool is_supported_cmd(std::uint8_t cmd);

    [[nodiscard]] static bool is_supported_atyp(std::uint8_t atyp);

    asio::awaitable<bool> read_request_host(std::uint8_t atyp, std::uint8_t cmd, std::string& host);

    struct request_info
    {
        bool ok;
        std::string host;
        std::uint16_t port;
        std::uint8_t cmd;
    };

    asio::awaitable<request_info> read_request();

    asio::awaitable<void> reply_error(std::uint8_t code);

   private:
    std::uint32_t sid_;
    std::string username_;
    std::string password_;
    bool auth_enabled_ = false;
    connection_context ctx_;
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    config::timeout_t timeout_config_;
};

}    // namespace mux

#endif
