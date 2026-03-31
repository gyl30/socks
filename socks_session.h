#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include "client_tunnel_pool.h"

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

#include "router.h"
#include "constants.h"

namespace mux
{

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket,
                  io_worker& worker,
                  std::shared_ptr<client_tunnel_pool> tunnel_pool,
                  std::shared_ptr<router> router,
                  uint32_t sid,
                  const config& cfg,
                  std::shared_ptr<void> active_connection_guard = nullptr);
    ~socks_session();

    void start();

    void stop();

   private:
    boost::asio::awaitable<void> run_loop();

    boost::asio::awaitable<bool> handshake();

    boost::asio::awaitable<bool> read_socks_greeting(uint8_t& method_count);

    boost::asio::awaitable<bool> read_auth_methods(uint8_t method_count, std::vector<uint8_t>& methods);

    [[nodiscard]] uint8_t select_auth_method(const std::vector<uint8_t>& methods) const;

    boost::asio::awaitable<bool> write_selected_method(uint8_t method);

    boost::asio::awaitable<bool> do_password_auth();

    boost::asio::awaitable<bool> read_auth_version();

    boost::asio::awaitable<bool> read_auth_field(std::string& out, const char* field_name);

    [[nodiscard]] bool verify_credentials(const std::string& username, const std::string& password) const;

    boost::asio::awaitable<bool> write_auth_result(bool success);

    boost::asio::awaitable<void> delay_invalid_request() const;

    [[nodiscard]] static bool is_supported_cmd(uint8_t cmd);

    [[nodiscard]] static bool is_supported_atyp(uint8_t cmd, uint8_t atyp);

    boost::asio::awaitable<bool> read_request_ipv4(std::string& host);

    boost::asio::awaitable<bool> read_request_domain(std::string& host);

    boost::asio::awaitable<bool> read_request_ipv6(std::string& host);

    boost::asio::awaitable<bool> read_request_host(uint8_t atyp, uint8_t cmd, std::string& host);

    struct request_info
    {
        bool ok;
        std::string host;
        uint16_t port;
        uint8_t cmd;
    };

    [[nodiscard]] static request_info make_invalid_request(uint8_t cmd = 0);

    boost::asio::awaitable<request_info> reject_request(uint8_t cmd, uint8_t rep);

    boost::asio::awaitable<bool> read_request_header(std::array<uint8_t, 4>& head);

    boost::asio::awaitable<bool> read_request_port(uint16_t& port);

    boost::asio::awaitable<std::optional<request_info>> validate_request_head(const std::array<uint8_t, 4>& head);

    boost::asio::awaitable<request_info> read_request_target(uint8_t cmd, uint8_t atyp);

    boost::asio::awaitable<request_info> read_request();

    boost::asio::awaitable<void> reply_error(uint8_t code);

   private:
    uint32_t sid_;
    uint32_t conn_id_ = 0;
    std::string username_;
    std::string password_;
    bool auth_enabled_ = false;
    const config& cfg_;
    io_worker& worker_;
    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<void> active_guard_;
    std::shared_ptr<client_tunnel_pool> tunnel_pool_;
};

}    // namespace mux

#endif
