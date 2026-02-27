#ifndef SOCKS_SESSION_H
#define SOCKS_SESSION_H

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include "config.h"
#include "router.h"
#include "mux_tunnel.h"
#include "log_context.h"

namespace mux
{

class router;

class socks_session : public std::enable_shared_from_this<socks_session>
{
    friend class socks_session_tester;

   public:
    socks_session(boost::asio::ip::tcp::socket socket,
                  boost::asio::io_context& io_context,
                  std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                  std::shared_ptr<router> router,
                  std::uint32_t sid,
                  const config::socks_t& socks_cfg = {},
                  const config::timeout_t& timeout_cfg = {},
                  const config::queues_t& queue_cfg = {},
                  std::shared_ptr<boost::asio::cancellation_signal> stop_signal = nullptr);

    ~socks_session();

    void start();

    void stop();

   private:
    boost::asio::awaitable<void> run();

    boost::asio::awaitable<bool> handshake();

    boost::asio::awaitable<bool> read_socks_greeting(std::uint8_t& method_count);

    boost::asio::awaitable<bool> read_auth_methods(std::uint8_t method_count, std::vector<std::uint8_t>& methods);

    [[nodiscard]] std::uint8_t select_auth_method(const std::vector<std::uint8_t>& methods) const;

    boost::asio::awaitable<bool> write_selected_method(std::uint8_t method);

    boost::asio::awaitable<bool> do_password_auth();

    boost::asio::awaitable<bool> read_auth_version();

    boost::asio::awaitable<bool> read_auth_field(std::string& out, const char* field_name);

    [[nodiscard]] bool verify_credentials(const std::string& username, const std::string& password) const;

    boost::asio::awaitable<bool> write_auth_result(bool success);

    boost::asio::awaitable<void> delay_invalid_request() const;

    [[nodiscard]] static bool is_supported_cmd(std::uint8_t cmd);

    [[nodiscard]] static bool is_supported_atyp(std::uint8_t cmd, std::uint8_t atyp);

    boost::asio::awaitable<bool> read_request_ipv4(std::string& host);

    boost::asio::awaitable<bool> read_request_domain(std::string& host);

    boost::asio::awaitable<bool> read_request_ipv6(std::string& host);

    boost::asio::awaitable<bool> read_request_host(std::uint8_t atyp, std::uint8_t cmd, std::string& host);

    struct request_info
    {
        bool ok;
        std::string host;
        std::uint16_t port;
        std::uint8_t cmd;
    };

    [[nodiscard]] static request_info make_invalid_request(std::uint8_t cmd = 0);

    boost::asio::awaitable<request_info> reject_request(std::uint8_t cmd, std::uint8_t rep);

    boost::asio::awaitable<bool> read_request_header(std::array<std::uint8_t, 4>& head);

    boost::asio::awaitable<bool> read_request_port(std::uint16_t& port);

    boost::asio::awaitable<std::optional<request_info>> validate_request_head(const std::array<std::uint8_t, 4>& head);

    boost::asio::awaitable<request_info> read_request_target(std::uint8_t cmd, std::uint8_t atyp);

    boost::asio::awaitable<request_info> read_request();

    boost::asio::awaitable<void> reply_error(std::uint8_t code);

   private:
    std::uint32_t sid_;
    std::string username_;
    std::string password_;
    bool auth_enabled_ = false;
    connection_context ctx_;
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
    std::shared_ptr<void> active_connection_guard_;
    std::shared_ptr<boost::asio::cancellation_signal> stop_signal_;
    config::timeout_t timeout_config_;
    config::queues_t queue_config_;
};

}    // namespace mux

#endif
