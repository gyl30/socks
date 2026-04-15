#ifndef SOCKS_CONTROL_SESSION_H
#define SOCKS_CONTROL_SESSION_H

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.h"
#include "router.h"
#include "constants.h"
#include "run_loop_spawner.h"

namespace relay
{

class socks_control_session : public std::enable_shared_from_this<socks_control_session>
{
   public:
    socks_control_session(boost::asio::ip::tcp::socket socket,
                          io_worker& worker,
                          std::shared_ptr<router> router,
                          uint32_t sid,
                          std::string inbound_tag,
                          const config& cfg,
                          const config::socks_t& settings);
    ~socks_control_session();

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

    template <typename Address>
    boost::asio::awaitable<bool> read_request_ip(std::string& host, const char* address_type_name);

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
    friend struct run_loop_spawner;

    uint32_t sid_;
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    std::string inbound_tag_;
    std::string local_host_ = "unknown";
    uint16_t local_port_ = 0;
    std::string client_host_ = "unknown";
    uint16_t client_port_ = 0;
    bool peer_closed_before_greeting_ = false;
    const config& cfg_;
    config::socks_t settings_;
    io_worker& worker_;
    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<router> router_;
};

}    // namespace relay

#endif
