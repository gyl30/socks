#ifndef SOCKS_PROTOCOL_SESSION_H
#define SOCKS_PROTOCOL_SESSION_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "config.h"
#include "context_pool.h"

namespace relay
{

struct socks_protocol_request
{
    bool ok = false;
    std::string host;
    uint16_t port = 0;
    uint8_t cmd = 0;
};

class socks_protocol_session
{
   public:
    socks_protocol_session(boost::asio::ip::tcp::socket& socket,
                           io_worker& worker,
                           const config& cfg,
                           const config::socks_t& settings,
                           uint64_t trace_id,
                           uint32_t conn_id,
                           const std::string& local_host,
                           uint16_t local_port,
                           const std::string& client_host,
                           uint16_t client_port);

    boost::asio::awaitable<bool> handshake();

    boost::asio::awaitable<socks_protocol_request> read_request();

    boost::asio::awaitable<void> reply_error(uint8_t code);
    boost::asio::awaitable<bool> fail_request(uint8_t code);

    [[nodiscard]] bool peer_closed_before_greeting() const;

   private:
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

    [[nodiscard]] static socks_protocol_request make_invalid_request(uint8_t cmd = 0);

    boost::asio::awaitable<socks_protocol_request> reject_request(uint8_t cmd, uint8_t rep);

    boost::asio::awaitable<bool> read_request_header(std::array<uint8_t, 4>& head);

    boost::asio::awaitable<bool> read_request_port(uint16_t& port);

    boost::asio::awaitable<std::optional<socks_protocol_request>> validate_request_head(const std::array<uint8_t, 4>& head);

    boost::asio::awaitable<socks_protocol_request> read_request_target(uint8_t cmd, uint8_t atyp);

   private:
    boost::asio::ip::tcp::socket& socket_;
    io_worker& worker_;
    const config& cfg_;
    const config::socks_t& settings_;
    uint64_t trace_id_ = 0;
    uint32_t conn_id_ = 0;
    const std::string& local_host_;
    uint16_t local_port_ = 0;
    const std::string& client_host_;
    uint16_t client_port_ = 0;
    bool peer_closed_before_greeting_ = false;
};

}    // namespace relay

#endif
