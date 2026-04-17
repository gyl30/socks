#include <algorithm>
#include <array>
#include <chrono>
#include <random>
#include <string>
#include <vector>
#include <cstddef>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/endian/conversion.hpp>

#include "config.h"
#include "constants.h"
#include "log.h"
#include "net_utils.h"
#include "protocol.h"
#include "socks_protocol_session.h"

namespace relay
{

namespace
{

bool secure_string_equals(const std::string& lhs, const std::string& rhs)
{
    const auto max_len = std::max(lhs.size(), rhs.size());
    std::size_t diff = lhs.size() ^ rhs.size();
    for (std::size_t i = 0; i < max_len; ++i)
    {
        const auto lhs_byte = i < lhs.size() ? static_cast<uint8_t>(lhs[i]) : 0;
        const auto rhs_byte = i < rhs.size() ? static_cast<uint8_t>(rhs[i]) : 0;
        diff |= static_cast<std::size_t>(lhs_byte ^ rhs_byte);
    }
    return diff == 0;
}

}    // namespace

socks_protocol_session::socks_protocol_session(boost::asio::ip::tcp::socket& socket,
                                               io_worker& worker,
                                               const config& cfg,
                                               const config::socks_t& settings,
                                               const uint64_t trace_id,
                                               const uint32_t conn_id,
                                               const std::string& local_host,
                                               const uint16_t local_port,
                                               const std::string& client_host,
                                               const uint16_t client_port)
    : socket_(socket),
      worker_(worker),
      cfg_(cfg),
      settings_(settings),
      trace_id_(trace_id),
      conn_id_(conn_id),
      local_host_(local_host),
      local_port_(local_port),
      client_host_(client_host),
      client_port_(client_port)
{
}

boost::asio::awaitable<bool> socks_protocol_session::handshake()
{
    uint8_t method_count = 0;
    if (!(co_await read_socks_greeting(method_count)))
    {
        co_return false;
    }

    std::vector<uint8_t> methods;
    if (!(co_await read_auth_methods(method_count, methods)))
    {
        co_return false;
    }

    const uint8_t selected_method = select_auth_method(methods);
    if (!(co_await write_selected_method(selected_method)))
    {
        co_return false;
    }

    if (selected_method == socks::kMethodNoAcceptable)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} no acceptable method",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
        co_return false;
    }

    if (selected_method == socks::kMethodPassword)
    {
        co_return co_await do_password_auth();
    }

    co_return true;
}

boost::asio::awaitable<socks_protocol_request> socks_protocol_session::read_request()
{
    std::array<uint8_t, 4> head = {0};
    if (!(co_await read_request_header(head)))
    {
        co_return make_invalid_request();
    }

    const auto invalid_result = co_await validate_request_head(head);
    if (invalid_result.has_value())
    {
        co_return invalid_result.value();
    }

    co_return co_await read_request_target(head[1], head[3]);
}

boost::asio::awaitable<void> socks_protocol_session::reply_error(const uint8_t code)
{
    const auto err = socks::make_error_reply(code);

    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(err), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} write error response failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
    }
}

boost::asio::awaitable<bool> socks_protocol_session::fail_request(const uint8_t code)
{
    co_await reply_error(code);
    co_return false;
}

bool socks_protocol_session::peer_closed_before_greeting() const { return peer_closed_before_greeting_; }

boost::asio::awaitable<bool> socks_protocol_session::read_socks_greeting(uint8_t& method_count)
{
    boost::system::error_code ec;
    uint8_t ver_nmethods[2] = {0};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(ver_nmethods, 2), cfg_.timeout.read, ec);
    if (ec)
    {
        if (ec == boost::asio::error::eof)
        {
            peer_closed_before_greeting_ = true;
            LOG_INFO("{} conn {} local {}:{} remote {}:{} peer closed before greeting",
                     log_event::kConnClose,
                     conn_id_,
                     local_host_,
                     local_port_,
                     client_host_,
                     client_port_);
            co_return false;
        }
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read greeting failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return false;
    }
    if (ver_nmethods[0] != socks::kVer)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} invalid greeting version {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  static_cast<int>(ver_nmethods[0]));
        co_return false;
    }
    method_count = ver_nmethods[1];
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_auth_methods(const uint8_t method_count, std::vector<uint8_t>& methods)
{
    methods.assign(method_count, 0);
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(methods), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read methods failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return false;
    }
    co_return true;
}

uint8_t socks_protocol_session::select_auth_method(const std::vector<uint8_t>& methods) const
{
    if (settings_.auth)
    {
        if (std::ranges::find(methods, socks::kMethodPassword) != methods.end())
        {
            return socks::kMethodPassword;
        }
    }
    else
    {
        if (std::ranges::find(methods, socks::kMethodNoAuth) != methods.end())
        {
            return socks::kMethodNoAuth;
        }
    }
    return socks::kMethodNoAcceptable;
}

boost::asio::awaitable<bool> socks_protocol_session::write_selected_method(const uint8_t method)
{
    uint8_t resp[] = {socks::kVer, method};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(resp), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} write selected method failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::do_password_auth()
{
    if (!(co_await read_auth_version()))
    {
        (void)co_await write_auth_result(false);
        co_return false;
    }

    std::string username;
    if (!co_await read_auth_field(username, "username"))
    {
        (void)co_await write_auth_result(false);
        co_return false;
    }

    std::string password;
    if (!co_await read_auth_field(password, "password"))
    {
        (void)co_await write_auth_result(false);
        co_return false;
    }

    const bool success = verify_credentials(username, password);
    if (!(co_await write_auth_result(success)))
    {
        co_return false;
    }

    if (!success)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} auth failed",
                 log_event::kAuth,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
        const auto delay_ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(constants::socks::kAuthFailDelayMs));
        (void)delay_ec;
    }
    else
    {
        LOG_INFO("{} conn {} local {}:{} remote {}:{} auth success",
                 log_event::kAuth,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
    }

    co_return success;
}

boost::asio::awaitable<bool> socks_protocol_session::read_auth_version()
{
    uint8_t ver = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&ver, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read auth version failed {}",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return false;
    }

    if (ver != 0x01)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} invalid auth version {}",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ver);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_auth_field(std::string& out, const char* field_name)
{
    uint8_t field_len = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&field_len, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read {} len failed {}",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  field_name,
                  ec.message());
        co_return false;
    }
    if (field_len == 0)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read {} len invalid 0",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  field_name);
        co_return false;
    }

    out.assign(field_len, '\0');
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(out), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} read {} failed {}",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  field_name,
                  ec.message());
        co_return false;
    }
    co_return true;
}

bool socks_protocol_session::verify_credentials(const std::string& username, const std::string& password) const
{
    const bool user_match = secure_string_equals(username, settings_.username);
    const bool pass_match = secure_string_equals(password, settings_.password);
    return user_match && pass_match;
}

boost::asio::awaitable<bool> socks_protocol_session::write_auth_result(const bool success)
{
    uint8_t result[] = {0x01, success ? static_cast<uint8_t>(0x00) : static_cast<uint8_t>(0x01)};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(result), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} write auth result failed {}",
                  log_event::kAuth,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> socks_protocol_session::delay_invalid_request() const
{
    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<uint32_t> delay_dist(10, 50);
    const auto delay_ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(delay_dist(delay_gen)));
    (void)delay_ec;
}

bool socks_protocol_session::is_supported_cmd(const uint8_t cmd)
{
    return cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate;
}

bool socks_protocol_session::is_supported_atyp(const uint8_t cmd, const uint8_t atyp)
{
    if (atyp == socks::kAtypIpv4 || atyp == socks::kAtypIpv6)
    {
        return true;
    }
    return atyp == socks::kAtypDomain && (cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate);
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_ipv4(std::string& host)
{
    boost::asio::ip::address_v4::bytes_type bytes{};
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(bytes), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read ipv4 failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    host = boost::asio::ip::address_v4(bytes).to_string();
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_domain(std::string& host)
{
    uint8_t domain_len = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&domain_len, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read domain len failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    if (domain_len == 0)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request domain len invalid 0",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_);
        co_return co_await fail_request(socks::kRepGenFail);
    }
    host.resize(domain_len);
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(host), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read domain failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    if (host.find('\0') != std::string::npos)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request domain contains nul",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_);
        co_return co_await fail_request(socks::kRepGenFail);
    }
    if (!socks::is_valid_domain(host))
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request domain invalid",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_);
        co_return co_await fail_request(socks::kRepGenFail);
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_ipv6(std::string& host)
{
    boost::asio::ip::address_v6::bytes_type bytes{};
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(bytes), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read ipv6 failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    host = boost::asio::ip::address_v6(bytes).to_string();
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_host(const uint8_t atyp, const uint8_t cmd, std::string& host)
{
    if (atyp == socks::kAtypIpv4)
    {
        co_return co_await read_request_ipv4(host);
    }
    if (atyp == socks::kAtypDomain)
    {
        co_return co_await read_request_domain(host);
    }
    if (atyp == socks::kAtypIpv6)
    {
        co_return co_await read_request_ipv6(host);
    }
    LOG_WARN("{} conn {} local {}:{} remote {}:{} request unsupported atyp {} cmd {}",
             log_event::kSocks,
             conn_id_,
             local_host_,
             local_port_,
             client_host_,
             client_port_,
             atyp,
             cmd);
    co_await reply_error(socks::kRepAddrTypeNotSupported);
    co_return false;
}

socks_protocol_request socks_protocol_session::make_invalid_request(const uint8_t cmd)
{
    return socks_protocol_request{.ok = false, .host = "", .port = 0, .cmd = cmd};
}

boost::asio::awaitable<socks_protocol_request> socks_protocol_session::reject_request(const uint8_t cmd, const uint8_t rep)
{
    co_await delay_invalid_request();
    co_await reply_error(rep);
    co_return make_invalid_request(cmd);
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_header(std::array<uint8_t, 4>& head)
{
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(head), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_protocol_session::read_request_port(uint16_t& port)
{
    uint16_t port_n = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&port_n, 2), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} local {}:{} remote {}:{} request read port failed {}",
                  log_event::kSocks,
                  conn_id_,
                  local_host_,
                  local_port_,
                  client_host_,
                  client_port_,
                  ec.message());
        co_return co_await fail_request(socks::kRepGenFail);
    }
    port = boost::endian::big_to_native(port_n);
    co_return true;
}

boost::asio::awaitable<std::optional<socks_protocol_request>> socks_protocol_session::validate_request_head(
    const std::array<uint8_t, 4>& head)
{
    if (head[0] != socks::kVer || head[2] != 0)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request invalid header ver {} rsv {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_,
                 head[0],
                 head[2]);
        co_return co_await reject_request(0, socks::kRepGenFail);
    }

    if (!is_supported_cmd(head[1]))
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request unsupported cmd {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_,
                 head[1]);
        co_return co_await reject_request(head[1], socks::kRepCmdNotSupported);
    }

    if (!is_supported_atyp(head[1], head[3]))
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request unsupported atyp {} cmd {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_,
                 head[3],
                 head[1]);
        co_return co_await reject_request(head[1], socks::kRepAddrTypeNotSupported);
    }

    co_return std::nullopt;
}

boost::asio::awaitable<socks_protocol_request> socks_protocol_session::read_request_target(const uint8_t cmd, const uint8_t atyp)
{
    std::string host;
    if (!co_await read_request_host(atyp, cmd, host))
    {
        co_return make_invalid_request(cmd);
    }

    uint16_t port = 0;
    if (!(co_await read_request_port(port)))
    {
        co_return make_invalid_request(cmd);
    }

    if (host.empty())
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request empty host",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
        co_return co_await reject_request(cmd, socks::kRepGenFail);
    }
    if (cmd == socks::kCmdConnect && port == 0)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} request invalid port 0",
                 log_event::kSocks,
                 conn_id_,
                 local_host_,
                 local_port_,
                 client_host_,
                 client_port_);
        co_return co_await reject_request(cmd, socks::kRepGenFail);
    }

    LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} cmd {} request {} {}",
             log_event::kSocks,
             trace_id_,
             conn_id_,
             local_host_,
             local_port_,
             client_host_,
             client_port_,
             cmd,
             host,
             port);
    co_return socks_protocol_request{.ok = true, .host = host, .port = port, .cmd = cmd};
}

}    // namespace relay
