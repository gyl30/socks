#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "protocol.h"
#include "net_utils.h"
#include "context_pool.h"
#include "socks_session.h"
#include "connection_tracker.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"

namespace mux
{

namespace
{
bool secure_string_equals(const std::string& lhs, const std::string& rhs)
{
    const auto max_len = std::max(lhs.size(), rhs.size());
    std::size_t diff = lhs.size() ^ rhs.size();
    for (std::size_t i = 0; i < max_len; ++i)
    {
        const uint8_t lhs_byte = i < lhs.size() ? static_cast<uint8_t>(lhs[i]) : 0;
        const uint8_t rhs_byte = i < rhs.size() ? static_cast<uint8_t>(rhs[i]) : 0;
        diff |= static_cast<std::size_t>(lhs_byte ^ rhs_byte);
    }
    return diff == 0;
}

}    // namespace

socks_session::socks_session(boost::asio::ip::tcp::socket socket,
                             io_worker& worker,
                             std::shared_ptr<client_tunnel_pool> tunnel_pool,
                             std::shared_ptr<router> router,
                             uint32_t sid,
                             const config& cfg,
                             std::shared_ptr<void> active_connection_guard)
    : sid_(sid),
      conn_id_(sid),
      username_(cfg.socks.username),
      password_(cfg.socks.password),
      auth_enabled_(cfg.socks.auth),
      cfg_(cfg),
      worker_(worker),
      socket_(std::move(socket)),
      router_(std::move(router)),
      active_guard_(std::move(active_connection_guard)),
      tunnel_pool_(std::move(tunnel_pool))
{
    if (!active_guard_)
    {
        active_guard_ = acquire_active_connection_guard();
    }
}

socks_session::~socks_session() = default;

void socks_session::start()
{
    worker_.group.spawn([self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await self->run_loop(); });
}

void socks_session::stop()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("event {} conn_id {} shutdown client failed {}", log_event::kSocks, conn_id_, ec.message());
    }
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} conn_id {} close client failed {}", log_event::kSocks, conn_id_, ec.message());
    }
}

boost::asio::awaitable<void> socks_session::run_loop()
{
    if (!co_await handshake())
    {
        LOG_WARN("event {} conn_id {} handshake failed", log_event::kSocks, conn_id_);
        stop();
        co_return;
    }

    const auto [ok, host, port, cmd] = co_await read_request();
    if (!ok)
    {
        LOG_WARN("event {} conn_id {} request invalid", log_event::kSocks, conn_id_);
        stop();
        co_return;
    }

    if (cmd == socks::kCmdConnect)
    {
        const auto tcp_sess = std::make_shared<tcp_socks_session>(std::move(socket_), tunnel_pool_, router_, sid_, cfg_, std::move(active_guard_));
        worker_.group.spawn([tcp_sess, host, port]() -> boost::asio::awaitable<void> { co_await tcp_sess->start(host, port); });
    }
    else if (cmd == socks::kCmdUdpAssociate)
    {
        const auto udp_sess =
            std::make_shared<udp_socks_session>(std::move(socket_), worker_, tunnel_pool_, router_, sid_, cfg_, std::move(active_guard_));
        udp_sess->start(host, port);
    }
    else
    {
        LOG_WARN("event {} conn_id {} cmd {} unsupported", log_event::kSocks, conn_id_, cmd);
        co_await reply_error(socks::kRepCmdNotSupported);
        co_return;
    }
}

boost::asio::awaitable<bool> socks_session::handshake()
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
        LOG_WARN("event {} conn_id {} no acceptable method", log_event::kSocks, conn_id_);
        co_return false;
    }

    if (selected_method == socks::kMethodPassword)
    {
        co_return co_await do_password_auth();
    }

    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_socks_greeting(uint8_t& method_count)
{
    boost::system::error_code ec;
    uint8_t ver_nmethods[2] = {0};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(ver_nmethods, 2), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} read greeting failed {}", log_event::kSocks, conn_id_, ec.message());
        co_return false;
    }
    if (ver_nmethods[0] != socks::kVer)
    {
        LOG_ERROR("event {} conn_id {} invalid greeting version {}", log_event::kSocks, conn_id_, static_cast<int>(ver_nmethods[0]));
        co_return false;
    }
    method_count = ver_nmethods[1];
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_auth_methods(uint8_t method_count, std::vector<uint8_t>& methods)
{
    methods.assign(method_count, 0);
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(methods), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} read methods failed {}", log_event::kSocks, conn_id_, ec.message());
        co_return false;
    }
    co_return true;
}

uint8_t socks_session::select_auth_method(const std::vector<uint8_t>& methods) const
{
    if (auth_enabled_)
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

boost::asio::awaitable<bool> socks_session::write_selected_method(uint8_t method)
{
    uint8_t resp[] = {socks::kVer, method};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(resp), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} write selected method failed {}", log_event::kSocks, conn_id_, ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::do_password_auth()
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
        LOG_WARN("event {} conn_id {} auth failed", log_event::kAuth, conn_id_);
        const auto delay_ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(constants::socks::kAuthFailDelayMs));
        (void)delay_ec;
    }
    else
    {
        LOG_INFO("socks session {} auth success", sid_);
    }

    co_return success;
}

boost::asio::awaitable<bool> socks_session::read_auth_version()
{
    uint8_t ver = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&ver, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} read auth version failed {}", sid_, ec.message());
        co_return false;
    }

    if (ver != 0x01)
    {
        LOG_ERROR("socks session {} invalid auth version {}", sid_, ver);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_auth_field(std::string& out, const char* field_name)
{
    uint8_t field_len = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&field_len, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} read {} len failed {}", sid_, field_name, ec.message());
        co_return false;
    }
    if (field_len == 0)
    {
        LOG_ERROR("socks session {} read {} len invalid 0", sid_, field_name);
        co_return false;
    }

    out.assign(field_len, '\0');
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(out), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} read {} failed {}", sid_, field_name, ec.message());
        co_return false;
    }
    co_return true;
}

bool socks_session::verify_credentials(const std::string& username, const std::string& password) const
{
    const bool user_match = secure_string_equals(username, username_);
    const bool pass_match = secure_string_equals(password, password_);
    return user_match && pass_match;
}

boost::asio::awaitable<bool> socks_session::write_auth_result(bool success)
{
    uint8_t result[] = {0x01, success ? static_cast<uint8_t>(0x00) : static_cast<uint8_t>(0x01)};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(result), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} write auth result failed {}", sid_, ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> socks_session::delay_invalid_request() const
{
    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<uint32_t> delay_dist(10, 50);
    const auto delay_ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(delay_dist(delay_gen)));
    (void)delay_ec;
}

bool socks_session::is_supported_cmd(uint8_t cmd) { return cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate; }

bool socks_session::is_supported_atyp(uint8_t cmd, uint8_t atyp)
{
    if (atyp == socks::kAtypIpv4 || atyp == socks::kAtypIpv6)
    {
        return true;
    }
    return atyp == socks::kAtypDomain && (cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate);
}

template <typename Address>
boost::asio::awaitable<bool> socks_session::read_request_ip(std::string& host, const char* address_type_name)
{
    using bytes_type = typename Address::bytes_type;
    boost::system::error_code ec;
    bytes_type bytes{};
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(bytes), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} request read {} failed {}", sid_, address_type_name, ec.message());
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    host = Address(bytes).to_string();
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_ipv4(std::string& host)
{
    co_return co_await read_request_ip<boost::asio::ip::address_v4>(host, "ipv4");
}

boost::asio::awaitable<bool> socks_session::read_request_domain(std::string& host)
{
    uint8_t domain_len = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&domain_len, 1), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} request read domain len failed {}", sid_, ec.message());
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    if (domain_len == 0)
    {
        LOG_ERROR("socks session {} request domain len invalid 0", sid_);
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    host.resize(domain_len);
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(host), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} request read domain failed {}", sid_, ec.message());
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    if (host.find('\0') != std::string::npos)
    {
        LOG_ERROR("socks session {} request domain contains nul", sid_);
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    if (!socks::is_valid_domain(host))
    {
        LOG_ERROR("socks session {} request domain invalid", sid_);
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_ipv6(std::string& host)
{
    co_return co_await read_request_ip<boost::asio::ip::address_v6>(host, "ipv6");
}

boost::asio::awaitable<bool> socks_session::read_request_host(uint8_t atyp, uint8_t cmd, std::string& host)
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
    LOG_WARN("socks session {} request unsupported atyp {} cmd {}", sid_, atyp, cmd);
    co_await reply_error(socks::kRepAddrTypeNotSupported);
    co_return false;
}

socks_session::request_info socks_session::make_invalid_request(uint8_t cmd)
{
    return request_info{.ok = false, .host = "", .port = 0, .cmd = cmd};
}

boost::asio::awaitable<socks_session::request_info> socks_session::reject_request(uint8_t cmd, uint8_t rep)
{
    co_await delay_invalid_request();
    co_await reply_error(rep);
    co_return make_invalid_request(cmd);
}

boost::asio::awaitable<bool> socks_session::read_request_header(std::array<uint8_t, 4>& head)
{
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(head), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} request read failed {}", sid_, ec.message());
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_port(uint16_t& port)
{
    uint16_t port_n = 0;
    boost::system::error_code ec;
    co_await net::wait_read_with_timeout(socket_, boost::asio::buffer(&port_n, 2), cfg_.timeout.read, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} request read port failed {}", sid_, ec.message());
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    port = boost::endian::big_to_native(port_n);
    co_return true;
}

boost::asio::awaitable<std::optional<socks_session::request_info>> socks_session::validate_request_head(const std::array<uint8_t, 4>& head)
{
    if (head[0] != socks::kVer || head[2] != 0)
    {
        LOG_WARN("socks session {} request invalid header", sid_);
        co_return co_await reject_request(0, socks::kRepGenFail);
    }

    if (!is_supported_cmd(head[1]))
    {
        LOG_WARN("socks session {} request unsupported cmd {}", sid_, head[1]);
        co_return co_await reject_request(head[1], socks::kRepCmdNotSupported);
    }

    if (!is_supported_atyp(head[1], head[3]))
    {
        LOG_WARN("socks session {} request unsupported atyp {} cmd {}", sid_, head[3], head[1]);
        co_return co_await reject_request(head[1], socks::kRepAddrTypeNotSupported);
    }

    co_return std::nullopt;
}

boost::asio::awaitable<socks_session::request_info> socks_session::read_request_target(uint8_t cmd, uint8_t atyp)
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
        LOG_WARN("socks session {} request empty host", sid_);
        co_return co_await reject_request(cmd, socks::kRepGenFail);
    }
    if (cmd == socks::kCmdConnect && port == 0)
    {
        LOG_WARN("socks session {} request invalid port 0", sid_);
        co_return co_await reject_request(cmd, socks::kRepGenFail);
    }

    LOG_INFO("socks session {} request {} {}", sid_, host, port);
    co_return request_info{.ok = true, .host = host, .port = port, .cmd = cmd};
}

boost::asio::awaitable<socks_session::request_info> socks_session::read_request()
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

boost::asio::awaitable<void> socks_session::reply_error(uint8_t code)
{
    uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};

    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(err), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_ERROR("socks session {} write error response failed {}", sid_, ec.message());
    }
}

}    // namespace mux
