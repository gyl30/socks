#include <array>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>
#include <netinet/in.h>

#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "log_context.h"
#include "socks_session.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"
#include "timeout_io.h"

namespace mux
{

namespace
{

std::shared_ptr<void> make_active_connection_guard()
{
    return {new int(0),
            [](void* ptr)
            {
                delete static_cast<int*>(ptr);
                statistics::instance().dec_active_connections();
            }};
}

boost::asio::awaitable<timeout_io::timed_tcp_read_result> read_exact_with_optional_timeout(boost::asio::ip::tcp::socket& socket,
                                                                                            const boost::asio::mutable_buffer& buffer,
                                                                                            const std::uint32_t timeout_sec)
{
    if (timeout_sec == 0)
    {
        const auto [read_ec, read_size] = co_await boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        co_return timeout_io::timed_tcp_read_result{
            .ok = !read_ec,
            .timed_out = false,
            .read_size = read_size,
            .ec = read_ec,
        };
    }
    co_return co_await timeout_io::async_read_with_timeout(socket, buffer, timeout_sec, true, "socks session");
}

boost::asio::awaitable<timeout_io::timed_tcp_write_result> write_exact_with_optional_timeout(boost::asio::ip::tcp::socket& socket,
                                                                                              const boost::asio::const_buffer& buffer,
                                                                                              const std::uint32_t timeout_sec)
{
    if (timeout_sec == 0)
    {
        const auto [write_ec, write_size] = co_await boost::asio::async_write(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        co_return timeout_io::timed_tcp_write_result{
            .ok = !write_ec,
            .timed_out = false,
            .write_size = write_size,
            .ec = write_ec,
        };
    }
    co_return co_await timeout_io::async_write_with_timeout(socket, buffer, timeout_sec, "socks session");
}

bool secure_string_equals(const std::string& lhs, const std::string& rhs)
{
    const auto max_len = std::max(lhs.size(), rhs.size());
    std::uint8_t diff = static_cast<std::uint8_t>(lhs.size() ^ rhs.size());
    for (std::size_t i = 0; i < max_len; ++i)
    {
        const std::uint8_t lhs_byte = i < lhs.size() ? static_cast<std::uint8_t>(lhs[i]) : 0;
        const std::uint8_t rhs_byte = i < rhs.size() ? static_cast<std::uint8_t>(rhs[i]) : 0;
        diff = static_cast<std::uint8_t>(diff | (lhs_byte ^ rhs_byte));
    }
    return diff == 0;
}

}    // namespace

socks_session::socks_session(boost::asio::ip::tcp::socket socket,
                             boost::asio::io_context& io_context,
                             std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                             std::shared_ptr<router> router,
                             const std::uint32_t sid,
                             const config::socks_t& socks_cfg,
                             const config::timeout_t& timeout_cfg,
                             const config::queues_t& queue_cfg)
    : sid_(sid),
      username_(socks_cfg.username),
      password_(socks_cfg.password),
      auth_enabled_(socks_cfg.auth),
      io_context_(io_context),
      socket_(std::move(socket)),
      router_(std::move(router)),
      tunnel_manager_(std::move(tunnel_manager)),
      timeout_config_(timeout_cfg),
      queue_config_(queue_cfg)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    statistics::instance().inc_total_connections();
    statistics::instance().inc_active_connections();
    active_connection_guard_ = make_active_connection_guard();
}

socks_session::~socks_session() = default;

void socks_session::start()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(io_context_, [self]() mutable -> boost::asio::awaitable<void> { co_await self->run(); }, boost::asio::detached);
}

void socks_session::stop()
{
    boost::system::error_code ec;
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_WARN("socks session {} shutdown failed {}", sid_, ec.message());
    }
    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("socks session {} close failed {}", sid_, ec.message());
    }
}

boost::asio::awaitable<void> socks_session::run()
{
    if (!co_await handshake())
    {
        LOG_CTX_WARN(ctx_, "{} handshake failed", log_event::kSocks);
        stop();
        co_return;
    }

    const auto [ok, host, port, cmd] = co_await read_request();
    if (!ok)
    {
        LOG_CTX_WARN(ctx_, "{} request invalid", log_event::kSocks);
        stop();
        co_return;
    }

    if (cmd == socks::kCmdConnect)
    {
        const auto tcp_sess = std::make_shared<tcp_socks_session>(
            std::move(socket_), io_context_, tunnel_manager_, router_, sid_, timeout_config_, std::move(active_connection_guard_));
        tcp_sess->start(host, port);
    }
    else if (cmd == socks::kCmdUdpAssociate)
    {
        const auto udp_sess = std::make_shared<udp_socks_session>(std::move(socket_),
                                                                  io_context_,
                                                                  tunnel_manager_,
                                                                  sid_,
                                                                  timeout_config_,
                                                                  std::move(active_connection_guard_),
                                                                  queue_config_.udp_session_recv_channel_capacity);
        udp_sess->start(host, port);
    }
    else
    {
        LOG_WARN("socks session {} cmd {} unsupported", sid_, cmd);
        co_await reply_error(socks::kRepCmdNotSupported);
        stop();
        co_return;
    }
}

boost::asio::awaitable<bool> socks_session::handshake()
{
    std::uint8_t method_count = 0;
    if (!(co_await read_socks_greeting(method_count)))
    {
        co_return false;
    }

    std::vector<std::uint8_t> methods;
    if (!(co_await read_auth_methods(method_count, methods)))
    {
        co_return false;
    }

    const std::uint8_t selected_method = select_auth_method(methods);
    if (!(co_await write_selected_method(selected_method)))
    {
        co_return false;
    }

    if (selected_method == socks::kMethodNoAcceptable)
    {
        LOG_WARN("socks session {} no acceptable method", sid_);
        co_return false;
    }

    if (selected_method == socks::kMethodPassword)
    {
        co_return co_await do_password_auth();
    }

    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_socks_greeting(std::uint8_t& method_count)
{
    std::uint8_t ver_nmethods[2] = {0};
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(ver_nmethods, 2), timeout_config_.read);
    if (!read_res.ok || ver_nmethods[0] != socks::kVer)
    {
        if (!read_res.ok)
        {
            if (read_res.timed_out)
            {
                LOG_ERROR("socks session {} handshake timeout {}s", sid_, timeout_config_.read);
            }
            else
            {
                LOG_ERROR("socks session {} handshake failed {}", sid_, read_res.ec.message());
            }
        }
        else
        {
            LOG_ERROR("socks session {} handshake failed", sid_);
        }
        co_return false;
    }
    method_count = ver_nmethods[1];
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_auth_methods(const std::uint8_t method_count, std::vector<std::uint8_t>& methods)
{
    methods.assign(method_count, 0);
    const auto method_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(methods), timeout_config_.read);
    if (!method_res.ok)
    {
        if (method_res.timed_out)
        {
            LOG_ERROR("socks session {} methods read timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks methods read failed {}", method_res.ec.message());
        }
        co_return false;
    }
    co_return true;
}

std::uint8_t socks_session::select_auth_method(const std::vector<std::uint8_t>& methods) const
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

boost::asio::awaitable<bool> socks_session::write_selected_method(const std::uint8_t method)
{
    std::uint8_t resp[] = {socks::kVer, method};
    const auto write_res = co_await write_exact_with_optional_timeout(socket_, boost::asio::buffer(resp), timeout_config_.write);
    if (!write_res.ok)
    {
        if (write_res.timed_out)
        {
            LOG_ERROR("socks session {} write selected method timeout {}s", sid_, timeout_config_.write);
        }
        else
        {
            LOG_ERROR("socks session {} handshake failed {}", sid_, write_res.ec.message());
        }
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::do_password_auth()
{
    if (!(co_await read_auth_version()))
    {
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
        LOG_WARN("socks session {} auth failed", sid_);
        statistics::instance().inc_auth_failures();
    }
    else
    {
        LOG_INFO("socks session {} auth success", sid_);
    }

    co_return success;
}

boost::asio::awaitable<bool> socks_session::read_auth_version()
{
    std::uint8_t ver = 0;
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(&ver, 1), timeout_config_.read);
    if (!read_res.ok || ver != 0x01)
    {
        if (!read_res.ok && read_res.timed_out)
        {
            LOG_ERROR("socks session {} read auth version timeout {}s", sid_, timeout_config_.read);
            co_return false;
        }
        LOG_ERROR("socks session {} invalid auth version {}", sid_, ver);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_auth_field(std::string& out, const char* field_name)
{
    std::uint8_t field_len = 0;
    const auto len_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(&field_len, 1), timeout_config_.read);
    if (!len_res.ok)
    {
        if (len_res.timed_out)
        {
            LOG_ERROR("socks session {} read {} len timeout {}s", sid_, field_name, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} read {} len failed", sid_, field_name);
        }
        co_return false;
    }
    if (field_len == 0)
    {
        LOG_ERROR("socks session {} read {} len invalid 0", sid_, field_name);
        co_return false;
    }

    out.assign(field_len, '\0');
    const auto field_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(out), timeout_config_.read);
    if (!field_res.ok)
    {
        if (field_res.timed_out)
        {
            LOG_ERROR("socks session {} read {} timeout {}s", sid_, field_name, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} read {} failed", sid_, field_name);
        }
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

boost::asio::awaitable<bool> socks_session::write_auth_result(const bool success)
{
    std::uint8_t result[] = {0x01, success ? static_cast<std::uint8_t>(0x00) : static_cast<std::uint8_t>(0x01)};
    const auto write_res = co_await write_exact_with_optional_timeout(socket_, boost::asio::buffer(result), timeout_config_.write);
    if (!write_res.ok)
    {
        if (write_res.timed_out)
        {
            LOG_ERROR("socks session {} write auth result timeout {}s", sid_, timeout_config_.write);
        }
        else
        {
            LOG_ERROR("socks session {} write auth result failed {}", sid_, write_res.ec.message());
        }
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> socks_session::delay_invalid_request() const
{
    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
    boost::asio::steady_timer delay_timer(io_context_);
    delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
    co_await delay_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
}

bool socks_session::is_supported_cmd(const std::uint8_t cmd) { return cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate; }

bool socks_session::is_supported_atyp(const std::uint8_t cmd, const std::uint8_t atyp)
{
    if (atyp == socks::kAtypIpv4 || atyp == socks::kAtypIpv6)
    {
        return true;
    }
    return atyp == socks::kAtypDomain && (cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate);
}

boost::asio::awaitable<bool> socks_session::read_request_ipv4(std::string& host)
{
    boost::asio::ip::address_v4::bytes_type bytes_v4;
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(bytes_v4), timeout_config_.read);
    if (!read_res.ok)
    {
        if (read_res.timed_out)
        {
            LOG_ERROR("socks session {} request read ipv4 timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read ipv4 failed {}", sid_, read_res.ec.message());
        }
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    host = boost::asio::ip::address_v4(bytes_v4).to_string();
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_domain(std::string& host)
{
    std::uint8_t domain_len = 0;
    const auto len_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(&domain_len, 1), timeout_config_.read);
    if (!len_res.ok)
    {
        if (len_res.timed_out)
        {
            LOG_ERROR("socks session {} request read domain len timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read domain len failed {}", sid_, len_res.ec.message());
        }
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
    const auto host_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(host), timeout_config_.read);
    if (!host_res.ok)
    {
        if (host_res.timed_out)
        {
            LOG_ERROR("socks session {} request read domain timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read domain failed {}", sid_, host_res.ec.message());
        }
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    if (host.find('\0') != std::string::npos)
    {
        LOG_ERROR("socks session {} request domain contains nul", sid_);
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_ipv6(std::string& host)
{
    boost::asio::ip::address_v6::bytes_type bytes_v6;
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(bytes_v6), timeout_config_.read);
    if (!read_res.ok)
    {
        if (read_res.timed_out)
        {
            LOG_ERROR("socks session {} request read ipv6 timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read ipv6 failed {}", sid_, read_res.ec.message());
        }
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    host = boost::asio::ip::address_v6(bytes_v6).to_string();
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_host(const std::uint8_t atyp, const std::uint8_t cmd, std::string& host)
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

socks_session::request_info socks_session::make_invalid_request(const std::uint8_t cmd)
{
    return request_info{.ok = false, .host = "", .port = 0, .cmd = cmd};
}

boost::asio::awaitable<socks_session::request_info> socks_session::reject_request(const std::uint8_t cmd, const std::uint8_t rep)
{
    co_await delay_invalid_request();
    co_await reply_error(rep);
    co_return make_invalid_request(cmd);
}

boost::asio::awaitable<bool> socks_session::read_request_header(std::array<std::uint8_t, 4>& head)
{
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(head), timeout_config_.read);
    if (!read_res.ok)
    {
        if (read_res.timed_out)
        {
            LOG_ERROR("socks session {} request read timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read failed {}", sid_, read_res.ec.message());
        }
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_session::read_request_port(std::uint16_t& port)
{
    std::uint16_t port_n = 0;
    const auto read_res = co_await read_exact_with_optional_timeout(socket_, boost::asio::buffer(&port_n, 2), timeout_config_.read);
    if (!read_res.ok)
    {
        if (read_res.timed_out)
        {
            LOG_ERROR("socks session {} request read port timeout {}s", sid_, timeout_config_.read);
        }
        else
        {
            LOG_ERROR("socks session {} request read port failed {}", sid_, read_res.ec.message());
        }
        co_await reply_error(socks::kRepGenFail);
        co_return false;
    }
    port = ntohs(port_n);
    co_return true;
}

boost::asio::awaitable<std::optional<socks_session::request_info>> socks_session::validate_request_head(const std::array<std::uint8_t, 4>& head)
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

boost::asio::awaitable<socks_session::request_info> socks_session::read_request_target(const std::uint8_t cmd, const std::uint8_t atyp)
{
    std::string host;
    if (!co_await read_request_host(atyp, cmd, host))
    {
        co_return make_invalid_request(cmd);
    }

    std::uint16_t port = 0;
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
    std::array<std::uint8_t, 4> head = {0};
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

boost::asio::awaitable<void> socks_session::reply_error(std::uint8_t code)
{
    std::uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    const auto write_res = co_await write_exact_with_optional_timeout(socket_, boost::asio::buffer(err), timeout_config_.write);
    if (!write_res.ok)
    {
        if (write_res.timed_out)
        {
            LOG_ERROR("socks session {} write error response timeout {}s", sid_, timeout_config_.write);
        }
        else
        {
            LOG_ERROR("socks session {} write error response failed {}", sid_, write_res.ec.message());
        }
    }
}

}    // namespace mux
