#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/crypto.h>
}

#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "log_context.h"
#include "socks_session.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"

namespace mux
{

socks_session::socks_session(asio::ip::tcp::socket socket,
                             asio::io_context& io_context,
                             std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                             std::shared_ptr<router> router,
                             const std::uint32_t sid,
                             const config::socks_t& socks_cfg,
                             const config::timeout_t& timeout_cfg)
    : sid_(sid),
      username_(socks_cfg.username),
      password_(socks_cfg.password),
      auth_enabled_(socks_cfg.auth),
      io_context_(io_context),
      socket_(std::move(socket)),
      router_(std::move(router)),
      tunnel_manager_(std::move(tunnel_manager)),
      timeout_config_(timeout_cfg)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    statistics::instance().inc_total_connections();
    statistics::instance().inc_active_connections();
}

socks_session::~socks_session() { statistics::instance().dec_active_connections(); }

void socks_session::start()
{
    const auto self = shared_from_this();
    asio::co_spawn(io_context_, [self]() mutable -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
}

void socks_session::stop()
{
    std::error_code ec;
    ec = socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != asio::error::not_connected)
    {
        LOG_WARN("socks session {} shutdown failed {}", sid_, ec.message());
    }
    ec = socket_.close(ec);
    if (ec && ec != asio::error::bad_descriptor)
    {
        LOG_WARN("socks session {} close failed {}", sid_, ec.message());
    }
}

asio::awaitable<void> socks_session::run()
{
    if (!co_await handshake())
    {
        LOG_CTX_WARN(ctx_, "{} handshake failed", log_event::kSocks);
        co_return;
    }

    const auto [ok, host, port, cmd] = co_await read_request();
    if (!ok)
    {
        LOG_CTX_WARN(ctx_, "{} request invalid", log_event::kSocks);
        co_return;
    }

    if (cmd == socks::kCmdConnect)
    {
        const auto tcp_sess =
            std::make_shared<tcp_socks_session>(std::move(socket_), io_context_, tunnel_manager_, router_, sid_, timeout_config_);
        tcp_sess->start(host, port);
    }
    else if (cmd == socks::kCmdUdpAssociate)
    {
        const auto udp_sess = std::make_shared<udp_socks_session>(std::move(socket_), io_context_, tunnel_manager_, sid_, timeout_config_);
        udp_sess->start(host, port);
    }
    else
    {
        LOG_WARN("socks session {} cmd {} unsupported", sid_, cmd);
        co_await reply_error(socks::kRepCmdNotSupported);
        co_return;
    }
}

asio::awaitable<bool> socks_session::handshake()
{
    std::uint8_t ver_nmethods[2];
    auto [e, n] = co_await asio::async_read(socket_, asio::buffer(ver_nmethods, 2), asio::as_tuple(asio::use_awaitable));
    if (e || ver_nmethods[0] != socks::kVer)
    {
        LOG_ERROR("socks session {} handshake failed", sid_);
        co_return false;
    }

    std::vector<std::uint8_t> methods(ver_nmethods[1]);
    auto [method_error, n2] = co_await asio::async_read(socket_, asio::buffer(methods), asio::as_tuple(asio::use_awaitable));
    if (method_error)
    {
        LOG_ERROR("socks methods read failed {}", method_error.message());
        co_return false;
    }

    std::uint8_t selected_method = socks::kMethodNoAcceptable;

    if (auth_enabled_)
    {
        if (std::find(methods.begin(), methods.end(), socks::kMethodPassword) != methods.end())
        {
            selected_method = socks::kMethodPassword;
        }
    }
    else
    {
        if (std::find(methods.begin(), methods.end(), socks::kMethodNoAuth) != methods.end())
        {
            selected_method = socks::kMethodNoAuth;
        }
    }

    std::uint8_t resp[] = {socks::kVer, selected_method};
    auto [response_error, n3] = co_await asio::async_write(socket_, asio::buffer(resp), asio::as_tuple(asio::use_awaitable));
    if (response_error)
    {
        LOG_ERROR("socks session {} handshake failed {}", sid_, response_error.message());
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

asio::awaitable<bool> socks_session::do_password_auth()
{
    std::uint8_t ver = 0;
    auto [ve, vn] = co_await asio::async_read(socket_, asio::buffer(&ver, 1), asio::as_tuple(asio::use_awaitable));
    if (ve || ver != 0x01)
    {
        LOG_ERROR("socks session {} invalid auth version {}", sid_, ver);
        co_return false;
    }

    std::string username;
    if (!co_await read_auth_field(username, "username"))
    {
        co_return false;
    }

    std::string password;
    if (!co_await read_auth_field(password, "password"))
    {
        co_return false;
    }

    const bool user_match =
        (username.size() == username_.size()) && (CRYPTO_memcmp(username.data(), username_.data(), username.size()) == 0);
    const bool pass_match =
        (password.size() == password_.size()) && (CRYPTO_memcmp(password.data(), password_.data(), password.size()) == 0);
    const bool success = user_match && pass_match;

    std::uint8_t result[] = {0x01, success ? static_cast<std::uint8_t>(0x00) : static_cast<std::uint8_t>(0x01)};
    auto [re, rn] = co_await asio::async_write(socket_, asio::buffer(result), asio::as_tuple(asio::use_awaitable));
    if (re)
    {
        LOG_ERROR("socks session {} write auth result failed", sid_);
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

asio::awaitable<bool> socks_session::read_auth_field(std::string& out, const char* field_name)
{
    std::uint8_t field_len = 0;
    auto [len_ec, len_n] = co_await asio::async_read(socket_, asio::buffer(&field_len, 1), asio::as_tuple(asio::use_awaitable));
    if (len_ec)
    {
        LOG_ERROR("socks session {} read {} len failed", sid_, field_name);
        co_return false;
    }

    out.assign(field_len, '\0');
    auto [field_ec, field_n] = co_await asio::async_read(socket_, asio::buffer(out), asio::as_tuple(asio::use_awaitable));
    if (field_ec)
    {
        LOG_ERROR("socks session {} read {} failed", sid_, field_name);
        co_return false;
    }
    (void)len_n;
    (void)field_n;
    co_return true;
}

asio::awaitable<void> socks_session::delay_invalid_request() const
{
    static thread_local std::mt19937 delay_gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
    asio::steady_timer delay_timer(io_context_);
    delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
    co_await delay_timer.async_wait(asio::as_tuple(asio::use_awaitable));
}

bool socks_session::is_supported_cmd(const std::uint8_t cmd) { return cmd == socks::kCmdConnect || cmd == socks::kCmdUdpAssociate; }

bool socks_session::is_supported_atyp(const std::uint8_t atyp)
{
    return atyp == socks::kAtypIpv4 || atyp == socks::kAtypDomain || atyp == socks::kAtypIpv6;
}

asio::awaitable<bool> socks_session::read_request_host(const std::uint8_t atyp, const std::uint8_t cmd, std::string& host)
{
    if (atyp == socks::kAtypIpv4)
    {
        asio::ip::address_v4::bytes_type bytes_v4;
        auto [read_ec, read_n] = co_await asio::async_read(socket_, asio::buffer(bytes_v4), asio::as_tuple(asio::use_awaitable));
        if (read_ec)
        {
            LOG_ERROR("socks session {} request read ipv4 failed {}", sid_, read_ec.message());
            co_await reply_error(socks::kRepGenFail);
            co_return false;
        }
        host = asio::ip::address_v4(bytes_v4).to_string();
        (void)read_n;
        co_return true;
    }

    if (atyp == socks::kAtypDomain)
    {
        std::uint8_t domain_len = 0;
        auto [len_ec, len_n] = co_await asio::async_read(socket_, asio::buffer(&domain_len, 1), asio::as_tuple(asio::use_awaitable));
        if (len_ec)
        {
            LOG_ERROR("socks session {} request read domain len failed {}", sid_, len_ec.message());
            co_await reply_error(socks::kRepGenFail);
            co_return false;
        }
        host.resize(domain_len);
        auto [host_ec, host_n] = co_await asio::async_read(socket_, asio::buffer(host), asio::as_tuple(asio::use_awaitable));
        if (host_ec)
        {
            LOG_ERROR("socks session {} request read domain failed {}", sid_, host_ec.message());
            co_await reply_error(socks::kRepGenFail);
            co_return false;
        }
        (void)len_n;
        (void)host_n;
        co_return true;
    }

    if (atyp == socks::kAtypIpv6)
    {
        asio::ip::address_v6::bytes_type bytes_v6;
        auto [read_ec, read_n] = co_await asio::async_read(socket_, asio::buffer(bytes_v6), asio::as_tuple(asio::use_awaitable));
        if (read_ec)
        {
            LOG_ERROR("socks session {} request read ipv6 failed {}", sid_, read_ec.message());
            co_await reply_error(socks::kRepGenFail);
            co_return false;
        }
        host = asio::ip::address_v6(bytes_v6).to_string();
        (void)read_n;
        co_return true;
    }

    LOG_WARN("socks session {} request unsupported atyp {} cmd {}", sid_, atyp, cmd);
    co_await reply_error(socks::kRepAddrTypeNotSupported);
    co_return false;
}

asio::awaitable<socks_session::request_info> socks_session::read_request()
{
    auto invalid = [](const std::uint8_t cmd = 0) -> request_info { return request_info{.ok = false, .host = "", .port = 0, .cmd = cmd}; };

    std::uint8_t head[4];
    auto [e, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
    if (e)
    {
        LOG_ERROR("socks session {} request read failed {}", sid_, e.message());
        co_await reply_error(socks::kRepGenFail);
        co_return invalid();
    }
    (void)n;

    if (head[0] != socks::kVer || head[2] != 0)
    {
        LOG_WARN("socks session {} request invalid header", sid_);
        co_await delay_invalid_request();
        co_await reply_error(socks::kRepGenFail);
        co_return invalid();
    }

    if (!is_supported_cmd(head[1]))
    {
        LOG_WARN("socks session {} request unsupported cmd {}", sid_, head[1]);
        co_await delay_invalid_request();
        co_await reply_error(socks::kRepCmdNotSupported);
        co_return invalid(head[1]);
    }

    if (!is_supported_atyp(head[3]))
    {
        LOG_WARN("socks session {} request unsupported atyp {}", sid_, head[3]);
        co_await delay_invalid_request();
        co_await reply_error(socks::kRepAddrTypeNotSupported);
        co_return invalid(head[1]);
    }

    std::string host;
    if (!co_await read_request_host(head[3], head[1], host))
    {
        co_return invalid(head[1]);
    }

    std::uint16_t port_n = 0;
    auto [pe, pn] = co_await asio::async_read(socket_, asio::buffer(&port_n, 2), asio::as_tuple(asio::use_awaitable));
    if (pe)
    {
        LOG_ERROR("socks session {} request read port failed {}", sid_, pe.message());
        co_await reply_error(socks::kRepGenFail);
        co_return invalid(head[1]);
    }
    (void)pn;
    const std::uint16_t port = ntohs(port_n);
    LOG_INFO("socks session {} request {} {}", sid_, host, port);
    co_return request_info{.ok = true, .host = host, .port = port, .cmd = head[1]};
}

asio::awaitable<void> socks_session::reply_error(std::uint8_t code)
{
    std::uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_ERROR("socks session {} write error response failed {}", sid_, we.message());
    }
}

}    // namespace mux
