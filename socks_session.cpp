#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/detached.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/crypto.h>
}

#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "socks_session.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"

namespace mux
{

socks_session::socks_session(asio::ip::tcp::socket socket,
                             std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                             std::shared_ptr<router> router,
                             const std::uint32_t sid,
                             const config::socks_t& socks_cfg)
    : sid_(sid),
      username_(socks_cfg.username),
      password_(socks_cfg.password),
      auth_enabled_(socks_cfg.auth),
      socket_(std::move(socket)),
      router_(std::move(router)),
      tunnel_manager_(std::move(tunnel_manager))
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
}

void socks_session::start()
{
    const auto self = shared_from_this();
    asio::co_spawn(socket_.get_executor(), [self]() mutable -> asio::awaitable<void> { co_await self->run(); }, asio::detached);
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
        const auto tcp_sess = std::make_shared<tcp_socks_session>(std::move(socket_), tunnel_manager_, router_, sid_);
        tcp_sess->start(host, port);
    }
    else if (cmd == socks::kCmdUdpAssociate)
    {
        const auto udp_sess = std::make_shared<udp_socks_session>(std::move(socket_), tunnel_manager_, sid_);
        udp_sess->start(host, port);
    }
    else
    {
        LOG_WARN("socks session {} cmd {} unsupported", sid_, cmd);
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

    std::uint8_t ulen = 0;
    auto [ue, un] = co_await asio::async_read(socket_, asio::buffer(&ulen, 1), asio::as_tuple(asio::use_awaitable));
    if (ue)
    {
        LOG_ERROR("socks session {} read username len failed", sid_);
        co_return false;
    }

    std::string username(ulen, '\0');
    auto [ue2, un2] = co_await asio::async_read(socket_, asio::buffer(username), asio::as_tuple(asio::use_awaitable));
    if (ue2)
    {
        LOG_ERROR("socks session {} read username failed", sid_);
        co_return false;
    }

    std::uint8_t plen = 0;
    auto [pe, pn] = co_await asio::async_read(socket_, asio::buffer(&plen, 1), asio::as_tuple(asio::use_awaitable));
    if (pe)
    {
        LOG_ERROR("socks session {} read password len failed", sid_);
        co_return false;
    }

    std::string password(plen, '\0');
    auto [pe2, pn2] = co_await asio::async_read(socket_, asio::buffer(password), asio::as_tuple(asio::use_awaitable));
    if (pe2)
    {
        LOG_ERROR("socks session {} read password failed", sid_);
        co_return false;
    }

    const bool user_match = (username.size() == username_.size()) && (CRYPTO_memcmp(username.data(), username_.data(), username.size()) == 0);
    const bool pass_match = (password.size() == password_.size()) && (CRYPTO_memcmp(password.data(), password_.data(), password.size()) == 0);
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
        LOG_WARN("socks session {} auth failed for user {}", sid_, username);
    }
    else
    {
        LOG_INFO("socks session {} auth success for user {}", sid_, username);
    }

    co_return success;
}

asio::awaitable<socks_session::request_info> socks_session::read_request()
{
    std::uint8_t head[4];
    auto [e, n] = co_await asio::async_read(socket_, asio::buffer(head), asio::as_tuple(asio::use_awaitable));
    if (e)
    {
        LOG_ERROR("socks session {} request read failed {}", sid_, e.message());
        co_return request_info{.ok = false, .host = "", .port = 0, .cmd = 0};
    }

    std::string host;
    if (head[3] == socks::kAtypIpv4)
    {
        asio::ip::address_v4::bytes_type b;
        co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
        host = asio::ip::address_v4(b).to_string();
    }
    else if (head[3] == socks::kAtypDomain)
    {
        std::uint8_t len = 0;
        co_await asio::async_read(socket_, asio::buffer(&len, 1), asio::as_tuple(asio::use_awaitable));
        host.resize(len);
        co_await asio::async_read(socket_, asio::buffer(host), asio::as_tuple(asio::use_awaitable));
    }
    else if (head[3] == socks::kAtypIpv6)
    {
        asio::ip::address_v6::bytes_type b;
        co_await asio::async_read(socket_, asio::buffer(b), asio::as_tuple(asio::use_awaitable));
        host = asio::ip::address_v6(b).to_string();
    }

    std::uint16_t port_n = 0;
    co_await asio::async_read(socket_, asio::buffer(&port_n, 2), asio::as_tuple(asio::use_awaitable));
    const std::uint16_t port = ntohs(port_n);
    LOG_INFO("socks session {} request {} {}", sid_, host, port);
    co_return request_info{.ok = true, .host = host, .port = port, .cmd = head[1]};
}

}    // namespace mux
