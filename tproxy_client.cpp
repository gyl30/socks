#include <chrono>
#include <array>
#include <cerrno>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <sys/uio.h>
#include <sys/socket.h>

#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "net_utils.h"
#include "context_pool.h"
#include "tproxy_client.h"
#include "client_tunnel_pool.h"
#include "tproxy_tcp_session.h"
#include "tproxy_udp_session.h"

namespace mux
{

namespace
{
void open_tcp_listener(boost::asio::ip::tcp::acceptor& acceptor, const std::string& host, std::uint16_t port, boost::system::error_code& ec)
{
    auto listen_addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return;
    }

    const boost::asio::ip::tcp::endpoint ep{listen_addr, port};
    const bool is_v6 = listen_addr.is_v6();
    const bool enable_dual_stack = is_v6 && listen_addr.to_v6().is_unspecified();
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return;
    }
    ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return;
    }
    if (enable_dual_stack)
    {
        ec = acceptor.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return;
        }
    }
    net::set_socket_transparent(acceptor.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }

    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        return;
    }
    ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        return;
    }
}

void open_udp_listener(boost::asio::ip::udp::socket& socket, const std::string& host, std::uint16_t port, boost::system::error_code& ec)
{
    auto listen_addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return;
    }

    const boost::asio::ip::udp::endpoint endpoint{listen_addr, port};
    const bool is_v6 = listen_addr.is_v6();
    const bool enable_dual_stack = is_v6 && listen_addr.to_v6().is_unspecified();
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        return;
    }
    ec = socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return;
    }
    if (enable_dual_stack)
    {
        ec = socket.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return;
        }
    }
    net::set_socket_transparent(socket.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }
    net::set_socket_recv_origdst(socket.native_handle(), is_v6, ec);
    if (ec)
    {
        return;
    }
    ec = socket.bind(endpoint, ec);
}

}    // namespace

tproxy_client::tproxy_client(io_context_pool& pool, const config& cfg)
    : cfg_(cfg),
      io_context_(pool.get_io_context()),
      router_(std::make_shared<router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, group_)),
      tcp_acceptor_(io_context_)
{
}

void tproxy_client::start()
{
    if (!cfg_.tproxy.enabled)
    {
        LOG_INFO("tproxy client disabled");
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        return;
    }

    if (cfg_.tproxy.tcp_port == 0 && cfg_.tproxy.udp_port == 0)
    {
        LOG_ERROR("tproxy tcp and udp ports are both zero");
        return;
    }

    auto self = shared_from_this();
    tunnel_pool_->start();
    if (cfg_.tproxy.tcp_port != 0)
    {
        boost::asio::co_spawn(io_context_, [self]() { return self->accept_tcp_loop(); }, group_.adapt(boost::asio::detached));
    }
    if (cfg_.tproxy.udp_port != 0)
    {
        boost::asio::co_spawn(io_context_, [self]() { return self->accept_udp_loop(); }, group_.adapt(boost::asio::detached));
    }
}

void tproxy_client::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(
        io_context_,
        [self = shared_from_this()]()
        {
            LOG_INFO("tproxy client stopping closing resources");

            boost::system::error_code ec;
            ec = self->tcp_acceptor_.close(ec);
            if (ec && ec != boost::asio::error::bad_descriptor)
            {
                LOG_ERROR("tproxy tcp acceptor close error {}", ec.message());
            }
            ec = self->udp_socket_.close(ec);
            if (ec && ec != boost::asio::error::bad_descriptor)
            {
                LOG_ERROR("tproxy udp socket close error {}", ec.message());
            }

            for (auto& [_, session] : self->udp_sessions_)
            {
                if (session != nullptr)
                {
                    session->stop();
                }
            }
            self->udp_sessions_.clear();

            if (self->tunnel_pool_ != nullptr)
            {
                self->tunnel_pool_->stop();
            }

            self->group_.emit(boost::asio::cancellation_type::all);
        });
}

boost::asio::awaitable<void> tproxy_client::wait_stopped()
{
    const auto [ec] = co_await group_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("tproxy client wait stopped failed {}", ec.message());
    }
}

boost::asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    boost::system::error_code ec;
    open_tcp_listener(tcp_acceptor_, cfg_.tproxy.listen_host, cfg_.tproxy.tcp_port, ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp listen failed {}", ec.message());
        co_return;
    }
    LOG_INFO("tproxy tcp listening on {}:{}", cfg_.tproxy.listen_host, cfg_.tproxy.tcp_port);

    while (true)
    {
        boost::asio::ip::tcp::socket socket(io_context_);
        co_await tcp_acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_WARN("tproxy tcp accept cancelled {}", ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("tproxy tcp accept failed {} retry", ec.message());
            boost::asio::steady_timer retry_timer(io_context_);
            retry_timer.expires_after(std::chrono::seconds(3));
            co_await retry_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                LOG_ERROR("tproxy accept retry timer error {}", ec.message());
                break;
            }
            continue;
        }
        on_tcp_socket(std::move(socket));
    }

    LOG_INFO("tproxy tcp accept loop exited");
}

void tproxy_client::on_tcp_socket(boost::asio::ip::tcp::socket&& socket)
{
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy tcp set no delay failed code {}", ec.value());
    }

    const std::uint32_t sid = tunnel_pool_->next_session_id();
    std::make_shared<tproxy_tcp_session>(std::move(socket), io_context_, tunnel_pool_, router_, sid, cfg_, group_)->start();
}

boost::asio::awaitable<void> tproxy_client::accept_udp_loop()
{
    boost::system::error_code ec;
    open_udp_listener(udp_socket_, cfg_.tproxy.listen_host, cfg_.tproxy.udp_port, ec);
    if (ec)
    {
        LOG_ERROR("tproxy udp listen failed {}", ec.message());
        co_return;
    }

    LOG_INFO("tproxy udp listening on {}:{}", cfg_.tproxy.listen_host, cfg_.tproxy.udp_port);
    std::vector<std::uint8_t> payload(65535);
    std::array<char, CMSG_SPACE(sizeof(sockaddr_in6))> control{};

    while (true)
    {
        co_await udp_socket_.async_wait(boost::asio::ip::udp::socket::wait_read, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            break;
        }
        if (ec)
        {
            LOG_ERROR("tproxy udp wait failed {}", ec.message());
            break;
        }

        sockaddr_storage source_addr{};
        iovec iov{payload.data(), payload.size()};
        msghdr msg{};
        msg.msg_name = &source_addr;
        msg.msg_namelen = sizeof(source_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();

        const auto bytes_recv = recvmsg(udp_socket_.native_handle(), &msg, MSG_DONTWAIT);
        if (bytes_recv < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            {
                continue;
            }
            LOG_ERROR("tproxy udp recvmsg failed {}", std::strerror(errno));
            continue;
        }
        if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        {
            LOG_WARN("tproxy udp recvmsg truncated drop flags {} bytes {} controllen {}",
                     msg.msg_flags,
                     bytes_recv,
                     msg.msg_controllen);
            continue;
        }

        const auto client_endpoint = net::normalize_endpoint(net::endpoint_from_sockaddr(source_addr, msg.msg_namelen));
        const auto target_endpoint_opt = net::parse_original_dst(msg);
        if (!target_endpoint_opt.has_value())
        {
            LOG_WARN("tproxy udp parse original dst failed");
            continue;
        }

        const auto target_endpoint = net::normalize_endpoint(*target_endpoint_opt);
        if (client_endpoint.port() == 0 || target_endpoint.port() == 0)
        {
            LOG_WARN("tproxy udp skip invalid endpoint");
            continue;
        }

        std::vector<std::uint8_t> packet(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(bytes_recv));
        co_await on_udp_packet(client_endpoint, target_endpoint, std::move(packet));
    }

    LOG_INFO("tproxy udp accept loop exited");
}

boost::asio::awaitable<void> tproxy_client::on_udp_packet(boost::asio::ip::udp::endpoint client_endpoint,
                                                          boost::asio::ip::udp::endpoint target_endpoint,
                                                          std::vector<std::uint8_t> payload)
{
    client_endpoint = net::normalize_endpoint(client_endpoint);
    target_endpoint = net::normalize_endpoint(target_endpoint);

    const auto key = make_udp_session_key(client_endpoint, target_endpoint);
    auto session_it = udp_sessions_.find(key);
    if (session_it == udp_sessions_.end())
    {
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(tunnel_pool_->next_session_id());
        ctx.remote_addr(client_endpoint.address().to_string());
        ctx.remote_port(client_endpoint.port());
        ctx.set_target(target_endpoint.address().to_string(), target_endpoint.port());
        ctx.local_addr(target_endpoint.address().to_string());
        ctx.local_port(target_endpoint.port());

        route_type route = route_type::kProxy;
        if (router_ != nullptr)
        {
            route = co_await router_->decide_ip(ctx, target_endpoint.address());
        }
        LOG_CTX_INFO(ctx,
                     "{} udp route decision target {}:{} route {}",
                     log_event::kRoute,
                     target_endpoint.address().to_string(),
                     target_endpoint.port(),
                     mux::to_string(route));
        if (route == route_type::kBlock)
        {
            LOG_CTX_INFO(ctx, "{} udp blocked {}:{}", log_event::kRoute, target_endpoint.address().to_string(), target_endpoint.port());
            co_return;
        }

        const auto weak_self = weak_from_this();
        auto session = std::make_shared<tproxy_udp_session>(io_context_,
                                                            tunnel_pool_,
                                                            client_endpoint,
                                                            target_endpoint,
                                                            route,
                                                            ctx,
                                                            cfg_,
                                                            group_,
                                                            [weak_self, key]()
                                                            {
                                                                if (const auto self = weak_self.lock(); self != nullptr)
                                                                {
                                                                    self->erase_udp_session(key);
                                                                }
                                                            });
        udp_sessions_.emplace(key, session);
        session->start();
        session_it = udp_sessions_.find(key);
    }

    if (session_it == udp_sessions_.end() || session_it->second == nullptr)
    {
        co_return;
    }

    const auto enqueue_result = session_it->second->try_enqueue_packet(std::move(payload));
    if (enqueue_result == udp_enqueue_result::kClosed)
    {
        erase_udp_session(key);
    }
}

void tproxy_client::erase_udp_session(const std::string& key)
{
    udp_sessions_.erase(key);
}

std::string tproxy_client::make_udp_session_key(const boost::asio::ip::udp::endpoint& client_endpoint,
                                                const boost::asio::ip::udp::endpoint& target_endpoint)
{
    const auto normalized_client = net::normalize_endpoint(client_endpoint);
    const auto normalized_target = net::normalize_endpoint(target_endpoint);
    return normalized_client.address().to_string() + "|" + std::to_string(normalized_client.port()) + "->" +
           normalized_target.address().to_string() + "|" + std::to_string(normalized_target.port());
}

}    // namespace mux
