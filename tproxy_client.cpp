#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_client.h"

namespace mux
{

tproxy_client::tproxy_client(io_context_pool& pool, const config& cfg)
    : io_context_(pool.get_io_context()),
      tcp_acceptor_(io_context_),
      udp_socket_(io_context_),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, cfg.tproxy.mark)),
      router_(std::make_shared<router>()),
      sender_(std::make_shared<tproxy_udp_sender>(io_context_, cfg.tproxy.mark)),
      cfg_(cfg),
      tproxy_config_(cfg.tproxy),
      tcp_port_(cfg.tproxy.tcp_port),
      udp_port_(cfg.tproxy.udp_port == 0 ? cfg.tproxy.tcp_port : cfg.tproxy.udp_port),
      udp_idle_timeout_sec_(cfg.timeout.idle)
{
}

void tproxy_client::start()
{
    stop_.store(false, std::memory_order_release);
    if (!tproxy_config_.enabled)
    {
        LOG_INFO("tproxy client disabled");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (!tunnel_pool_->valid())
    {
        LOG_ERROR("invalid reality auth config");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (tcp_port_ == 0)
    {
        LOG_ERROR("tproxy tcp port invalid");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (udp_port_ == 0)
    {
        udp_port_ = tcp_port_;
    }

    tunnel_pool_->start();

    asio::co_spawn(io_context_, [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->accept_tcp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->udp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->udp_cleanup_loop(); }, asio::detached);
}

void tproxy_client::stop()
{
    LOG_INFO("tproxy client stopping closing resources");
    stop_.store(true, std::memory_order_release);

    asio::dispatch(io_context_,
                   [self = shared_from_this()]()
                   {
                       std::error_code close_ec;
                       close_ec = self->tcp_acceptor_.close(close_ec);
                       if (close_ec && close_ec != asio::error::bad_descriptor)
                       {
                           LOG_ERROR("tproxy acceptor close failed {}", close_ec.message());
                       }
                       close_ec = self->udp_socket_.close(close_ec);
                       if (close_ec && close_ec != asio::error::bad_descriptor)
                       {
                           LOG_ERROR("tproxy udp close failed {}", close_ec.message());
                       }

                       std::vector<std::shared_ptr<tproxy_udp_session>> sessions;
                       sessions.reserve(self->udp_sessions_.size());
                       for (auto& entry : self->udp_sessions_)
                       {
                           if (entry.second != nullptr)
                           {
                               sessions.push_back(entry.second);
                           }
                       }
                       self->udp_sessions_.clear();

                       for (auto& session : sessions)
                       {
                           if (session != nullptr)
                           {
                               session->stop();
                           }
                       }
                   });

    tunnel_pool_->stop();
}

std::string tproxy_client::endpoint_key(const asio::ip::udp::endpoint& ep) const
{
    return ep.address().to_string() + ":" + std::to_string(ep.port());
}

asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    const std::string listen_host = tproxy_config_.listen_host.empty() ? "::" : tproxy_config_.listen_host;
    std::error_code addr_ec;
    const auto listen_addr = asio::ip::make_address(listen_host, addr_ec);
    if (addr_ec)
    {
        LOG_ERROR("tproxy tcp parse address failed {}", addr_ec.message());
        co_return;
    }

    const asio::ip::tcp::endpoint ep{listen_addr, tcp_port_};
    std::error_code ec;
    ec = tcp_acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp open failed {}", ec.message());
        co_return;
    }
    ec = tcp_acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp reuse addr failed {}", ec.message());
        co_return;
    }
    if (listen_addr.is_v6())
    {
        ec = tcp_acceptor_.set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("tproxy tcp v6 only failed {}", ec.message());
            co_return;
        }
    }

    std::error_code trans_ec;
    if (!net::set_socket_transparent(tcp_acceptor_.native_handle(), listen_addr.is_v6(), trans_ec))
    {
        LOG_ERROR("tproxy tcp transparent failed {}", trans_ec.message());
        co_return;
    }

    ec = tcp_acceptor_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp bind failed {}", ec.message());
        co_return;
    }
    ec = tcp_acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp listen failed {}", ec.message());
        co_return;
    }

    LOG_INFO("tproxy tcp listening on {}:{}", listen_host, tcp_port_);

    while (!stop_.load(std::memory_order_acquire))
    {
        asio::ip::tcp::socket s(io_context_);
        const auto [e] = co_await tcp_acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            if (e == asio::error::operation_aborted)
            {
                break;
            }
            LOG_ERROR("tproxy tcp accept failed {}", e.message());
            asio::steady_timer accept_retry_timer(io_context_);
            accept_retry_timer.expires_after(std::chrono::seconds(1));
            co_await accept_retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
            continue;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            std::error_code close_ec;
            close_ec = s.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
            close_ec = s.close(close_ec);
            break;
        }

        ec = s.set_option(asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("tproxy tcp set no delay failed {}", ec.message());
        }

        const auto local_ep = s.local_endpoint(ec);
        if (ec)
        {
            LOG_ERROR("tproxy tcp local endpoint failed {}", ec.message());
            std::error_code close_ec;
            close_ec = s.close(close_ec);
            continue;
        }

        const asio::ip::tcp::endpoint dst_ep(net::normalize_address(local_ep.address()), local_ep.port());
        const std::uint32_t sid = tunnel_pool_->next_session_id();
        const auto session = std::make_shared<tproxy_tcp_session>(std::move(s), io_context_, tunnel_pool_, router_, sid, cfg_, dst_ep);
        session->start();
    }

    LOG_INFO("tproxy tcp accept loop exited");
}

asio::awaitable<void> tproxy_client::udp_loop()
{
    const std::string listen_host = tproxy_config_.listen_host.empty() ? "::" : tproxy_config_.listen_host;
    std::error_code addr_ec;
    const auto listen_addr = asio::ip::make_address(listen_host, addr_ec);
    if (addr_ec)
    {
        LOG_ERROR("tproxy udp parse address failed {}", addr_ec.message());
        co_return;
    }

    const asio::ip::udp::endpoint ep{listen_addr, udp_port_};
    std::error_code ec;
    ec = udp_socket_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("tproxy udp open failed {}", ec.message());
        co_return;
    }
    ec = udp_socket_.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp reuse addr failed {}", ec.message());
    }
    if (listen_addr.is_v6())
    {
        ec = udp_socket_.set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("tproxy udp v6 only failed {}", ec.message());
            co_return;
        }
    }

    std::error_code trans_ec;
    if (!net::set_socket_transparent(udp_socket_.native_handle(), listen_addr.is_v6(), trans_ec))
    {
        LOG_ERROR("tproxy udp transparent failed {}", trans_ec.message());
        co_return;
    }

    std::error_code recv_ec;
    if (!net::set_socket_recv_origdst(udp_socket_.native_handle(), listen_addr.is_v6(), recv_ec))
    {
        LOG_ERROR("tproxy udp recv origdst failed {}", recv_ec.message());
        co_return;
    }

    if (tproxy_config_.mark != 0)
    {
        std::error_code mark_ec;
        if (!net::set_socket_mark(udp_socket_.native_handle(), tproxy_config_.mark, mark_ec))
        {
            LOG_WARN("tproxy udp set mark failed {}", mark_ec.message());
        }
    }

    ec = udp_socket_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("tproxy udp bind failed {}", ec.message());
        co_return;
    }

    LOG_INFO("tproxy udp listening on {}:{}", listen_host, udp_port_);

    std::vector<std::uint8_t> buf(65535);
    std::array<char, 512> control;

    while (!stop_.load(std::memory_order_acquire))
    {
        const auto [wait_ec] = co_await udp_socket_.async_wait(asio::socket_base::wait_read, asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            if (wait_ec == asio::error::operation_aborted)
            {
                break;
            }
            LOG_ERROR("tproxy udp wait failed {}", wait_ec.message());
            continue;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            break;
        }

        sockaddr_storage src_addr{};
        iovec iov{};
        iov.iov_base = buf.data();
        iov.iov_len = buf.size();

        msghdr msg{};
        msg.msg_name = &src_addr;
        msg.msg_namelen = sizeof(src_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();

        const auto n = ::recvmsg(udp_socket_.native_handle(), &msg, 0);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            LOG_ERROR("tproxy udp recvmsg failed {}", std::strerror(errno));
            continue;
        }

        auto src_ep = net::endpoint_from_sockaddr(src_addr, msg.msg_namelen);
        src_ep = net::normalize_endpoint(src_ep);
        const auto dst_ep_opt = net::parse_original_dst(msg);
        if (!dst_ep_opt.has_value())
        {
            LOG_WARN("tproxy udp missing origdst");
            continue;
        }
        const auto dst_ep = net::normalize_endpoint(*dst_ep_opt);

        std::shared_ptr<tproxy_udp_session> session;
        const auto key = endpoint_key(src_ep);
        if (stop_.load(std::memory_order_acquire))
        {
            break;
        }
        auto it = udp_sessions_.find(key);
        if (it == udp_sessions_.end())
        {
            const std::uint32_t sid = tunnel_pool_->next_session_id();
            session = std::make_shared<tproxy_udp_session>(io_context_, tunnel_pool_, router_, sender_, sid, cfg_, src_ep);
            session->start();
            udp_sessions_.emplace(key, session);
        }
        else
        {
            session = it->second;
        }

        if (session != nullptr)
        {
            co_await session->handle_packet(dst_ep, buf.data(), static_cast<std::size_t>(n));
        }
    }

    LOG_INFO("tproxy udp loop exited");
}

asio::awaitable<void> tproxy_client::udp_cleanup_loop()
{
    asio::steady_timer cleanup_timer(io_context_);
    while (!stop_.load(std::memory_order_acquire))
    {
        cleanup_timer.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await cleanup_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            if (ec == asio::error::operation_aborted)
            {
                break;
            }
            continue;
        }

        if (udp_idle_timeout_sec_ == 0)
        {
            continue;
        }

        const auto now = std::chrono::steady_clock::now().time_since_epoch();
        const auto now_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
        const auto idle_ms = static_cast<std::uint64_t>(udp_idle_timeout_sec_) * 1000U;

        std::vector<std::shared_ptr<tproxy_udp_session>> expired_sessions;
        for (auto it = udp_sessions_.begin(); it != udp_sessions_.end();)
        {
            if (it->second != nullptr && it->second->is_idle(now_ms, idle_ms))
            {
                expired_sessions.push_back(it->second);
                it = udp_sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        for (auto& session : expired_sessions)
        {
            session->stop();
        }
    }
}

}    // namespace mux
