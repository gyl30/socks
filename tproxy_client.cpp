#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <system_error>
#include <sys/socket.h>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_client.h"

namespace mux
{

tproxy_client::tproxy_client(io_context_pool& pool, const config& cfg)
    : pool_(pool),
      tcp_acceptor_(pool.get_io_context()),
      udp_socket_(pool.get_io_context()),
      udp_cleanup_timer_(pool.get_io_context()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, cfg.tproxy.mark)),
      router_(std::make_shared<router>()),
      sender_(std::make_shared<tproxy_udp_sender>(pool.get_io_context().get_executor(), cfg.tproxy.mark)),
      cfg_(cfg),
      tproxy_config_(cfg.tproxy),
      tcp_port_(cfg.tproxy.tcp_port),
      udp_port_(cfg.tproxy.udp_port == 0 ? cfg.tproxy.tcp_port : cfg.tproxy.udp_port),
      udp_idle_timeout_sec_(cfg.timeout.idle)
{
}

void tproxy_client::start()
{
    if (!tproxy_config_.enabled)
    {
        LOG_INFO("tproxy client disabled");
        stop_ = true;
        return;
    }
    if (!tunnel_pool_->valid())
    {
        LOG_ERROR("invalid reality auth config");
        stop_ = true;
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        stop_ = true;
        return;
    }
    if (tcp_port_ == 0)
    {
        LOG_ERROR("tproxy tcp port invalid");
        stop_ = true;
        return;
    }
    if (udp_port_ == 0)
    {
        udp_port_ = tcp_port_;
    }

    tunnel_pool_->start();

    asio::co_spawn(pool_.get_io_context(),
                   [this, self = shared_from_this()]() -> asio::awaitable<void> { co_await accept_tcp_loop(); },
                   asio::detached);

    asio::co_spawn(pool_.get_io_context(),
                   [this, self = shared_from_this()]() -> asio::awaitable<void> { co_await udp_loop(); },
                   asio::detached);

    asio::co_spawn(pool_.get_io_context(),
                   [this, self = shared_from_this()]() -> asio::awaitable<void> { co_await udp_cleanup_loop(); },
                   asio::detached);
}

void tproxy_client::stop()
{
    LOG_INFO("tproxy client stopping closing resources");
    stop_ = true;
    std::error_code ec;
    ec = tcp_acceptor_.close(ec);
    if (ec)
    {
        LOG_ERROR("tproxy acceptor close failed {}", ec.message());
    }
    ec = udp_socket_.close(ec);
    if (ec)
    {
        LOG_ERROR("tproxy udp close failed {}", ec.message());
    }
    udp_cleanup_timer_.cancel();
    std::vector<std::shared_ptr<tproxy_udp_session>> sessions;
    {
        const std::lock_guard<std::mutex> lock(udp_mutex_);
        for (auto& entry : udp_sessions_)
        {
            if (entry.second != nullptr)
            {
                sessions.push_back(entry.second);
            }
        }
        udp_sessions_.clear();
    }
    for (auto& session : sessions)
    {
        session->stop();
    }
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

    while (!stop_)
    {
        asio::ip::tcp::socket s(pool_.get_io_context().get_executor());
        const auto [e] = co_await tcp_acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            if (e == asio::error::operation_aborted)
            {
                break;
            }
            LOG_ERROR("tproxy tcp accept failed {}", e.message());
            asio::steady_timer accept_retry_timer(pool_.get_io_context());
            accept_retry_timer.expires_after(std::chrono::seconds(1));
            co_await accept_retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
            continue;
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
        const auto session =
            std::make_shared<tproxy_tcp_session>(std::move(s), tunnel_pool_, router_, sid, cfg_, dst_ep);
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

    while (!stop_)
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
        {
            const std::lock_guard<std::mutex> lock(udp_mutex_);
            auto it = udp_sessions_.find(key);
            if (it == udp_sessions_.end())
            {
                const std::uint32_t sid = tunnel_pool_->next_session_id();
                session = std::make_shared<tproxy_udp_session>(udp_socket_.get_executor(), tunnel_pool_, router_, sender_, sid, cfg_, src_ep);
                session->start();
                udp_sessions_.emplace(key, session);
            }
            else
            {
                session = it->second;
            }
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
    while (!stop_)
    {
        udp_cleanup_timer_.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await udp_cleanup_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
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
        {
            const std::lock_guard<std::mutex> lock(udp_mutex_);
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
        }

        for (auto& session : expired_sessions)
        {
            session->stop();
        }
    }
}

}    // namespace mux
