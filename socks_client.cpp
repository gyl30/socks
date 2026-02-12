#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "socks_client.h"
#include "socks_session.h"

namespace mux
{

namespace
{

void close_local_socket(asio::ip::tcp::socket& socket)
{
    std::error_code close_ec;
    close_ec = socket.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
    close_ec = socket.close(close_ec);
}

bool setup_local_acceptor(asio::ip::tcp::acceptor& acceptor,
                          const asio::ip::address& listen_addr,
                          const std::uint16_t port,
                          std::uint16_t& bound_port,
                          std::error_code& ec)
{
    const asio::ip::tcp::endpoint ep{listen_addr, port};
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return false;
    }
    ec = acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return false;
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        return false;
    }
    bound_port = acceptor.local_endpoint().port();
    ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
    return !ec;
}

void log_accept_error(const std::error_code& ec)
{
    LOG_ERROR("local accept failed {}", ec.message());
}

void set_no_delay_or_log(asio::ip::tcp::socket& socket)
{
    std::error_code ec;
    ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("failed to set no delay on local socket {}", ec.message());
    }
}

void prune_expired_sessions(std::vector<std::weak_ptr<socks_session>>& sessions)
{
    for (auto it = sessions.begin(); it != sessions.end();)
    {
        if (it->expired())
        {
            it = sessions.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

asio::awaitable<std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> wait_for_tunnel_ready(asio::io_context& io_context,
                                                                                                std::shared_ptr<client_tunnel_pool> pool,
                                                                                                const std::atomic<bool>& stop)
{
    auto selected_tunnel = pool->select_tunnel();
    if (selected_tunnel != nullptr)
    {
        co_return selected_tunnel;
    }

    asio::steady_timer tunnel_wait_timer(io_context);
    for (std::uint32_t attempt = 0; attempt < 6 && !stop.load(std::memory_order_acquire) && selected_tunnel == nullptr; ++attempt)
    {
        tunnel_wait_timer.expires_after(std::chrono::milliseconds(200));
        const auto [wait_ec] = co_await tunnel_wait_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        selected_tunnel = pool->select_tunnel();
    }

    co_return selected_tunnel;
}

}    // namespace

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : listen_port_(cfg.socks.port),
      io_context_(pool.get_io_context()),
      acceptor_(io_context_),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, 0)),
      timeout_config_(cfg.timeout),
      socks_config_(cfg.socks)
{
}

void socks_client::start()
{
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
    if (!socks_config_.enabled)
    {
        LOG_INFO("socks client disabled");
        stop_.store(true, std::memory_order_release);
        return;
    }

    tunnel_pool_->start();

    asio::co_spawn(io_context_, [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->accept_local_loop(); }, asio::detached);
}

void socks_client::stop()
{
    LOG_INFO("client stopping closing resources");
    stop_.store(true, std::memory_order_release);

    asio::dispatch(io_context_,
                   [self = shared_from_this()]()
                   {
                       std::error_code close_ec;
                       close_ec = self->acceptor_.close(close_ec);
                       if (close_ec && close_ec != asio::error::bad_descriptor)
                       {
                           LOG_ERROR("acceptor close failed {}", close_ec.message());
                       }

                       std::vector<std::shared_ptr<socks_session>> sessions_to_stop;
                       sessions_to_stop.reserve(self->sessions_.size());
                       for (auto it = self->sessions_.begin(); it != self->sessions_.end();)
                       {
                           if (auto session = it->lock())
                           {
                               sessions_to_stop.push_back(std::move(session));
                               ++it;
                           }
                           else
                           {
                               it = self->sessions_.erase(it);
                           }
                       }
                       self->sessions_.clear();

                       for (const auto& session : sessions_to_stop)
                       {
                           if (session != nullptr)
                           {
                               session->stop();
                           }
                       }
                   });

    tunnel_pool_->stop();
}

asio::awaitable<void> socks_client::accept_local_loop()
{
    std::error_code addr_ec;
    const auto listen_addr = asio::ip::make_address(socks_config_.host, addr_ec);
    if (addr_ec)
    {
        LOG_ERROR("local acceptor parse address failed {}", addr_ec.message());
        co_return;
    }
    std::error_code ec;
    std::uint16_t bound_port = 0;
    if (!setup_local_acceptor(acceptor_, listen_addr, listen_port_, bound_port, ec))
    {
        LOG_ERROR("local acceptor setup failed {}", ec.message());
        co_return;
    }
    listen_port_.store(bound_port, std::memory_order_release);

    LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));
    while (!stop_.load(std::memory_order_acquire))
    {
        asio::ip::tcp::socket s(io_context_);
        const auto [e] = co_await acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            if (e == asio::error::operation_aborted)
            {
                break;
            }
            log_accept_error(e);
            asio::steady_timer accept_retry_timer(io_context_);
            accept_retry_timer.expires_after(std::chrono::seconds(1));
            co_await accept_retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
            continue;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            close_local_socket(s);
            break;
        }

        set_no_delay_or_log(s);

        auto selected_tunnel = co_await wait_for_tunnel_ready(io_context_, tunnel_pool_, stop_);
        if (stop_.load(std::memory_order_acquire))
        {
            close_local_socket(s);
            break;
        }
        if (selected_tunnel == nullptr)
        {
            LOG_WARN("accepting local connection without active tunnel");
        }
        const std::uint32_t sid = tunnel_pool_->next_session_id();
        if (selected_tunnel != nullptr)
        {
            LOG_INFO("client session {} selected tunnel", sid);
        }
        else
        {
            LOG_INFO("client session {} running without tunnel", sid);
        }
        const auto session =
            std::make_shared<socks_session>(std::move(s), io_context_, selected_tunnel, router_, sid, socks_config_, timeout_config_);
        if (stop_.load(std::memory_order_acquire))
        {
            session->stop();
            break;
        }

        prune_expired_sessions(sessions_);
        sessions_.push_back(session);
        session->start();
    }
    LOG_INFO("accept local loop exited");
}

}    // namespace mux
