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

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : listen_port_(cfg.socks.port),
      ex_(pool.get_io_context().get_executor()),
      acceptor_(ex_),
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

    asio::co_spawn(ex_, [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->accept_local_loop(); }, asio::detached);
}

void socks_client::stop()
{
    LOG_INFO("client stopping closing resources");
    stop_.store(true, std::memory_order_release);

    asio::dispatch(ex_,
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
    const asio::ip::tcp::endpoint ep{listen_addr, listen_port_};
    std::error_code ec;
    ec = acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("local acceptor open failed {}", ec.message());
        co_return;
    }
    ec = acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("local acceptor set reuse address failed {}", ec.message());
        co_return;
    }
    ec = acceptor_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("local acceptor bind failed {}", ec.message());
        co_return;
    }
    listen_port_.store(acceptor_.local_endpoint().port(), std::memory_order_release);
    ec = acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("local acceptor listen failed {}", ec.message());
        co_return;
    }

    LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));
    while (!stop_.load(std::memory_order_acquire))
    {
        asio::ip::tcp::socket s(ex_);
        const auto [e] = co_await acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            if (e == asio::error::operation_aborted)
            {
                break;
            }
            LOG_ERROR("local accept failed {}", e.message());
            asio::steady_timer accept_retry_timer(ex_);
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
            LOG_WARN("failed to set no delay on local socket {}", ec.message());
        }

        auto selected_tunnel = tunnel_pool_->select_tunnel();
        if (selected_tunnel == nullptr)
        {
            asio::steady_timer tunnel_wait_timer(acceptor_.get_executor());
            for (std::uint32_t attempt = 0; attempt < 6 && !stop_.load(std::memory_order_acquire) && selected_tunnel == nullptr; ++attempt)
            {
                tunnel_wait_timer.expires_after(std::chrono::milliseconds(200));
                const auto [wait_ec] = co_await tunnel_wait_timer.async_wait(asio::as_tuple(asio::use_awaitable));
                if (wait_ec)
                {
                    break;
                }
                selected_tunnel = tunnel_pool_->select_tunnel();
            }
        }
        if (stop_.load(std::memory_order_acquire))
        {
            std::error_code close_ec;
            close_ec = s.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
            close_ec = s.close(close_ec);
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
        const auto session = std::make_shared<socks_session>(std::move(s), selected_tunnel, router_, sid, socks_config_, timeout_config_);
        if (stop_.load(std::memory_order_acquire))
        {
            session->stop();
            break;
        }

        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (it->expired())
            {
                it = sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }
        sessions_.push_back(session);
        session->start();
    }
    LOG_INFO("accept local loop exited");
}

}    // namespace mux
