#include <chrono>
#include <memory>
#include <string>
#include <cstdint>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "socks_client.h"
#include "socks_session.h"

namespace mux
{

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : pool_(pool),
      listen_port_(cfg.socks.port),
      acceptor_(pool.get_io_context()),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, 0)),
      stop_channel_(pool.get_io_context(), 1),
      timeout_config_(cfg.timeout),
      socks_config_(cfg.socks)
{
}

void socks_client::start()
{
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
    if (!socks_config_.enabled)
    {
        LOG_INFO("socks client disabled");
        stop_ = true;
        return;
    }

    tunnel_pool_->start();

    asio::co_spawn(
        pool_.get_io_context(),
        [this, self = shared_from_this()]() -> asio::awaitable<void>
        {
            using asio::experimental::awaitable_operators::operator||;
            co_await (accept_local_loop() || wait_stop());
        },
        asio::detached);
}

void socks_client::stop()
{
    LOG_INFO("client stopping closing resources");
    stop_ = true;
    std::error_code ec;
    ec = acceptor_.close(ec);
    if (ec)
    {
        LOG_ERROR("acceptor close failed {}", ec.message());
    }
    stop_channel_.cancel();
    tunnel_pool_->stop();
}

asio::awaitable<void> socks_client::wait_stop()
{
    const auto [ec, msg] = co_await stop_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("stop error {}", ec.message());
    }
    stop_ = true;
    LOG_INFO("stop channel received");
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
    listen_port_ = acceptor_.local_endpoint().port();
    ec = acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("local acceptor listen failed {}", ec.message());
        co_return;
    }

    LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_);
    while (!stop_)
    {
        asio::ip::tcp::socket s(pool_.get_io_context().get_executor());
        const auto [e] = co_await acceptor_.async_accept(s, asio::as_tuple(asio::use_awaitable));
        if (e)
        {
            if (e == asio::error::operation_aborted)
            {
                break;
            }
            LOG_ERROR("local accept failed {}", e.message());
            asio::steady_timer accept_retry_timer(pool_.get_io_context());
            accept_retry_timer.expires_after(std::chrono::seconds(1));
            co_await accept_retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
            continue;
        }

        ec = s.set_option(asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("failed to set no delay on local socket {}", ec.message());
        }

        const auto selected_tunnel = tunnel_pool_->select_tunnel();
        if (selected_tunnel != nullptr)
        {
            const std::uint32_t sid = tunnel_pool_->next_session_id();
            LOG_INFO("client session {} selected tunnel", sid);
            const auto session = std::make_shared<socks_session>(std::move(s), selected_tunnel, router_, sid, socks_config_, timeout_config_);
            session->start();
        }
        else
        {
            LOG_WARN("rejecting local connection no active tunnel");
            std::error_code close_ec;
            close_ec = s.close(close_ec);
            LOG_WARN("local connection closed {}", close_ec.message());
        }
    }
    LOG_INFO("accept local loop exited");
}

}    // namespace mux
