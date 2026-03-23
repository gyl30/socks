#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "statistics.h"
#include "context_pool.h"
#include "socks_client.h"
#include "socks_session.h"
#include "client_tunnel_pool.h"

namespace mux
{

namespace
{

void setup_acceptor(boost::asio::ip::tcp::acceptor& acceptor, const std::string& host, const std::uint16_t port, boost::system::error_code& ec)
{
    const auto listen_addr = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        return;
    }
    const boost::asio::ip::tcp::endpoint ep{listen_addr, port};
    const bool enable_dual_stack = listen_addr.is_v6() && listen_addr.to_v6().is_unspecified();
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

}    // namespace

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : cfg_(cfg),
      ioc_(pool.get_io_context()),
      pool_(pool),
      groups_(pool),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, groups_))
{
}

int socks_client::start()
{
    auto tunnel_pool = tunnel_pool_;
    if (tunnel_pool == nullptr)
    {
        LOG_ERROR("tunnel pool unavailable");
        std::exit(EXIT_FAILURE);
    }

    auto router = router_;
    if (router == nullptr)
    {
        LOG_ERROR("router unavailable");
        std::exit(EXIT_FAILURE);
    }

    if (!router->load())
    {
        LOG_ERROR("failed to load router data");
        std::exit(EXIT_FAILURE);
    }
    if (!cfg_.socks.enabled)
    {
        LOG_INFO("socks client disabled");
        return 0;
    }

    boost::system::error_code ec;
    setup_acceptor(acceptor_, cfg_.socks.host, cfg_.socks.port, ec);
    if (ec)
    {
        LOG_ERROR("socks5 setup {}:{} failed {}", cfg_.socks.host, cfg_.socks.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    LOG_INFO("local socks5 listening on {}:{}", cfg_.socks.host, cfg_.socks.port);

    tunnel_pool->start();

    boost::asio::co_spawn(ioc_, accept_loop(), groups_.get(ioc_).adapt(boost::asio::detached));
    return 0;
}

boost::asio::awaitable<void> socks_client::accept_loop()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto& socket_io = pool_.get_io_context();
        auto& socket_group = groups_.get(socket_io);
        boost::asio::ip::tcp::socket socket(socket_io);
        co_await acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_WARN("socks5 accept cancelled {}", ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("socks5 accept failed {} retry", ec.message());
            boost::asio::steady_timer retry_timer(ioc_);
            retry_timer.expires_after(std::chrono::seconds(3));
            co_await retry_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                LOG_ERROR("accept retry timer error {}", ec.message());
                break;
            }
            continue;
        }

        auto& stats = statistics::instance();
        if (stats.active_connections() >= resolve_client_session_max_connections(cfg_.limits))
        {
            stats.inc_connection_limit_rejected();
            boost::system::error_code close_ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
            socket.close(close_ec);
            LOG_WARN("socks5 connection limit reached drop");
            continue;
        }

        boost::system::error_code ec;
        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("failed to set no delay on local socket {}", ec.message());
        }
        const std::uint32_t sid = tunnel_pool_->next_session_id();
        std::make_shared<socks_session>(std::move(socket), socket_io, tunnel_pool_, router_, sid, cfg_, socket_group)->start();
    }
    LOG_INFO("local socks5 acceptor stopped");
}

void socks_client::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(
        ioc_,
        [self = shared_from_this()]()
        {
            boost::system::error_code ec;
            ec = self->acceptor_.close(ec);
            if (ec && ec != boost::asio::error::bad_descriptor)
            {
                LOG_ERROR("acceptor close error {}", ec.message());
            }
            if (self->tunnel_pool_ != nullptr)
            {
                self->tunnel_pool_->stop();
            }
            self->groups_.emit_all(::boost::asio::cancellation_type::all);
        });
}

boost::asio::awaitable<void> socks_client::wait_stopped()
{
    co_await groups_.async_wait_all();
}

}    // namespace mux
