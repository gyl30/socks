#include <chrono>
#include <memory>
#include <string>
#include <cstdlib>
#include <utility>

#include <boost/asio.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "context_pool.h"
#include "net_utils.h"
#include "socks_client.h"
#include "socks_session.h"
#include "client_tunnel_pool.h"

namespace mux
{

namespace
{

void setup_acceptor(boost::asio::ip::tcp::acceptor& acceptor, const std::string& host, uint16_t port, boost::system::error_code& ec)
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
      pool_(pool),
      owner_worker_(pool.get_io_worker()),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg))
{
}

void socks_client::start()
{
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        std::exit(EXIT_FAILURE);
    }
    if (!cfg_.socks.enabled)
    {
        LOG_INFO("socks client disabled");
        return;
    }

    tunnel_pool_->start();
    LOG_INFO("local socks5 starting listener on {}:{}", cfg_.socks.host, cfg_.socks.port);

    owner_worker_.group.spawn([self = shared_from_this()]() { return self->start_acceptor(); });
}

boost::asio::awaitable<void> socks_client::start_acceptor()
{
    boost::system::error_code ec;
    setup_acceptor(acceptor_, cfg_.socks.host, cfg_.socks.port, ec);
    if (ec)
    {
        LOG_ERROR("socks5 setup {}:{} failed {}", cfg_.socks.host, cfg_.socks.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("local socks5 listening on {}:{}", cfg_.socks.host, cfg_.socks.port);
    co_await accept_loop();
    co_return;
}

boost::asio::awaitable<void> socks_client::accept_loop()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto& socket_worker = pool_.get_io_worker();
        boost::asio::ip::tcp::socket socket(socket_worker.io_context);
        co_await acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_WARN("socks5 accept cancelled {}", ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("socks5 accept failed {} retry", ec.message());
            ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::seconds(3));
            if (ec)
            {
                LOG_ERROR("accept retry timer error {}", ec.message());
                break;
            }
            continue;
        }

        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("failed to set no delay on local socket {}", ec.message());
        }
        const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
        std::make_shared<socks_session>(std::move(socket), socket_worker, tunnel_pool_, router_, sid, cfg_)->start();
    }
    LOG_INFO("local socks5 acceptor stopped");
}

void socks_client::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(owner_worker_.io_context,
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
                      });
}

}    // namespace mux
