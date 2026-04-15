#include <tuple>
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
#include "net_utils.h"
#include "context_pool.h"
#include "socks_inbound.h"
#include "socks_control_session.h"

namespace relay
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

socks_inbound::socks_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::socks_t& settings)
    : cfg_(cfg),
      inbound_tag_(std::move(inbound_tag)),
      settings_(settings),
      pool_(pool),
      owner_worker_(pool.get_io_worker()),
      router_(std::make_shared<relay::router>(cfg_, inbound_tag_))
{
}

void socks_inbound::start()
{
    if (!router_->load())
    {
        LOG_ERROR("{} stage start load router data failed", log_event::kConnInit);
        std::exit(EXIT_FAILURE);
    }
    LOG_INFO("{} inbound_tag {} listen {}:{} socks inbound starting listener",
             log_event::kConnInit,
             inbound_tag_,
             settings_.host,
             settings_.port);

    owner_worker_.group.spawn([self = shared_from_this()]() { return self->start_acceptor(); });
}

boost::asio::awaitable<void> socks_inbound::start_acceptor()
{
    boost::system::error_code ec;
    setup_acceptor(acceptor_, settings_.host, settings_.port, ec);
    if (ec)
    {
        LOG_ERROR("{} inbound_tag {} stage start listen {}:{} setup failed {}",
                  log_event::kConnInit,
                  inbound_tag_,
                  settings_.host,
                  settings_.port,
                  ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("{} inbound_tag {} listen {}:{} socks listening", log_event::kConnInit, inbound_tag_, settings_.host, settings_.port);
    co_await accept_loop();
    co_return;
}

boost::asio::awaitable<void> socks_inbound::accept_loop()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto& socket_worker = pool_.get_io_worker();
        boost::asio::ip::tcp::socket socket(socket_worker.io_context);
        co_await acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted)
        {
            LOG_INFO("{} inbound_tag {} listen {}:{} accept loop stopped {}",
                     log_event::kConnClose,
                     inbound_tag_,
                     settings_.host,
                     settings_.port,
                     ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("{} inbound_tag {} listen {}:{} stage accept error {} retry",
                      log_event::kConnInit,
                      inbound_tag_,
                      settings_.host,
                      settings_.port,
                      ec.message());
            ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::seconds(3));
            if (ec)
            {
                LOG_ERROR("{} inbound_tag {} listen {}:{} stage accept_retry_wait error {}",
                          log_event::kConnInit,
                          inbound_tag_,
                          settings_.host,
                          settings_.port,
                          ec.message());
                break;
            }
            continue;
        }

        const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
        std::string local_host;
        std::string remote_host;
        uint16_t local_port = 0;
        uint16_t remote_port = 0;
        boost::system::error_code local_ep_ec;
        boost::system::error_code remote_ep_ec;
        net::load_tcp_socket_endpoints(socket, local_host, local_port, remote_host, remote_port, &local_ep_ec, &remote_ep_ec);
        if (local_ep_ec)
        {
            LOG_WARN("{} conn {} stage query_local_endpoint error {}", log_event::kConnInit, sid, local_ep_ec.message());
        }
        if (remote_ep_ec)
        {
            LOG_WARN("{} conn {} stage query_remote_endpoint error {}", log_event::kConnInit, sid, remote_ep_ec.message());
        }
        LOG_INFO("{} conn {} local {}:{} remote {}:{} accepted", log_event::kConnInit, sid, local_host, local_port, remote_host, remote_port);
        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("{} conn {} local {}:{} remote {}:{} stage set_no_delay error {}",
                     log_event::kSocks,
                     sid,
                     local_host,
                     local_port,
                     remote_host,
                     remote_port,
                     ec.message());
        }
        std::make_shared<socks_control_session>(std::move(socket), socket_worker, router_, sid, cfg_, settings_)->start();
    }
    LOG_INFO("{} inbound_tag {} listen {}:{} accept loop exited", log_event::kConnClose, inbound_tag_, settings_.host, settings_.port);
}

void socks_inbound::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(
        owner_worker_.io_context,
        [self = shared_from_this()]()
        {
            boost::system::error_code ec;
            ec = self->acceptor_.close(ec);
            if (ec && ec != boost::asio::error::bad_descriptor)
            {
                LOG_ERROR("{} inbound_tag {} listen {}:{} acceptor close failed {}",
                          log_event::kConnClose,
                          self->inbound_tag_,
                          self->settings_.host,
                          self->settings_.port,
                          ec.message());
            }
        });
}

}    // namespace relay
