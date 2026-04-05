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
#include "socks_client.h"
#include "socks_session.h"
#include "client_tunnel_pool.h"
namespace mux
{

namespace
{

std::pair<std::string, uint16_t> endpoint_parts(const boost::asio::ip::tcp::endpoint& endpoint)
{
    return {endpoint.address().to_string(), endpoint.port()};
}

void load_socket_endpoints(boost::asio::ip::tcp::socket& socket,
                           uint32_t conn_id,
                           std::string& local_host,
                           uint16_t& local_port,
                           std::string& remote_host,
                           uint16_t& remote_port)
{
    local_host = "unknown";
    local_port = 0;
    remote_host = "unknown";
    remote_port = 0;

    boost::system::error_code local_ec;
    const auto local_endpoint = socket.local_endpoint(local_ec);
    if (local_ec)
    {
        LOG_WARN("event {} conn_id {} stage query_local_endpoint error {}", log_event::kConnInit, conn_id, local_ec.message());
    }
    else
    {
        std::tie(local_host, local_port) = endpoint_parts(local_endpoint);
    }

    boost::system::error_code remote_ec;
    const auto remote_endpoint = socket.remote_endpoint(remote_ec);
    if (remote_ec)
    {
        LOG_WARN("event {} conn_id {} stage query_remote_endpoint error {}", log_event::kConnInit, conn_id, remote_ec.message());
    }
    else
    {
        std::tie(remote_host, remote_port) = endpoint_parts(remote_endpoint);
    }
}

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

socks_client::socks_client(io_context_pool& pool, const config& cfg, std::shared_ptr<client_tunnel_pool> tunnel_pool)
    : cfg_(cfg),
      pool_(pool),
      owner_worker_(pool.get_io_worker()),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(tunnel_pool != nullptr ? std::move(tunnel_pool) : std::make_shared<client_tunnel_pool>(pool, cfg))
{
}

void socks_client::start()
{
    if (!router_->load())
    {
        LOG_ERROR("event {} stage start load router data failed", log_event::kConnInit);
        std::exit(EXIT_FAILURE);
    }
    if (!cfg_.socks.enabled)
    {
        LOG_INFO("event {} stage start socks client disabled", log_event::kConnInit);
        return;
    }

    LOG_INFO("event {} listen {}:{} socks client starting listener", log_event::kConnInit, cfg_.socks.host, cfg_.socks.port);

    owner_worker_.group.spawn([self = shared_from_this()]() { return self->start_acceptor(); });
}

boost::asio::awaitable<void> socks_client::start_acceptor()
{
    boost::system::error_code ec;
    setup_acceptor(acceptor_, cfg_.socks.host, cfg_.socks.port, ec);
    if (ec)
    {
        LOG_ERROR("event {} stage start listen {}:{} setup failed {}", log_event::kConnInit, cfg_.socks.host, cfg_.socks.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("event {} listen {}:{} socks listening", log_event::kConnInit, cfg_.socks.host, cfg_.socks.port);
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
            LOG_INFO("event {} listen {}:{} accept loop stopped {}", log_event::kConnClose, cfg_.socks.host, cfg_.socks.port, ec.message());
            break;
        }
        if (ec)
        {
            LOG_ERROR("event {} listen {}:{} stage accept error {} retry", log_event::kConnInit, cfg_.socks.host, cfg_.socks.port, ec.message());
            ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::seconds(3));
            if (ec)
            {
                LOG_ERROR(
                    "event {} listen {}:{} stage accept_retry_wait error {}", log_event::kConnInit, cfg_.socks.host, cfg_.socks.port, ec.message());
                break;
            }
            continue;
        }

        const uint32_t sid = next_session_id_.fetch_add(1, std::memory_order_relaxed);
        std::string local_host;
        std::string remote_host;
        uint16_t local_port = 0;
        uint16_t remote_port = 0;
        load_socket_endpoints(socket, sid, local_host, local_port, remote_host, remote_port);
        LOG_INFO(
            "event {} conn_id {} local {}:{} remote {}:{} accepted", log_event::kConnInit, sid, local_host, local_port, remote_host, remote_port);
        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} stage set_no_delay error {}",
                     log_event::kSocks,
                     sid,
                     local_host,
                     local_port,
                     remote_host,
                     remote_port,
                     ec.message());
        }
        std::make_shared<socks_session>(std::move(socket), socket_worker, tunnel_pool_, router_, sid, cfg_)->start();
    }
    LOG_INFO("event {} listen {}:{} accept loop exited", log_event::kConnClose, cfg_.socks.host, cfg_.socks.port);
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
                              LOG_ERROR("event {} listen {}:{} acceptor close failed {}",
                                        log_event::kConnClose,
                                        self->cfg_.socks.host,
                                        self->cfg_.socks.port,
                                        ec.message());
                          }
                      });
}

}    // namespace mux
