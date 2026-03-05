#include <cerrno>
#include <memory>
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
    if (auto r = net::set_socket_transparent(acceptor.native_handle(), is_v6); !r)
    {
        ec = r.error();
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

    if (cfg_.tproxy.tcp_port == 0)
    {
        LOG_ERROR("tproxy port invalid");
        return;
    }

    auto self = shared_from_this();
    boost::asio::co_spawn(io_context_, [self]() { return self->accept_tcp_loop(); }, group_.adapt(boost::asio::detached));
}

void tproxy_client::stop()
{
    LOG_INFO("tproxy client stopping closing resources");

    boost::system::error_code ec;
    ec = tcp_acceptor_.close(ec);

    if (tunnel_pool_ != nullptr)
    {
        tunnel_pool_->stop();
    }

    group_.emit(boost::asio::cancellation_type::all);
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
    LOG_INFO("tproxy udp is not implemented only tcp listener is active");

    tunnel_pool_->start();

    while (true)
    {
        boost::asio::ip::tcp::socket socket(io_context_);
        co_await tcp_acceptor_.async_accept(socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_ERROR("tproxy tcp accept failed {}", ec.message());
            break;
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

}    // namespace mux
