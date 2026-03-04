#include <chrono>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "upstream.h"
#include "net_utils.h"
#include "statistics.h"
#include "timeout_io.h"
#include "log_context.h"
#include "client_tunnel_pool.h"
#include "tproxy_tcp_session.h"

namespace mux
{

tproxy_tcp_session::tproxy_tcp_session(boost::asio::ip::tcp::socket socket,
                                       boost::asio::io_context& io_context,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       std::shared_ptr<router> router,
                                       const std::uint32_t sid,
                                       const config& cfg,
                                       task_group& group)
    : io_context_(io_context),
      socket_(std::move(socket)),
      idle_timer_(io_context_),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      cfg_(cfg),
      group_(group)

{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_ = timeout_io::now_ms();
}

void tproxy_tcp_session::start()
{
    auto self = shared_from_this();
    boost::asio::co_spawn(io_context_, [this, self]() -> boost::asio::awaitable<void> { co_await run(); }, group_.adapt(boost::asio::detached));
}

void tproxy_tcp_session::stop() {}

boost::asio::awaitable<void> tproxy_tcp_session::run()
{
    boost::system::error_code ec;
    const auto local_ep = socket_.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp local endpoint failed {}", ec.message());
        co_return;
    }
    boost::system::error_code peer_ec;
    const auto peer_ep = socket_.remote_endpoint(peer_ec);
    auto local_addr = net::normalize_address(local_ep.address());
    const auto port = local_ep.port();
    ctx_.local_addr(local_addr.to_string());
    ctx_.local_port(port);
    if (!peer_ec)
    {
        ctx_.remote_addr(peer_ep.address().to_string());
        ctx_.remote_port(peer_ep.port());
    }
    LOG_CTX_INFO(ctx_,
                 "{} redirected flow client {}:{} -> target {}:{}",
                 log_event::kConnInit,
                 ctx_.remote_addr(),
                 ctx_.remote_port(),
                 local_addr.to_string(),
                 port);
    const auto [route, backend] = co_await select_backend(local_addr);
    if (backend == nullptr)
    {
        co_return;
    }
    LOG_CTX_INFO(ctx_, "{} selecting backend route {}", log_event::kRoute, mux::to_string(route));
    co_await backend->connect(local_addr.to_string(), port, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_,
                     "{} backend connect failed target {}:{} route {} error {}",
                     log_event::kConnInit,
                     local_addr.to_string(),
                     port,
                     mux::to_string(route),
                     ec.message());
        co_await backend->close();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, local_addr.to_string(), port, mux::to_string(route));

    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_upstream(backend) || upstream_to_client(backend));
    }
    else
    {
        co_await (client_to_upstream(backend) || upstream_to_client(backend) || idle_watchdog());
    }

    co_await backend->close();

    ec = socket_.close(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} close client failed {}", log_event::kSocks, ec.message());
    }
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

boost::asio::awaitable<std::pair<route_type, std::shared_ptr<upstream>>> tproxy_tcp_session::select_backend(const boost::asio::ip::address& addr)
{
    if (router_ == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} router unavailable", log_event::kRoute);
        statistics::instance().inc_routing_blocked();
        co_return std::make_pair(route_type::kBlock, std::shared_ptr<upstream>(nullptr));
    }

    const auto route = co_await router_->decide_ip(ctx_, addr);
    if (route == route_type::kBlock)
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, addr.to_string());
        statistics::instance().inc_routing_blocked();
        co_return std::make_pair(route, std::shared_ptr<upstream>(nullptr));
    }
    if (route == route_type::kDirect)
    {
        const std::shared_ptr<upstream> backend = std::make_shared<direct_upstream>(io_context_, ctx_, cfg_);
        co_return std::make_pair(route, backend);
    }
    if (route == route_type::kProxy)
    {
        const auto tunnel = tunnel_pool_->select_tunnel();
        if (tunnel == nullptr)
        {
            LOG_CTX_WARN(ctx_, "{} no active tunnel for proxy route", log_event::kRoute);
        }
        const std::shared_ptr<upstream> backend = std::make_shared<proxy_upstream>(tunnel, ctx_, cfg_);
        co_return std::make_pair(route, backend);
    }
    co_return std::make_pair(route_type::kBlock, std::shared_ptr<upstream>(nullptr));
}

boost::asio::awaitable<void> tproxy_tcp_session::client_to_upstream(std::shared_ptr<upstream> backend)
{
    std::vector<std::uint8_t> buf(8192);
    boost::system::error_code ec;
    for (;;)
    {
        const std::size_t n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            LOG_CTX_INFO(ctx_, "{} client read finished {}", log_event::kSocks, ec.message());
            break;
        }
        std::vector<std::uint8_t> data_buf(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await backend->write(data_buf, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to backend {}", log_event::kSocks, ec.message());
            break;
        }
        ctx_.add_tx_bytes(n);
        last_activity_time_ms_ = timeout_io::now_ms();
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::kSocks);
}

boost::asio::awaitable<void> tproxy_tcp_session::upstream_to_client(std::shared_ptr<upstream> backend)
{
    std::vector<std::uint8_t> buf(8192);
    boost::system::error_code ec;
    for (;;)
    {
        const auto n = co_await backend->read(buf, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from backend {} code {}", log_event::kSocks, ec.message(), ec.value());
            break;
        }
        boost::system::error_code write_ec;
        auto write_size = co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(buf.data(), n), cfg_.timeout.write, write_ec);
        if (write_ec)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to client {} bytes {} error {}", log_event::kSocks, n, write_ec.value(), write_ec.message());
            break;
        }
        ctx_.add_rx_bytes(write_size);
        last_activity_time_ms_ = timeout_io::now_ms();
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::kSocks);
}

boost::asio::awaitable<void> tproxy_tcp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;

    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = timeout_io::now_ms() - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            break;
        }
    }
    boost::system::error_code ec;
    ec = socket_.close(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} close client failed {}", log_event::kSocks, ec.message());
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} tcp session idle closing", log_event::kSocks);
    }
}

}    // namespace mux
