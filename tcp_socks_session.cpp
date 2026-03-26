#include <chrono>
#include <memory>
#include <string>
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
#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "upstream.h"
#include "timeout_io.h"
#include "scoped_exit.h"
#include "connection_context.h"
#include "tcp_socks_session.h"

namespace mux
{

namespace
{

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

}    // namespace

tcp_socks_session::tcp_socks_session(boost::asio::ip::tcp::socket socket,
                                     boost::asio::io_context& io_context,
                                     std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                     std::shared_ptr<router> router,
                                     const std::uint32_t sid,
                                     const config& cfg,
                                     task_group& group,
                                     std::shared_ptr<void> active_connection_guard)
    : cfg_(cfg),
      group_(group),
      io_context_(io_context),
      socket_(std::move(socket)),
      idle_timer_(io_context_),
      router_(std::move(router)),
      tunnel_pool_(std::move(tunnel_pool)),
      active_connection_guard_(std::move(active_connection_guard))
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_ = now_ms();
}

void tcp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    boost::asio::co_spawn(
        io_context_,
        [self = shared_from_this(), host = host, port = port]() -> boost::asio::awaitable<void> { co_return co_await self->run(host, port); },
        group_.adapt(boost::asio::detached));
}

void tcp_socks_session::stop() { close_client_socket(); }

boost::asio::awaitable<void> tcp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    DEFER(close_client_socket());

    if (router_ == nullptr)
    {
        LOG_CTX_ERROR(ctx_, "{} router unavailable", log_event::kRoute);
        co_await reply_error(socks::kRepGenFail);
        co_return;
    }

    boost::system::error_code parse_ec;
    const auto target_addr = boost::asio::ip::make_address(host, parse_ec);
    route_type route = route_type::kProxy;
    if (parse_ec)
    {
        route = co_await router_->decide_domain(ctx_, host);
    }
    else
    {
        route = co_await router_->decide_ip(ctx_, target_addr);
    }

    const auto backend = create_backend(route);
    if (backend == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::kRoute, host);
        co_await reply_error(socks::kRepNotAllowed);
        co_return;
    }
    if (!co_await connect_backend(backend, host, port, route))
    {
        co_await backend->close();
        co_return;
    }

    if (!co_await reply_success(backend))
    {
        co_await backend->close();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::kConnEstablished, host, port, mux::to_string(route));

    using boost::asio::experimental::awaitable_operators::operator&&;
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (client_to_upstream(backend) && upstream_to_client(backend));
    }
    else
    {
        co_await ((client_to_upstream(backend) && upstream_to_client(backend)) || idle_watchdog(backend));
    }

    co_await backend->close();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

std::shared_ptr<upstream> tcp_socks_session::create_backend(const route_type route) const
{
    if (route == route_type::kDirect)
    {
        return std::make_shared<direct_upstream>(io_context_, ctx_, cfg_);
    }
    if (route == route_type::kProxy)
    {
        return std::make_shared<proxy_upstream>(tunnel_pool_, io_context_, ctx_, cfg_);
    }
    return nullptr;
}

boost::asio::awaitable<bool> tcp_socks_session::connect_backend(const std::shared_ptr<upstream>& backend,
                                                                const std::string& host,
                                                                const std::uint16_t port,
                                                                const route_type route)
{
    LOG_CTX_INFO(ctx_, "{} connecting {} {} via {}", log_event::kConnInit, host, port, mux::to_string(route));
    boost::system::error_code ec;
    co_await backend->connect(host, port, ec);
    if (!ec)
    {
        co_return true;
    }

    const auto rep = backend->suggested_socks_rep(ec);
    LOG_CTX_WARN(ctx_, "{} connect failed {} {} via {} error {} rep {}", log_event::kConnInit, host, port, mux::to_string(route), ec.message(), rep);
    co_await reply_error(rep);
    co_return false;
}

boost::asio::awaitable<void> tcp_socks_session::reply_error(const std::uint8_t code)
{
    std::uint8_t err[] = {socks::kVer, code, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    boost::system::error_code ec;
    co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(err), cfg_.timeout.write, ec);
    if (!ec)
    {
        co_return;
    }
    LOG_CTX_WARN(ctx_, "{} write error response failed {}", log_event::kSocks, ec.message());
}

boost::asio::awaitable<bool> tcp_socks_session::reply_success(const std::shared_ptr<upstream>& backend)
{
    std::vector<std::uint8_t> rep;
    rep.reserve(22);
    rep.push_back(socks::kVer);
    rep.push_back(socks::kRepSuccess);
    rep.push_back(0x00);
    boost::system::error_code bind_ec;
    boost::asio::ip::address bind_addr;
    std::uint16_t bind_port = 0;
    if (backend == nullptr || !backend->get_bind_endpoint(bind_addr, bind_port, bind_ec))
    {
        LOG_CTX_WARN(ctx_, "{} backend bind endpoint unavailable fallback zero", log_event::kSocks);
        rep.push_back(socks::kAtypIpv4);
        rep.insert(rep.end(), {0, 0, 0, 0, 0, 0});
    }
    else
    {
        bind_addr = socks_codec::normalize_ip_address(bind_addr);
        if (bind_addr.is_v4())
        {
            rep.push_back(socks::kAtypIpv4);
            const auto bytes = bind_addr.to_v4().to_bytes();
            rep.insert(rep.end(), bytes.begin(), bytes.end());
        }
        else
        {
            rep.push_back(socks::kAtypIpv6);
            const auto bytes = bind_addr.to_v6().to_bytes();
            rep.insert(rep.end(), bytes.begin(), bytes.end());
        }
        rep.push_back(static_cast<std::uint8_t>((bind_port >> 8) & 0xFF));
        rep.push_back(static_cast<std::uint8_t>(bind_port & 0xFF));
    }

    boost::system::error_code ec;
    co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(rep), cfg_.timeout.write, ec);
    if (!ec)
    {
        co_return true;
    }
    LOG_CTX_WARN(ctx_, "{} write to client failed {}", log_event::kDataSend, ec.message());
    co_return false;
}

void tcp_socks_session::close_client_socket()
{
    boost::system::error_code ec;
    idle_timer_.cancel();
    ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec && ec != boost::asio::error::not_connected)
    {
        LOG_CTX_WARN(ctx_, "{} shutdown client failed {}", log_event::kSocks, ec.message());
    }

    ec = socket_.close(ec);
    if (ec && ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close client failed {}", log_event::kSocks, ec.message());
    }
}

boost::asio::awaitable<void> tcp_socks_session::client_to_upstream(std::shared_ptr<upstream> backend)
{
    boost::system::error_code ec;
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        const std::size_t n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                co_await backend->shutdown_send(shutdown_ec);
                if (shutdown_ec)
                {
                    LOG_CTX_WARN(ctx_, "client_to_upstream shutdown backend send failed {}", shutdown_ec.message());
                }
            }
            else
            {
                LOG_CTX_WARN(ctx_, "client_to_upstream read failed {}", ec.message());
                co_await backend->close();
            }
            break;
        }
        std::vector<uint8_t> data(buf.begin(), buf.begin() + static_cast<int>(n));
        co_await backend->write(data, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "client_to_upstream write to backend failed {}", ec.message());
            co_await backend->close();
            break;
        }
        ctx_.add_tx_bytes(n);
        last_activity_time_ms_ = now_ms();
    }
    LOG_CTX_INFO(ctx_, "client_to_upstream finished");
}

boost::asio::awaitable<void> tcp_socks_session::upstream_to_client(std::shared_ptr<upstream> backend)
{
    boost::system::error_code ec;
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        const auto n = co_await backend->read(buf, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                shutdown_ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, shutdown_ec);
                if (shutdown_ec && shutdown_ec != boost::asio::error::not_connected)
                {
                    LOG_CTX_WARN(ctx_, "upstream_to_client shutdown client send failed {}", shutdown_ec.message());
                }
            }
            else
            {
                LOG_CTX_WARN(ctx_, "upstream_to_client read failed {}", ec.message());
                close_client_socket();
            }
            break;
        }
        auto write_size = co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(buf.data(), n), cfg_.timeout.write, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "upstream_to_client write failed {}", ec.message());
            co_await backend->close();
            break;
        }
        ctx_.add_rx_bytes(write_size);
        last_activity_time_ms_ = now_ms();
    }
    LOG_CTX_INFO(ctx_, "upstream_to_client finished");
}

boost::asio::awaitable<void> tcp_socks_session::idle_watchdog(std::shared_ptr<upstream> backend)
{
    const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;

    while (socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = now_ms() - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} tcp session idle closing", log_event::kSocks);
            co_await backend->close();
            boost::system::error_code ignore;
            ignore = socket_.close(ignore);
            break;
        }
    }
}

}    // namespace mux
