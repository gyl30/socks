#include "tcp_socks_session.h"

namespace mux
{

tcp_socks_session::tcp_socks_session(asio::ip::tcp::socket socket,
                  std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                  std::shared_ptr<router> router,
                  uint32_t sid)
    : sid_(sid), socket_(std::move(socket)), router_(std::move(router)), tunnel_manager_(std::move(tunnel_manager))
{
    ctx_.new_trace_id();
    ctx_.conn_id = sid;
}

void tcp_socks_session::start(const std::string& host, uint16_t port)
{
    auto self = shared_from_this();
    asio::co_spawn(
        socket_.get_executor(), [self, host, port]() mutable -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
}

asio::awaitable<void> tcp_socks_session::run(std::string host, uint16_t port)
{
    auto route = co_await router_->decide(ctx_, host, socket_.get_executor());

    std::unique_ptr<upstream> backend;

    if (route == route_type::direct)
    {
        backend = std::make_unique<direct_upstream>(socket_.get_executor(), ctx_);
    }
    else if (route == route_type::proxy)
    {
        backend = std::make_unique<proxy_upstream>(tunnel_manager_, ctx_);
    }
    else
    {
        LOG_CTX_WARN(ctx_, "{} blocked host {}", log_event::ROUTE, host);
        co_await reply_error(socks::REP_NOT_ALLOWED);
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connecting {} {} via {}", log_event::CONN_INIT, host, port, (route == route_type::direct ? "direct" : "proxy"));
    if (!co_await backend->connect(host, port))
    {
        LOG_CTX_WARN(ctx_, "{} connect failed {} {} via {}", log_event::CONN_INIT, host, port, (route == route_type::direct ? "direct" : "proxy"));
        co_await reply_error(socks::REP_HOST_UNREACH);
        co_return;
    }

    uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(rep), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_CTX_WARN(ctx_, "{} write to client failed {}", log_event::DATA_SEND, we.message());
        co_await backend->close();
        co_return;
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {} via {}", log_event::CONN_ESTABLISHED, host, port, (route == route_type::direct ? "direct" : "proxy"));
    using asio::experimental::awaitable_operators::operator&&;
    co_await (client_to_upstream(backend.get()) && upstream_to_client(backend.get()));
    co_await backend->close();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::CONN_CLOSE, ctx_.stats_summary());
}

asio::awaitable<void> tcp_socks_session::reply_error(uint8_t code)
{
    uint8_t err[] = {socks::VER, code, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
    co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<void> tcp_socks_session::client_to_upstream(upstream* backend)
{
    std::vector<uint8_t> buf(8192);
    for (;;)
    {
        std::error_code ec;
        uint32_t n = co_await socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, ec));
        if (ec || n == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from client {}", log_event::SOCKS, ec.message());
            break;
        }

        std::vector<uint8_t> chunk(buf.begin(), buf.begin() + n);
        auto written = co_await backend->write(chunk);
        if (written == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to backend", log_event::SOCKS);
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} client to upstream finished", log_event::SOCKS);
}

asio::awaitable<void> tcp_socks_session::upstream_to_client(upstream* backend)
{
    std::vector<uint8_t> buf(8192);
    for (;;)
    {
        auto [ec, n] = co_await backend->read(buf);
        if (ec || n == 0)
        {
            LOG_CTX_WARN(ctx_, "{} failed to read from backend {}", log_event::SOCKS, ec.message());
            break;
        }

        auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(buf.data(), n), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to client {}", log_event::SOCKS, we.message());
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} upstream to client finished", log_event::SOCKS);
    std::error_code ignore;
    ignore = socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    if (ignore)
    {
        LOG_CTX_WARN(ctx_, "{} failed to shutdown client {}", log_event::SOCKS, ignore.message());
    }
}

}
