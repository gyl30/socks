#include <optional>
#include <atomic>
#include <chrono>
#include <memory>

#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "log_context.h"
#include "stop_dispatch.h"
#include "remote_session.h"

namespace mux
{

namespace
{

using resolve_results = asio::ip::tcp::resolver::results_type;

struct timed_resolve_result
{
    bool ok = false;
    bool timed_out = false;
    resolve_results endpoints;
    std::error_code ec;
};

struct timed_connect_result
{
    bool ok = false;
    bool timed_out = false;
    asio::ip::tcp::endpoint endpoint;
    std::error_code ec;
};

asio::awaitable<bool> send_ack(std::shared_ptr<mux_connection> conn,
                               const std::uint32_t stream_id,
                               const std::uint8_t rep,
                               const std::string& addr,
                               const std::uint16_t port,
                               const connection_context& ctx)
{
    const ack_payload ack{.socks_rep = rep, .bnd_addr = addr, .bnd_port = port};
    std::vector<std::uint8_t> ack_data;
    mux_codec::encode_ack(ack, ack_data);
    const auto ack_ec = co_await conn->send_async(stream_id, kCmdAck, std::move(ack_data));
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx, "{} send ack failed {}", log_event::kMux, ack_ec.message());
        co_return false;
    }
    co_return true;
}

asio::awaitable<void> remove_stream_and_reset(std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager,
                                              std::shared_ptr<mux_connection> conn,
                                              const std::uint32_t stream_id)
{
    if (auto mgr = manager.lock())
    {
        mgr->remove_stream(stream_id);
    }
    (void)co_await conn->send_async(stream_id, kCmdRst, {});
}

void remove_stream(std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager, const std::uint32_t stream_id)
{
    if (auto mgr = manager.lock())
    {
        mgr->remove_stream(stream_id);
    }
}

asio::awaitable<void> send_failure_ack_and_reset(std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager,
                                                 std::shared_ptr<mux_connection> conn,
                                                 const std::uint32_t stream_id,
                                                 const std::uint8_t rep,
                                                 const connection_context& ctx)
{
    (void)co_await send_ack(conn, stream_id, rep, "", 0, ctx);
    co_await remove_stream_and_reset(manager, conn, stream_id);
}

asio::awaitable<timed_resolve_result> resolve_target_endpoints(asio::ip::tcp::resolver& resolver,
                                                               const syn_payload& syn,
                                                               const connection_context& ctx,
                                                               const std::uint32_t timeout_sec)
{
    auto timer = std::make_shared<asio::steady_timer>(resolver.get_executor());
    auto timeout_triggered = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(std::chrono::seconds(timeout_sec));
    timer->async_wait(
        [&resolver, timeout_triggered](const std::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timeout_triggered->store(true, std::memory_order_release);
            resolver.cancel();
        });

    const auto [resolve_ec, eps] = co_await resolver.async_resolve(syn.addr, std::to_string(syn.port), asio::as_tuple(asio::use_awaitable));
    const auto cancelled = timer->cancel();
    (void)cancelled;
    if (timeout_triggered->load(std::memory_order_acquire))
    {
        LOG_CTX_ERROR(ctx, "{} resolve timed out {}s", log_event::kMux, timeout_sec);
        co_return timed_resolve_result{
            .ok = false,
            .timed_out = true,
            .ec = asio::error::timed_out};
    }
    if (resolve_ec)
    {
        LOG_CTX_ERROR(ctx, "{} resolve failed {}", log_event::kMux, resolve_ec.message());
        co_return timed_resolve_result{
            .ok = false,
            .ec = resolve_ec};
    }
    co_return timed_resolve_result{
        .ok = true,
        .endpoints = eps};
}

asio::awaitable<timed_connect_result> connect_target_endpoint(asio::ip::tcp::socket& target_socket,
                                                              const resolve_results& eps,
                                                              const connection_context& ctx,
                                                              const std::uint32_t timeout_sec)
{
    auto timer = std::make_shared<asio::steady_timer>(target_socket.get_executor());
    auto timeout_triggered = std::make_shared<std::atomic<bool>>(false);
    timer->expires_after(std::chrono::seconds(timeout_sec));
    timer->async_wait(
        [&target_socket, timeout_triggered](const std::error_code& timer_ec)
        {
            if (timer_ec)
            {
                return;
            }
            timeout_triggered->store(true, std::memory_order_release);
            std::error_code cancel_ec;
            target_socket.cancel(cancel_ec);
            if (cancel_ec && cancel_ec != asio::error::bad_descriptor)
            {
                LOG_WARN("remote session cancel timeout socket failed {}", cancel_ec.message());
            }

            std::error_code close_ec;
            target_socket.close(close_ec);
            if (close_ec && close_ec != asio::error::bad_descriptor)
            {
                LOG_WARN("remote session close timeout socket failed {}", close_ec.message());
            }
        });

    const auto [connect_ec, ep_conn] = co_await asio::async_connect(target_socket, eps, asio::as_tuple(asio::use_awaitable));
    const auto cancelled = timer->cancel();
    (void)cancelled;
    if (timeout_triggered->load(std::memory_order_acquire))
    {
        LOG_CTX_ERROR(ctx, "{} connect timed out {}s", log_event::kMux, timeout_sec);
        co_return timed_connect_result{
            .ok = false,
            .timed_out = true,
            .ec = asio::error::timed_out};
    }
    if (connect_ec)
    {
        LOG_CTX_ERROR(ctx, "{} connect failed {}", log_event::kMux, connect_ec.message());
        co_return timed_connect_result{
            .ok = false,
            .ec = connect_ec};
    }
    co_return timed_connect_result{
        .ok = true,
        .endpoint = ep_conn};
}

void set_target_socket_no_delay(asio::ip::tcp::socket& target_socket, const connection_context& ctx)
{
    std::error_code ec_sock;
    ec_sock = target_socket.set_option(asio::ip::tcp::no_delay(true), ec_sock);
    if (ec_sock)
    {
        LOG_CTX_WARN(ctx, "set_option no_delay failed {}", ec_sock.message());
    }
}

bool should_stop_upstream(const std::error_code& recv_ec,
                          const std::vector<std::uint8_t>& data,
                          asio::ip::tcp::socket& target_socket,
                          const connection_context& ctx)
{
    if (!recv_ec && !data.empty())
    {
        return false;
    }
    if (recv_ec)
    {
        LOG_CTX_DEBUG(ctx, "{} mux channel closed {}", log_event::kDataRecv, recv_ec.message());
    }
    std::error_code ignore;
    ignore = target_socket.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
    (void)ignore;
    return true;
}

asio::awaitable<bool> write_to_target(asio::ip::tcp::socket& target_socket, const std::vector<std::uint8_t>& data, connection_context& ctx)
{
    const auto [write_ec, write_size] = co_await asio::async_write(target_socket, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
    if (write_ec)
    {
        LOG_CTX_WARN(ctx, "{} failed to write to target {}", log_event::kDataSend, write_ec.message());
        co_return false;
    }
    ctx.add_rx_bytes(write_size);
    co_return true;
}

bool should_stop_downstream(const std::error_code& read_ec, const std::uint32_t read_size, const connection_context& ctx)
{
    if (!read_ec && read_size > 0)
    {
        return false;
    }
    if (read_ec && read_ec != asio::error::eof && read_ec != asio::error::operation_aborted)
    {
        LOG_CTX_WARN(ctx, "{} failed to read from target {}", log_event::kDataRecv, read_ec.message());
    }
    return true;
}

asio::awaitable<bool> send_downstream_payload(const std::weak_ptr<mux_connection>& connection,
                                              const std::uint32_t stream_id,
                                              const std::vector<std::uint8_t>& buf,
                                              const std::uint32_t size,
                                              connection_context& ctx)
{
    auto conn = connection.lock();
    if (!conn)
    {
        co_return false;
    }
    if (const auto ec = co_await conn->send_async(stream_id, kCmdDat, std::vector<std::uint8_t>(buf.begin(), buf.begin() + size)))
    {
        LOG_CTX_WARN(ctx, "{} failed to write to mux {}", log_event::kDataSend, ec.message());
        co_return false;
    }
    ctx.add_tx_bytes(size);
    co_return true;
}

asio::awaitable<void> send_fin_to_connection(const std::weak_ptr<mux_connection>& connection, const std::uint32_t stream_id)
{
    if (auto conn = connection.lock())
    {
        (void)co_await conn->send_async(stream_id, kCmdFin, {});
    }
}

void close_target_socket(asio::ip::tcp::socket& target_socket)
{
    std::error_code ignore;
    ignore = target_socket.close(ignore);
    (void)ignore;
}

asio::awaitable<bool> prepare_remote_target_connection(asio::ip::tcp::resolver& resolver,
                                                       asio::ip::tcp::socket& target_socket,
                                                       const syn_payload& syn,
                                                       std::shared_ptr<mux_connection> conn,
                                                       std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> manager,
                                                       const std::uint32_t stream_id,
                                                       connection_context& ctx,
                                                       const std::atomic<bool>& reset_requested,
                                                       const std::uint32_t connect_timeout_sec)
{
    const auto timeout_sec = (connect_timeout_sec == 0) ? 1U : connect_timeout_sec;
    if (reset_requested.load(std::memory_order_acquire))
    {
        co_return false;
    }

    ctx.set_target(syn.addr, syn.port);
    LOG_CTX_INFO(ctx, "{} connecting {} {}", log_event::kMux, syn.addr, syn.port);

    const auto resolve_res = co_await resolve_target_endpoints(resolver, syn, ctx, timeout_sec);
    if (!resolve_res.ok)
    {
        if (reset_requested.load(std::memory_order_acquire))
        {
            co_return false;
        }
        co_await send_failure_ack_and_reset(manager, conn, stream_id, socks::kRepHostUnreach, ctx);
        co_return false;
    }

    const auto connect_res = co_await connect_target_endpoint(target_socket, resolve_res.endpoints, ctx, timeout_sec);
    if (!connect_res.ok)
    {
        if (reset_requested.load(std::memory_order_acquire))
        {
            co_return false;
        }
        co_await send_failure_ack_and_reset(manager, conn, stream_id, socks::kRepConnRefused, ctx);
        co_return false;
    }

    if (reset_requested.load(std::memory_order_acquire))
    {
        close_target_socket(target_socket);
        remove_stream(manager, stream_id);
        co_return false;
    }

    set_target_socket_no_delay(target_socket, ctx);
    LOG_CTX_INFO(ctx, "{} connected {} {}", log_event::kConnEstablished, syn.addr, syn.port);
    if (!co_await send_ack(conn, stream_id, socks::kRepSuccess, connect_res.endpoint.address().to_string(), connect_res.endpoint.port(), ctx))
    {
        close_target_socket(target_socket);
        remove_stream(manager, stream_id);
        co_return false;
    }
    co_return true;
}

}    // namespace

remote_session::remote_session(std::shared_ptr<mux_connection> connection,
                               const std::uint32_t id,
                               asio::io_context& io_context,
                               const connection_context& ctx,
                               const std::uint32_t connect_timeout_sec)
    : id_(id),
      io_context_(io_context),
      resolver_(io_context_),
      target_socket_(io_context_),
      connection_(std::move(connection)),
      recv_channel_(io_context_, 128),
      connect_timeout_sec_(connect_timeout_sec)
{
    ctx_ = ctx;
    ctx_.stream_id(id);
}

asio::awaitable<void> remote_session::start(const syn_payload& syn)
{
    co_await asio::dispatch(io_context_, asio::use_awaitable);
    co_await run(syn);
}

asio::awaitable<void> remote_session::run(const syn_payload& syn)
{
    if (reset_requested_.load(std::memory_order_acquire))
    {
        remove_stream(manager_, id_);
        co_return;
    }

    auto conn = connection_.lock();
    if (!conn)
    {
        co_return;
    }
    if (!co_await prepare_remote_target_connection(
            resolver_, target_socket_, syn, conn, manager_, id_, ctx_, reset_requested_, connect_timeout_sec_))
    {
        if (reset_requested_.load(std::memory_order_acquire))
        {
            close_target_socket(target_socket_);
            remove_stream(manager_, id_);
        }
        co_return;
    }

    if (reset_requested_.load(std::memory_order_acquire))
    {
        close_target_socket(target_socket_);
        remove_stream(manager_, id_);
        co_return;
    }

    using asio::experimental::awaitable_operators::operator&&;
    co_await (upstream() && downstream());

    close_target_socket(target_socket_);
    remove_stream(manager_, id_);
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

void remote_session::on_data(std::vector<std::uint8_t> data)
{
    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [self = shared_from_this(), data = std::move(data)]() mutable
        {
            if (!self->recv_channel_.try_send(std::error_code(), std::move(data)))
            {
                LOG_CTX_WARN(self->ctx_, "{} recv channel unavailable on data", log_event::kMux);
                self->close_from_reset();
            }
        });
}

void remote_session::on_close()
{
    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                self->close_from_fin();
            }
        });
}

void remote_session::on_reset()
{
    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                self->close_from_reset();
            }
        });
}

void remote_session::close_from_fin()
{
    LOG_CTX_DEBUG(ctx_, "{} received fin from client", log_event::kMux);
    recv_channel_.close();
    std::error_code ec;
    ec = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
}

void remote_session::close_from_reset()
{
    reset_requested_.store(true, std::memory_order_release);
    recv_channel_.close();
    resolver_.cancel();
    std::error_code ec;
    ec = target_socket_.close(ec);
}

asio::awaitable<void> remote_session::upstream()
{
    for (;;)
    {
        const auto [recv_ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (should_stop_upstream(recv_ec, data, target_socket_, ctx_))
        {
            break;
        }
        if (!co_await write_to_target(target_socket_, data, ctx_))
        {
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} mux to target finished", log_event::kDataSend);
}

asio::awaitable<void> remote_session::downstream()
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        std::error_code re;
        const std::uint32_t n = co_await target_socket_.async_read_some(asio::buffer(buf), asio::redirect_error(asio::use_awaitable, re));
        if (should_stop_downstream(re, n, ctx_))
        {
            break;
        }
        if (!co_await send_downstream_payload(connection_, id_, buf, n, ctx_))
        {
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} target to mux finished", log_event::kDataRecv);
    co_await send_fin_to_connection(connection_, id_);
}

}    // namespace mux
