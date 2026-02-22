#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "timeout_io.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "stop_dispatch.h"
#include "mux_connection.h"
#include "remote_session.h"

namespace mux
{

namespace
{

using resolve_results = boost::asio::ip::tcp::resolver::results_type;
using timed_resolve_result = timeout_io::timed_tcp_resolve_result;
using timed_connect_result = timeout_io::timed_tcp_connect_result;

void log_remote_session_recv_channel_unavailable_on_data(const connection_context& ctx)
{
    LOG_CTX_WARN(ctx, "{} recv channel unavailable on data", log_event::kMux);
}

boost::asio::awaitable<bool> send_ack(std::shared_ptr<mux_connection> conn,
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

boost::asio::awaitable<void> remove_stream_and_reset(std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager,
                                                     std::shared_ptr<mux_connection> conn,
                                                     const std::uint32_t stream_id)
{
    if (auto mgr = manager.lock())
    {
        mgr->remove_stream(stream_id);
    }
    (void)co_await conn->send_async(stream_id, kCmdRst, {});
}

void remove_stream(const std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& manager, const std::uint32_t stream_id)
{
    if (auto mgr = manager.lock())
    {
        mgr->remove_stream(stream_id);
    }
}

boost::asio::awaitable<void> send_failure_ack_and_reset(std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager,
                                                        std::shared_ptr<mux_connection> conn,
                                                        const std::uint32_t stream_id,
                                                        const std::uint8_t rep,
                                                        const connection_context& ctx)
{
    (void)co_await send_ack(conn, stream_id, rep, "", 0, ctx);
    co_await remove_stream_and_reset(manager, conn, stream_id);
}

boost::asio::awaitable<timed_resolve_result> resolve_target_endpoints(boost::asio::ip::tcp::resolver& resolver,
                                                                      const syn_payload& syn,
                                                                      const connection_context& ctx,
                                                                      const std::uint32_t timeout_sec)
{
    const auto resolve_res = co_await timeout_io::async_resolve_with_timeout(resolver, syn.addr, std::to_string(syn.port), timeout_sec);
    if (resolve_res.timed_out)
    {
        statistics::instance().inc_remote_session_resolve_timeouts();
        LOG_CTX_ERROR(ctx, "{} stage=resolve target={}:{} timeout={}s", log_event::kMux, syn.addr, syn.port, timeout_sec);
        co_return resolve_res;
    }
    if (!resolve_res.ok)
    {
        statistics::instance().inc_remote_session_resolve_errors();
        LOG_CTX_ERROR(ctx, "{} stage=resolve target={}:{} error={}", log_event::kMux, syn.addr, syn.port, resolve_res.ec.message());
        co_return resolve_res;
    }
    co_return resolve_res;
}

boost::asio::awaitable<timed_connect_result> connect_target_endpoint(boost::asio::ip::tcp::socket& target_socket,
                                                                     const resolve_results& eps,
                                                                     const connection_context& ctx,
                                                                     const std::uint32_t timeout_sec)
{
    const auto connect_res = co_await timeout_io::async_connect_with_timeout(target_socket, eps, timeout_sec, "remote session");
    if (connect_res.timed_out)
    {
        statistics::instance().inc_remote_session_connect_timeouts();
        LOG_CTX_ERROR(ctx, "{} stage=connect target={}:{} timeout={}s", log_event::kMux, ctx.target_host(), ctx.target_port(), timeout_sec);
        co_return connect_res;
    }
    if (!connect_res.ok)
    {
        statistics::instance().inc_remote_session_connect_errors();
        LOG_CTX_ERROR(ctx, "{} stage=connect target={}:{} error={}", log_event::kMux, ctx.target_host(), ctx.target_port(), connect_res.ec.message());
        co_return connect_res;
    }
    co_return connect_res;
}

void set_target_socket_no_delay(boost::asio::ip::tcp::socket& target_socket, const connection_context& ctx)
{
    boost::system::error_code ec_sock;
    ec_sock = target_socket.set_option(boost::asio::ip::tcp::no_delay(true), ec_sock);
    if (ec_sock)
    {
        LOG_CTX_WARN(ctx, "set_option no_delay failed {}", ec_sock.message());
    }
}

bool should_stop_upstream(const boost::system::error_code& recv_ec,
                          const std::vector<std::uint8_t>& data,
                          boost::asio::ip::tcp::socket& target_socket,
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
    boost::system::error_code ignore;
    ignore = target_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
    (void)ignore;
    return true;
}

boost::asio::awaitable<bool> write_to_target(boost::asio::ip::tcp::socket& target_socket,
                                             const std::vector<std::uint8_t>& data,
                                             connection_context& ctx)
{
    const auto [write_ec, write_size] =
        co_await boost::asio::async_write(target_socket, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (write_ec)
    {
        LOG_CTX_WARN(ctx, "{} failed to write to target {}", log_event::kDataSend, write_ec.message());
        co_return false;
    }
    ctx.add_rx_bytes(write_size);
    co_return true;
}

bool should_stop_downstream(const boost::system::error_code& read_ec, const std::size_t read_size, const connection_context& ctx)
{
    if (!read_ec && read_size > 0)
    {
        return false;
    }
    if (read_ec && read_ec != boost::asio::error::eof && read_ec != boost::asio::error::operation_aborted)
    {
        LOG_CTX_WARN(ctx, "{} failed to read from target {}", log_event::kDataRecv, read_ec.message());
    }
    return true;
}

boost::asio::awaitable<bool> send_downstream_payload(const std::weak_ptr<mux_connection>& connection,
                                                     const std::uint32_t stream_id,
                                                     const std::vector<std::uint8_t>& buf,
                                                     const std::size_t size,
                                                     connection_context& ctx)
{
    auto conn = connection.lock();
    if (!conn)
    {
        co_return false;
    }
    std::vector<std::uint8_t> payload(size);
    if (size > 0)
    {
        std::memcpy(payload.data(), buf.data(), size);
    }
    if (const auto ec = co_await conn->send_async(stream_id, kCmdDat, std::move(payload)))
    {
        LOG_CTX_WARN(ctx, "{} failed to write to mux {}", log_event::kDataSend, ec.message());
        co_return false;
    }
    ctx.add_tx_bytes(size);
    co_return true;
}

boost::asio::awaitable<void> send_fin_to_connection(const std::weak_ptr<mux_connection>& connection, const std::uint32_t stream_id)
{
    if (auto conn = connection.lock())
    {
        (void)co_await conn->send_async(stream_id, kCmdFin, {});
    }
}

void close_target_socket(boost::asio::ip::tcp::socket& target_socket)
{
    boost::system::error_code ignore;
    ignore = target_socket.close(ignore);
    (void)ignore;
}

boost::asio::awaitable<bool> prepare_remote_target_connection(boost::asio::ip::tcp::resolver& resolver,
                                                              boost::asio::ip::tcp::socket& target_socket,
                                                              const syn_payload& syn,
                                                              std::shared_ptr<mux_connection> conn,
                                                              std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager,
                                                              const std::uint32_t stream_id,
                                                              connection_context& ctx,
                                                              const std::atomic<bool>& reset_requested,
                                                              const std::uint32_t connect_timeout_sec)
{
    const auto timeout_sec = connect_timeout_sec;
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
        // Keep timeout mapping compatible with existing clients.
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

remote_session::remote_session(const std::shared_ptr<mux_connection>& connection,
                               const std::uint32_t id,
                               boost::asio::io_context& io_context,
                               const connection_context& ctx,
                               const std::uint32_t connect_timeout_sec)
    : id_(id),
      io_context_(io_context),
      resolver_(io_context_),
      target_socket_(io_context_),
      connection_(connection),
      recv_channel_(io_context_, 128),
      connect_timeout_sec_(connect_timeout_sec)
{
    ctx_ = ctx;
    ctx_.stream_id(id);
}

boost::asio::awaitable<void> remote_session::start(const syn_payload& syn)
{
    co_await boost::asio::dispatch(io_context_, boost::asio::use_awaitable);
    co_await run(syn);
}

boost::asio::awaitable<void> remote_session::run(const syn_payload& syn)
{
    if (reset_requested_.load(std::memory_order_acquire))
    {
        remove_stream(manager_, id_);
        co_return;
    }

    auto conn = connection_.lock();
    if (!conn)
    {
        close_target_socket(target_socket_);
        remove_stream(manager_, id_);
        co_return;
    }
    if (!co_await prepare_remote_target_connection(resolver_, target_socket_, syn, conn, manager_, id_, ctx_, reset_requested_, connect_timeout_sec_))
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

    using boost::asio::experimental::awaitable_operators::operator&&;
    co_await (upstream() && downstream());

    close_target_socket(target_socket_);
    remove_stream(manager_, id_);
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

void remote_session::on_data(std::vector<std::uint8_t> data)
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [self = shared_from_this(), data = std::move(data)]() mutable
                                           {
                                               if (!self->recv_channel_.try_send(boost::system::error_code(), std::move(data)))
                                               {
                                                   log_remote_session_recv_channel_unavailable_on_data(self->ctx_);
                                                   self->close_from_reset();
                                               }
                                           });
}

void remote_session::on_close()
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
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
    detail::dispatch_cleanup_or_run_inline(io_context_,
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
    boost::system::error_code ec;
    ec = target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
}

void remote_session::close_from_reset()
{
    const auto already_requested = reset_requested_.exchange(true, std::memory_order_acq_rel);
    if (already_requested)
    {
        return;
    }
    recv_channel_.close();
    resolver_.cancel();
    boost::system::error_code ec;
    ec = target_socket_.close(ec);
    remove_stream(manager_, id_);
}

boost::asio::awaitable<void> remote_session::upstream()
{
    for (;;)
    {
        const auto [recv_ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
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

boost::asio::awaitable<void> remote_session::downstream()
{
    std::vector<std::uint8_t> buf(8192);
    for (;;)
    {
        boost::system::error_code re;
        const std::size_t n =
            co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, re));
        if (should_stop_downstream(re, n, ctx_))
        {
            break;
        }
        if (!co_await send_downstream_payload(connection_, id_, buf, n, ctx_))
        {
            recv_channel_.close();
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} target to mux finished", log_event::kDataRecv);
    if (!reset_requested_.load(std::memory_order_acquire))
    {
        co_await send_fin_to_connection(connection_, id_);
    }
}

}    // namespace mux
