#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "log_context.h"
#include "remote_session.h"

namespace mux
{

remote_session::remote_session(std::shared_ptr<mux_connection> connection,
                               const std::uint32_t id,
                               asio::io_context& io_context,
                               const connection_context& ctx)
    : id_(id),
      io_context_(io_context),
      resolver_(io_context_),
      target_socket_(io_context_),
      connection_(std::move(connection)),
      recv_channel_(io_context_, 128)
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
    auto conn = connection_.lock();
    if (!conn)
    {
        co_return;
    }

    ctx_.set_target(syn.addr, syn.port);
    LOG_CTX_INFO(ctx_, "{} connecting {} {}", log_event::kMux, syn.addr, syn.port);
    const auto [resolve_ec, eps] = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), asio::as_tuple(asio::use_awaitable));
    if (resolve_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} resolve failed {}", log_event::kMux, resolve_ec.message());
        const ack_payload ack{.socks_rep = socks::kRepHostUnreach, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        const auto ack_ec = co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
        if (ack_ec)
        {
            LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ack_ec.message());
        }
        if (auto mgr = manager_.lock())
        {
            mgr->remove_stream(id_);
        }
        (void)co_await conn->send_async(id_, kCmdRst, {});
        co_return;
    }

    const auto [connect_ec, ep_conn] = co_await asio::async_connect(target_socket_, eps, asio::as_tuple(asio::use_awaitable));
    if (connect_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} connect failed {}", log_event::kMux, connect_ec.message());
        const ack_payload ack{.socks_rep = socks::kRepConnRefused, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        const auto ack_ec = co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
        if (ack_ec)
        {
            LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ack_ec.message());
        }
        if (auto mgr = manager_.lock())
        {
            mgr->remove_stream(id_);
        }
        (void)co_await conn->send_async(id_, kCmdRst, {});
        co_return;
    }

    std::error_code ec_sock;
    ec_sock = target_socket_.set_option(asio::ip::tcp::no_delay(true), ec_sock);
    if (ec_sock)
    {
        LOG_CTX_WARN(ctx_, "set_option no_delay failed {}", ec_sock.message());
    }

    LOG_CTX_INFO(ctx_, "{} connected {} {}", log_event::kConnEstablished, syn.addr, syn.port);

    const ack_payload ack_pl{.socks_rep = socks::kRepSuccess, .bnd_addr = ep_conn.address().to_string(), .bnd_port = ep_conn.port()};
    std::vector<std::uint8_t> ack_data;
    mux_codec::encode_ack(ack_pl, ack_data);
    const auto ack_ec = co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ack_ec.message());
        if (auto mgr = manager_.lock())
        {
            mgr->remove_stream(id_);
        }
        co_return;
    }

    using asio::experimental::awaitable_operators::operator&&;
    co_await (upstream() && downstream());

    std::error_code ignore;
    ignore = target_socket_.close(ignore);
    (void)ignore;
    if (auto mgr = manager_.lock())
    {
        mgr->remove_stream(id_);
    }
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

void remote_session::on_data(std::vector<std::uint8_t> data)
{
    asio::dispatch(io_context_,
                   [self = shared_from_this(), data = std::move(data)]() mutable
                   { self->recv_channel_.try_send(std::error_code(), std::move(data)); });
}

void remote_session::on_close()
{
    asio::dispatch(io_context_, [self = shared_from_this()]() { self->close_from_fin(); });
}

void remote_session::on_reset()
{
    asio::dispatch(io_context_, [self = shared_from_this()]() { self->close_from_reset(); });
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
    recv_channel_.close();
    std::error_code ec;
    ec = target_socket_.close(ec);
}

asio::awaitable<void> remote_session::upstream()
{
    for (;;)
    {
        const auto [recv_ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (recv_ec || data.empty())
        {
            if (recv_ec)
            {
                LOG_CTX_DEBUG(ctx_, "{} mux channel closed {}", log_event::kDataRecv, recv_ec.message());
            }
            std::error_code ignore;
            ignore = target_socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
            (void)ignore;
            break;
        }
        const auto [we, wn] = co_await asio::async_write(target_socket_, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to target {}", log_event::kDataSend, we.message());
            break;
        }
        ctx_.add_rx_bytes(wn);
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
        if (re || n == 0)
        {
            if (re && re != asio::error::eof && re != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} failed to read from target {}", log_event::kDataRecv, re.message());
            }
            break;
        }

        auto conn = connection_.lock();
        if (!conn)
        {
            break;
        }

        if (const auto ec = co_await conn->send_async(id_, kCmdDat, std::vector<std::uint8_t>(buf.begin(), buf.begin() + n)))
        {
            LOG_CTX_WARN(ctx_, "{} failed to write to mux {}", log_event::kDataSend, ec.message());
            break;
        }
        ctx_.add_tx_bytes(n);
    }
    LOG_CTX_INFO(ctx_, "{} target to mux finished", log_event::kDataRecv);

    if (auto conn = connection_.lock())
    {
        (void)co_await conn->send_async(id_, kCmdFin, {});
    }
}

}    // namespace mux
