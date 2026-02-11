#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/error.hpp>
#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/address_v6.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "remote_udp_session.h"

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

remote_udp_session::remote_udp_session(std::shared_ptr<mux_connection> connection,
                                       const std::uint32_t id,
                                       const asio::any_io_executor& ex,
                                       const connection_context& ctx)
    : id_(id),
      strand_(asio::make_strand(ex)),
      timer_(strand_),
      idle_timer_(strand_),
      udp_socket_(strand_),
      udp_resolver_(strand_),
      connection_(std::move(connection)),
      recv_channel_(strand_, 128)
{
    ctx_ = ctx;
    ctx_.stream_id(id);
    const auto ts = now_ms();
    last_read_time_ms_.store(ts, std::memory_order_release);
    last_write_time_ms_.store(ts, std::memory_order_release);
    last_activity_time_ms_.store(ts, std::memory_order_release);
}

asio::awaitable<void> remote_udp_session::start()
{
    co_await asio::dispatch(strand_, asio::use_awaitable);
    co_await start_impl(shared_from_this());
}

asio::awaitable<void> remote_udp_session::start_impl(std::shared_ptr<remote_udp_session> self)
{
    auto conn = connection_.lock();
    if (!conn)
    {
        co_return;
    }
    std::error_code ec;
    ec = udp_socket_.open(asio::ip::udp::v6(), ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} udp open failed {}", log_event::kMux, ec.message());
        ack_payload const ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
        if (auto m = manager_.lock())
        {
            m->remove_stream(id_);
        }
        (void)co_await conn->send_async(id_, kCmdRst, {});
        co_return;
    }
    ec = udp_socket_.set_option(asio::ip::v6_only(false), ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} udp v4 and v6 failed {}", log_event::kMux, ec.message());
        ack_payload const ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
        if (auto m = manager_.lock())
        {
            m->remove_stream(id_);
        }
        (void)co_await conn->send_async(id_, kCmdRst, {});
        co_return;
    }
    ec = udp_socket_.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), 0), ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} udp bind failed {}", log_event::kMux, ec.message());
        ack_payload const ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
        if (auto m = manager_.lock())
        {
            m->remove_stream(id_);
        }
        (void)co_await conn->send_async(id_, kCmdRst, {});
        co_return;
    }

    const auto local_ep = udp_socket_.local_endpoint(ec);
    LOG_CTX_INFO(ctx_, "{} udp session started bound at {}", log_event::kMux, local_ep.address().to_string());

    const ack_payload ack_pl{.socks_rep = socks::kRepSuccess, .bnd_addr = "0.0.0.0", .bnd_port = 0};
    std::vector<std::uint8_t> ack_pl_data;
    mux_codec::encode_ack(ack_pl, ack_pl_data);
    co_await conn->send_async(id_, kCmdAck, std::move(ack_pl_data));

    using asio::experimental::awaitable_operators::operator||;
    co_await (mux_to_udp() || udp_to_mux() || watchdog() || idle_watchdog());
    request_stop();
    close_socket();

    if (auto m = manager_.lock())
    {
        m->remove_stream(id_);
    }
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

void remote_udp_session::on_data(std::vector<std::uint8_t> data)
{
    asio::dispatch(
        strand_, [self = shared_from_this(), data = std::move(data)]() mutable { self->recv_channel_.try_send(std::error_code(), std::move(data)); });
}

void remote_udp_session::request_stop()
{
    recv_channel_.close();
    timer_.cancel();
    idle_timer_.cancel();
    udp_resolver_.cancel();
    std::error_code ignore;
    ignore = udp_socket_.cancel(ignore);
}

void remote_udp_session::close_socket()
{
    if (!udp_socket_.is_open())
    {
        return;
    }
    std::error_code ignore;
    ignore = udp_socket_.close(ignore);
}

void remote_udp_session::on_close()
{
    asio::dispatch(strand_, [self = shared_from_this()]() { self->request_stop(); });
}

void remote_udp_session::on_reset() { on_close(); }

asio::awaitable<void> remote_udp_session::watchdog()
{
    while (udp_socket_.is_open())
    {
        timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            if (wait_ec == asio::error::operation_aborted)
            {
                LOG_CTX_DEBUG(ctx_, "{} watchdog stopped {}", log_event::kTimeout, wait_ec.message());
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} watchdog error {}", log_event::kTimeout, wait_ec.message());
            }
            break;
        }
        const auto current_ms = now_ms();
        const auto read_elapsed_ms = current_ms - last_read_time_ms_.load(std::memory_order_acquire);
        const auto write_elapsed_ms = current_ms - last_write_time_ms_.load(std::memory_order_acquire);
        if (read_elapsed_ms > 60000ULL)
        {
            LOG_CTX_WARN(ctx_, "{} read idle {}s", log_event::kTimeout, read_elapsed_ms / 1000ULL);
        }
        if (write_elapsed_ms > 60000ULL)
        {
            LOG_CTX_WARN(ctx_, "{} write idle {}s", log_event::kTimeout, write_elapsed_ms / 1000ULL);
        }
    }
    LOG_CTX_DEBUG(ctx_, "{} watchdog finished", log_event::kMux);
}

asio::awaitable<void> remote_udp_session::mux_to_udp()
{
    for (;;)
    {
        const auto [recv_ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (recv_ec || data.empty())
        {
            break;
        }

        _header h;
        if (!socks_codec::decode_udp_header(data.data(), data.size(), h))
        {
            LOG_CTX_WARN(ctx_, "{} udp failed to decode header", log_event::kMux);
            continue;
        }

        const auto [resolve_ec, eps] = co_await udp_resolver_.async_resolve(h.addr, std::to_string(h.port), asio::as_tuple(asio::use_awaitable));
        if (!resolve_ec)
        {
            auto target_ep = eps.begin()->endpoint();
            if (target_ep.address().is_v4())
            {
                const auto v4 = target_ep.address().to_v4();
                const auto v4_bytes = v4.to_bytes();
                asio::ip::address_v6::bytes_type v6_bytes = {0};
                v6_bytes[10] = 0xFF;
                v6_bytes[11] = 0xFF;
                v6_bytes[12] = v4_bytes[0];
                v6_bytes[13] = v4_bytes[1];
                v6_bytes[14] = v4_bytes[2];
                v6_bytes[15] = v4_bytes[3];
                const auto v6 = asio::ip::address_v6(v6_bytes);
                target_ep = asio::ip::udp::endpoint(v6, target_ep.port());
            }

            LOG_CTX_DEBUG(ctx_, "{} udp forwarding {} bytes to {}", log_event::kMux, data.size() - h.header_len, target_ep.address().to_string());

            const auto [se, sn] = co_await udp_socket_.async_send_to(
                asio::buffer(data.data() + h.header_len, data.size() - h.header_len), target_ep, asio::as_tuple(asio::use_awaitable));
            if (se)
            {
                LOG_CTX_WARN(ctx_, "{} udp send error {}", log_event::kMux, se.message());
            }
            else
            {
                const auto ts = now_ms();
                last_write_time_ms_.store(ts, std::memory_order_release);
                ctx_.add_tx_bytes(sn);
                last_activity_time_ms_.store(ts, std::memory_order_release);
            }
        }
        else
        {
            LOG_CTX_WARN(ctx_, "{} udp resolve error for {}", log_event::kMux, h.addr);
        }
    }
}

asio::awaitable<void> remote_udp_session::udp_to_mux()
{
    std::vector<std::uint8_t> buf(65535);
    asio::ip::udp::endpoint ep;
    for (;;)
    {
        const auto [recv_ec, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), ep, asio::as_tuple(asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} udp receive error {}", log_event::kMux, recv_ec.message());
            }
            break;
        }

        LOG_CTX_DEBUG(ctx_, "{} udp recv {} bytes from {}", log_event::kMux, n, ep.address().to_string());
        const auto ts = now_ms();
        last_read_time_ms_.store(ts, std::memory_order_release);
        ctx_.add_rx_bytes(n);
        last_activity_time_ms_.store(ts, std::memory_order_release);

        socks_udp_header h;
        h.addr = ep.address().to_string();
        h.port = ep.port();
        std::vector<std::uint8_t> pkt = socks_codec::encode_udp_header(h);
        pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<std::uint32_t>(n));

        if (auto conn = connection_.lock())
        {
            if (co_await conn->send_async(id_, kCmdDat, std::move(pkt)))
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
}

asio::awaitable<void> remote_udp_session::idle_watchdog()
{
    while (udp_socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto current_ms = now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_.load(std::memory_order_acquire);
        if (elapsed_ms > 60000ULL)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kMux);
            request_stop();
            break;
        }
    }
}

}    // namespace mux
