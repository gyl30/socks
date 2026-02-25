#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "statistics.h"
#include "timeout_io.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "stop_dispatch.h"
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

[[nodiscard]] boost::asio::ip::udp::endpoint normalize_target_endpoint(const boost::asio::ip::udp::endpoint& endpoint)
{
    if (!endpoint.address().is_v4())
    {
        return endpoint;
    }

    const auto v4 = endpoint.address().to_v4();
    const auto v4_bytes = v4.to_bytes();
    boost::asio::ip::address_v6::bytes_type v6_bytes = {0};
    v6_bytes[10] = 0xFF;
    v6_bytes[11] = 0xFF;
    v6_bytes[12] = v4_bytes[0];
    v6_bytes[13] = v4_bytes[1];
    v6_bytes[14] = v4_bytes[2];
    v6_bytes[15] = v4_bytes[3];
    return {boost::asio::ip::address_v6(v6_bytes), endpoint.port()};
}

void log_remote_udp_recv_channel_unavailable_on_data(const connection_context& ctx)
{
    LOG_CTX_WARN(ctx, "{} recv channel unavailable on data", log_event::kMux);
}

}    // namespace

remote_udp_session::remote_udp_session(const std::shared_ptr<mux_connection>& connection,
                                       const std::uint32_t id,
                                       boost::asio::io_context& io_context,
                                       const connection_context& ctx,
                                       const config::timeout_t& timeout_cfg,
                                       const std::size_t recv_channel_capacity)
    : id_(id),
      io_context_(io_context),
      timer_(io_context_),
      idle_timer_(io_context_),
      udp_socket_(io_context_),
      udp_resolver_(io_context_),
      connection_(connection),
      read_timeout_ms_(static_cast<std::uint64_t>(timeout_cfg.read) * 1000ULL),
      write_timeout_ms_(static_cast<std::uint64_t>(timeout_cfg.write) * 1000ULL),
      idle_timeout_ms_(static_cast<std::uint64_t>(timeout_cfg.idle) * 1000ULL),
      recv_channel_(io_context_, recv_channel_capacity)
{
    ctx_ = ctx;
    ctx_.stream_id(id);
    const auto ts = now_ms();
    last_read_time_ms_.store(ts, std::memory_order_release);
    last_write_time_ms_.store(ts, std::memory_order_release);
    last_activity_time_ms_.store(ts, std::memory_order_release);
}

boost::asio::awaitable<void> remote_udp_session::start()
{
    co_await boost::asio::dispatch(io_context_, boost::asio::use_awaitable);
    co_await start_impl(shared_from_this());
}

boost::asio::awaitable<boost::system::error_code> remote_udp_session::send_ack_payload(const std::shared_ptr<mux_connection>& conn,
                                                                                       const ack_payload& ack) const
{
    std::vector<std::uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        co_return boost::asio::error::invalid_argument;
    }
    co_return co_await conn->send_async(id_, kCmdAck, std::move(ack_data));
}

boost::asio::awaitable<void> remote_udp_session::handle_start_failure(const std::shared_ptr<mux_connection>& conn,
                                                                      const char* step,
                                                                      const boost::system::error_code& ec)
{
    LOG_CTX_ERROR(ctx_, "{} {} failed {}", log_event::kMux, step, ec.message());
    const ack_payload ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
    if (const auto ack_ec = co_await send_ack_payload(conn, ack))
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ack_ec.message());
    }
    co_await cleanup_after_stop();
}

boost::asio::awaitable<bool> remote_udp_session::setup_udp_socket(const std::shared_ptr<mux_connection>& conn)
{
    boost::system::error_code ec;
    ec = udp_socket_.open(boost::asio::ip::udp::v6(), ec);
    if (ec)
    {
        co_await handle_start_failure(conn, "udp open", ec);
        co_return false;
    }

    ec = udp_socket_.set_option(boost::asio::ip::v6_only(false), ec);
    if (ec)
    {
        co_await handle_start_failure(conn, "udp v4 and v6", ec);
        co_return false;
    }

    ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
    if (ec)
    {
        co_await handle_start_failure(conn, "udp bind", ec);
        co_return false;
    }

    co_return true;
}

void remote_udp_session::record_udp_write(const std::size_t bytes)
{
    const auto ts = now_ms();
    last_write_time_ms_.store(ts, std::memory_order_release);
    ctx_.add_tx_bytes(bytes);
    last_activity_time_ms_.store(ts, std::memory_order_release);
}

boost::asio::awaitable<void> remote_udp_session::forward_mux_payload(const std::vector<std::uint8_t>& data)
{
    socks_udp_header header;
    if (!socks_codec::decode_udp_header(data.data(), data.size(), header))
    {
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=invalid_udp_header", log_event::kMux);
        co_return;
    }
    if (header.frag != 0x00)
    {
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=unsupported_frag frag={}", log_event::kMux, header.frag);
        co_return;
    }
    if (header.addr.empty())
    {
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=empty_target_host", log_event::kMux);
        co_return;
    }
    if (header.port == 0)
    {
        LOG_CTX_WARN(ctx_, "{} stage=decode_header error=invalid_target_port", log_event::kMux);
        co_return;
    }

    if (header.header_len > data.size())
    {
        LOG_CTX_WARN(
            ctx_, "{} stage=decode_header error=invalid_header_len header_len={} packet_len={}", log_event::kMux, header.header_len, data.size());
        co_return;
    }

    const auto resolve_timeout_ms = read_timeout_ms_;
    const auto resolve_res =
        co_await timeout_io::async_resolve_with_timeout(udp_resolver_, header.addr, std::to_string(header.port), resolve_timeout_ms);
    if (!resolve_res.ok)
    {
        if (resolve_res.timed_out)
        {
            statistics::instance().inc_remote_udp_session_resolve_timeouts();
            LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} timeout={}ms", log_event::kMux, header.addr, header.port, resolve_timeout_ms);
        }
        else
        {
            statistics::instance().inc_remote_udp_session_resolve_errors();
            LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} error={}", log_event::kMux, header.addr, header.port, resolve_res.ec.message());
        }
        co_return;
    }

    if (resolve_res.endpoints.begin() == resolve_res.endpoints.end())
    {
        LOG_CTX_WARN(ctx_, "{} stage=resolve target={}:{} error=empty_result", log_event::kMux, header.addr, header.port);
        co_return;
    }

    const auto target_ep = normalize_target_endpoint(resolve_res.endpoints.begin()->endpoint());
    const auto payload_len = data.size() - header.header_len;
    LOG_CTX_DEBUG(ctx_, "{} udp forwarding {} bytes to {}", log_event::kMux, payload_len, target_ep.address().to_string());

    const auto [send_ec, sent_len] = co_await udp_socket_.async_send_to(
        boost::asio::buffer(data.data() + header.header_len, payload_len), target_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        LOG_CTX_WARN(
            ctx_, "{} stage=send target={}:{} error={}", log_event::kMux, target_ep.address().to_string(), target_ep.port(), send_ec.message());
        co_return;
    }

    record_udp_write(sent_len);
}

void remote_udp_session::log_udp_local_endpoint()
{
    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp local endpoint failed {}", log_event::kMux, local_ep_ec.message());
        return;
    }
    LOG_CTX_INFO(ctx_, "{} udp session started bound at {}", log_event::kMux, local_ep.address().to_string());
}

boost::asio::awaitable<void> remote_udp_session::run_udp_session_loops()
{
    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (mux_to_udp() || udp_to_mux() || watchdog() || idle_watchdog());
}

boost::asio::awaitable<void> remote_udp_session::cleanup_after_stop()
{
    request_stop();
    const auto already_cleaned = cleaned_up_.exchange(true, std::memory_order_acq_rel);
    if (already_cleaned)
    {
        co_return;
    }
    close_socket();
    if (auto conn = connection_.lock())
    {
        (void)co_await conn->send_async(id_, kCmdRst, {});
    }
    if (auto manager = manager_.lock())
    {
        manager->remove_stream(id_);
    }
    co_return;
}

boost::asio::awaitable<void> remote_udp_session::start_impl(std::shared_ptr<remote_udp_session> self)
{
    (void)self;
    auto conn = connection_.lock();
    if (!conn)
    {
        co_await cleanup_after_stop();
        co_return;
    }

    if (terminated_.load(std::memory_order_acquire))
    {
        co_await cleanup_after_stop();
        co_return;
    }

    if (!(co_await setup_udp_socket(conn)))
    {
        co_return;
    }

    if (terminated_.load(std::memory_order_acquire))
    {
        co_await cleanup_after_stop();
        co_return;
    }

    log_udp_local_endpoint();

    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        co_await handle_start_failure(conn, "udp local endpoint", local_ep_ec);
        co_return;
    }
    const ack_payload ack{
        .socks_rep = socks::kRepSuccess,
        .bnd_addr = local_ep.address().to_string(),
        .bnd_port = local_ep.port(),
    };
    if (const auto ack_ec = co_await send_ack_payload(conn, ack))
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ack_ec.message());
        co_await cleanup_after_stop();
        co_return;
    }

    if (terminated_.load(std::memory_order_acquire))
    {
        co_await cleanup_after_stop();
        co_return;
    }

    co_await run_udp_session_loops();
    co_await cleanup_after_stop();
    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

void remote_udp_session::on_data(std::vector<std::uint8_t> data)
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [self = shared_from_this(), data = std::move(data)]() mutable
                                           {
                                               if (!self->recv_channel_.try_send(boost::system::error_code(), std::move(data)))
                                               {
                                                   log_remote_udp_recv_channel_unavailable_on_data(self->ctx_);
                                                   self->request_stop();
                                               }
                                           });
}

void remote_udp_session::request_stop()
{
    const auto already_terminated = terminated_.exchange(true, std::memory_order_acq_rel);
    if (already_terminated)
    {
        return;
    }
    recv_channel_.close();
    timer_.cancel();
    idle_timer_.cancel();
    udp_resolver_.cancel();
    boost::system::error_code ignore;
    ignore = udp_socket_.cancel(ignore);
    close_socket();
    if (auto manager = manager_.lock())
    {
        manager->remove_stream(id_);
    }
}

void remote_udp_session::close_socket()
{
    if (!udp_socket_.is_open())
    {
        return;
    }
    boost::system::error_code ignore;
    ignore = udp_socket_.close(ignore);
}

void remote_udp_session::on_close()
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   self->request_stop();
                                               }
                                           });
}

void remote_udp_session::on_reset() { on_close(); }

boost::asio::awaitable<void> remote_udp_session::watchdog()
{
    while (udp_socket_.is_open())
    {
        timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            if (wait_ec == boost::asio::error::operation_aborted)
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
        bool timeout_triggered = false;
        if (read_timeout_ms_ > 0 && read_elapsed_ms > read_timeout_ms_)
        {
            LOG_CTX_WARN(ctx_, "{} read idle {}s", log_event::kTimeout, read_elapsed_ms / 1000ULL);
            timeout_triggered = true;
        }
        if (write_timeout_ms_ > 0 && write_elapsed_ms > write_timeout_ms_)
        {
            LOG_CTX_WARN(ctx_, "{} write idle {}s", log_event::kTimeout, write_elapsed_ms / 1000ULL);
            timeout_triggered = true;
        }
        if (timeout_triggered)
        {
            request_stop();
            break;
        }
    }
    LOG_CTX_DEBUG(ctx_, "{} watchdog finished", log_event::kMux);
}

boost::asio::awaitable<void> remote_udp_session::mux_to_udp()
{
    for (;;)
    {
        const auto [recv_ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec || data.empty())
        {
            break;
        }

        co_await forward_mux_payload(data);
    }
}

boost::asio::awaitable<void> remote_udp_session::udp_to_mux()
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint ep;
    boost::asio::ip::udp::endpoint cached_ep;
    std::vector<std::uint8_t> cached_header;
    bool has_cached_header = false;
    for (;;)
    {
        const auto [recv_ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), ep, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != boost::asio::error::operation_aborted)
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

        const auto normalized_ep = net::normalize_endpoint(ep);
        if (!has_cached_header || cached_ep != normalized_ep)
        {
            socks_udp_header h;
            h.addr = normalized_ep.address().to_string();
            h.port = normalized_ep.port();
            cached_header = socks_codec::encode_udp_header(h);
            if (cached_header.empty())
            {
                LOG_CTX_WARN(ctx_, "{} failed to encode udp header for {}", log_event::kMux, h.addr);
                has_cached_header = false;
                continue;
            }
            cached_ep = normalized_ep;
            has_cached_header = true;
        }

        std::vector<std::uint8_t> pkt;
        pkt.reserve(cached_header.size() + n);
        pkt.insert(pkt.end(), cached_header.begin(), cached_header.end());
        pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<std::uint32_t>(n));
        const auto pkt_size = pkt.size();
        if (pkt_size > mux::kMaxPayloadPerRecord)
        {
            LOG_CTX_WARN(ctx_, "{} drop oversized udp packet size {}", log_event::kMux, pkt_size);
            continue;
        }

        if (auto conn = connection_.lock())
        {
            const auto send_ec = co_await conn->send_async(id_, kCmdDat, std::move(pkt));
            if (!send_ec)
            {
                continue;
            }
            if (send_ec == boost::asio::error::message_size)
            {
                LOG_CTX_WARN(ctx_, "{} drop oversized udp packet size {}", log_event::kMux, pkt_size);
                continue;
            }
            LOG_CTX_WARN(ctx_, "{} send udp packet to mux failed {}", log_event::kMux, send_ec.message());
            break;
        }
        else
        {
            break;
        }
    }
}

boost::asio::awaitable<void> remote_udp_session::idle_watchdog()
{
    if (idle_timeout_ms_ == 0)
    {
        co_return;
    }

    while (udp_socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto current_ms = now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_.load(std::memory_order_acquire);
        if (elapsed_ms > idle_timeout_ms_)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kMux);
            request_stop();
            break;
        }
    }
}

}    // namespace mux
