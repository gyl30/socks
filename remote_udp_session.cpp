#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "constants.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "timeout_io.h"
#include "mux_stream.h"
#include "scoped_exit.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "connection_context.h"
#include "remote_udp_session.h"

namespace mux
{

namespace
{

void update_stream_close_command(std::atomic<uint8_t>& stream_close_command, const uint8_t next_command)
{
    auto current = stream_close_command.load(std::memory_order_relaxed);
    for (;;)
    {
        uint8_t desired = current;
        if (next_command == mux::kCmdRst)
        {
            desired = mux::kCmdRst;
        }
        else if (next_command == mux::kNoStreamControl && current != mux::kCmdRst)
        {
            desired = mux::kNoStreamControl;
        }
        if (desired == current)
        {
            return;
        }
        if (stream_close_command.compare_exchange_weak(current, desired, std::memory_order_relaxed))
        {
            return;
        }
    }
}

[[nodiscard]] std::string udp_target_key(const std::string& host, const uint16_t port) { return host + "|" + std::to_string(port); }

template <typename Cache>
void evict_expired(Cache& cache, const uint64_t now_ms)
{
    cache.evict_while([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
}

}    // namespace

remote_udp_session::remote_udp_session(boost::asio::io_context& io_context,
                                       const std::shared_ptr<mux_connection>& connection,
                                       const uint32_t id,
                                       const connection_context& ctx,
                                       const config& cfg)
    : id_(id),
      cfg_(cfg),
      idle_timer_(io_context),
      udp_socket_(io_context),
      udp_resolver_(io_context),
      stream_(connection != nullptr ? connection->create_incoming_stream(id) : nullptr),
      connection_(connection),
      resolved_targets_(constants::udp::kMaxCacheEntries),
      allowed_reply_peers_(constants::udp::kMaxCacheEntries)

{
    ctx_ = ctx;
    ctx_.stream_id(id);
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
    last_activity_time_ms_ = timeout_io::now_ms();
}

bool remote_udp_session::has_stream() const
{
    return stream_ != nullptr;
}

boost::asio::awaitable<void> remote_udp_session::start()
{
    if (stream_ == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} start udp session without stream {}", log_event::kMux, id_);
        co_return;
    }

    co_await start_impl();
}

boost::asio::awaitable<void> remote_udp_session::start_impl()
{
    DEFER(if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr) { connection->close_and_remove_stream(stream_); });
    DEFER(boost::system::error_code ignore; ignore = udp_socket_.close(ignore); (void)ignore;);

    boost::system::error_code ec;
    const auto send_fail_ack = [&](const uint8_t rep) -> boost::asio::awaitable<void>
    {
        const ack_payload ack{.socks_rep = rep, .bnd_addr = "0.0.0.0", .bnd_port = 0};
        std::vector<uint8_t> ack_data;
        if (!mux_codec::encode_ack(ack, ack_data))
        {
            co_return;
        }

        mux_frame ack_frame;
        ack_frame.h.stream_id = id_;
        ack_frame.h.command = mux::kCmdAck;
        ack_frame.payload = std::move(ack_data);
        boost::system::error_code ack_ec;
        co_await stream_->async_write(ack_frame, ack_ec);
    };

    auto bind_udp_socket = [&]() -> bool
    {
        ec = udp_socket_.open(boost::asio::ip::udp::v6(), ec);
        if (!ec)
        {
            ec = udp_socket_.set_option(boost::asio::ip::v6_only(false), ec);
            if (!ec)
            {
                ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v6(), 0), ec);
            }
            if (!ec)
            {
                return true;
            }

            LOG_CTX_WARN(ctx_, "{} bind dual-stack udp failed {} fallback ipv4", log_event::kMux, ec.message());
            boost::system::error_code close_ec;
            close_ec = udp_socket_.close(close_ec);
            (void)close_ec;
        }
        else
        {
            LOG_CTX_WARN(ctx_, "{} open ipv6 udp failed {} fallback ipv4", log_event::kMux, ec.message());
        }

        ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
        {
            return false;
        }
        ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        return !ec;
    };

    if (!bind_udp_socket())
    {
        co_await send_fail_ack(socks::kRepGenFail);
        co_return;
    }

    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        co_await send_fail_ack(socks::kRepGenFail);
        co_return;
    }
    const ack_payload ack{
        .socks_rep = socks::kRepSuccess,
        .bnd_addr = local_ep.address().to_string(),
        .bnd_port = local_ep.port(),
    };
    std::vector<uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        co_return;
    }
    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload = std::move(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} send ack failed {}", log_event::kMux, ec.message());
        co_return;
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (mux_to_udp() || udp_to_mux());
    }
    else
    {
        co_await (mux_to_udp() || udp_to_mux() || idle_watchdog());
    }

    const auto close_command = stream_close_command_.load(std::memory_order_relaxed);
    if (stream_ != nullptr && close_command != mux::kNoStreamControl)
    {
        mux_frame close_frame;
        close_frame.h.stream_id = stream_->id();
        close_frame.h.command = close_command;
        boost::system::error_code close_ec;
        co_await stream_->async_write(std::move(close_frame), close_ec);
        if (close_ec)
        {
            LOG_CTX_WARN(ctx_, "{} send {} failed {}", log_event::kMux, close_command == mux::kCmdRst ? "rst" : "fin", close_ec.message());
        }
    }

    LOG_CTX_INFO(ctx_, "{} finished {}", log_event::kConnClose, ctx_.stats_summary());
}

boost::asio::awaitable<void> remote_udp_session::mux_to_udp()
{
    boost::system::error_code ec;
    for (;;)
    {
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto data_frame = co_await stream_->async_read(read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
        {
            update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (data_frame.h.command != mux::kCmdDat)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            ec = boost::asio::error::invalid_argument;
            break;
        }
        co_await on_frame(data_frame, ec);
        if (ec)
        {
            if (ec == boost::asio::error::invalid_argument || ec == boost::system::errc::make_error_code(boost::system::errc::bad_message))
            {
                update_stream_close_command(stream_close_command_, mux::kCmdRst);
            }
            else
            {
                update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            }
            break;
        }
    }
    LOG_CTX_INFO(ctx_, "{} mux_to_udp finished", log_event::kMux);
}

boost::asio::awaitable<void> remote_udp_session::on_frame(const mux_frame& frame, boost::system::error_code& ec)
{
    socks_udp_header header;
    if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage decode_header error invalid_udp_header", log_event::kMux);
        co_return;
    }
    if (header.frag != 0x00)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage decode_header error unsupported_frag frag {}", log_event::kMux, header.frag);
        co_return;
    }
    if (header.addr.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage decode_header error empty_target_host", log_event::kMux);
        co_return;
    }
    if (header.port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_, "{} stage decode_header error invalid_target_port", log_event::kMux);
        co_return;
    }

    if (header.header_len > frame.payload.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx_,
                     "{} stage decode_header error invalid_header_len header_len {} packet_len {}",
                     log_event::kMux,
                     header.header_len,
                     frame.payload.size());
        co_return;
    }

    auto target_ep = co_await resolve_target_endpoint(header.addr, header.port, ec);
    if (ec)
    {
        ec.clear();
        co_return;
    }
    const auto payload_len = frame.payload.size() - header.header_len;
    if (payload_len > constants::udp::kMaxPayload)
    {
        LOG_CTX_WARN(ctx_, "{} drop oversized udp payload size {} max {}", log_event::kMux, payload_len, constants::udp::kMaxPayload);
        co_return;
    }
    LOG_CTX_DEBUG(ctx_, "{} udp forwarding {} bytes to {}", log_event::kMux, payload_len, target_ep.address().to_string());
    co_await udp_socket_.async_send_to(boost::asio::buffer(frame.payload.data() + header.header_len, payload_len),
                                       target_ep,
                                       boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} stage send target {}:{} error {}", log_event::kMux, target_ep.address().to_string(), target_ep.port(), ec.message());
        co_return;
    }
    last_activity_time_ms_ = timeout_io::now_ms();
    ctx_.add_tx_bytes(payload_len);
    const auto normalized_target = net::normalize_endpoint(target_ep);
    const auto now_ms = timeout_io::now_ms();
    const auto expires_at = now_ms + constants::udp::kCacheTtlMs;
    evict_expired(allowed_reply_peers_, now_ms);
    allowed_reply_peers_.put(normalized_target, peer_cache_entry{expires_at});
}

boost::asio::awaitable<void> remote_udp_session::udp_to_mux()
{
    std::vector<uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint ep;
    boost::system::error_code ec;
    for (;;)
    {
        auto n = co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), ep, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor)
            {
                LOG_CTX_DEBUG(ctx_, "{} udp receive stopped {}", log_event::kMux, ec.message());
            }
            else
            {
                LOG_CTX_WARN(ctx_, "{} udp receive error {}", log_event::kMux, ec.message());
            }
            break;
        }

        LOG_CTX_DEBUG(ctx_, "{} udp recv {} bytes from {}", log_event::kMux, n, ep.address().to_string());
        const auto normalized_ep = net::normalize_endpoint(ep);
        const auto now_ms = timeout_io::now_ms();
        evict_expired(allowed_reply_peers_, now_ms);
        auto* peer = allowed_reply_peers_.get(normalized_ep);
        if (peer == nullptr || peer->expires_at <= now_ms)
        {
            if (peer != nullptr && peer->expires_at <= now_ms)
            {
                allowed_reply_peers_.erase(normalized_ep);
            }
            LOG_CTX_WARN(
                ctx_, "{} ignore udp packet from unexpected peer {}:{}", log_event::kMux, normalized_ep.address().to_string(), normalized_ep.port());
            continue;
        }
        ctx_.add_rx_bytes(n);
        socks_udp_header h;
        h.addr = normalized_ep.address().to_string();
        h.port = normalized_ep.port();
        auto header_bytes = socks_codec::encode_udp_header(h);

        std::vector<uint8_t> pkt;
        pkt.reserve(header_bytes.size() + n);
        pkt.insert(pkt.end(), header_bytes.begin(), header_bytes.end());
        pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<uint32_t>(n));
        const auto pkt_size = pkt.size();
        if (pkt_size > mux::kMaxPayload)
        {
            LOG_CTX_WARN(ctx_, "{} drop oversized udp packet size {} max {}", log_event::kMux, pkt_size, mux::kMaxPayload);
            continue;
        }
        mux_frame data_frame;
        data_frame.h.stream_id = id_;
        data_frame.h.command = kCmdDat;
        data_frame.payload = std::move(pkt);
        co_await stream_->async_write(data_frame, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} send udp packet to mux failed {}", log_event::kMux, ec.message());
            break;
        }
        const auto refresh_now_ms = timeout_io::now_ms();
        if (auto* refreshed_peer = allowed_reply_peers_.get(normalized_ep); refreshed_peer != nullptr)
        {
            refreshed_peer->expires_at = refresh_now_ms + constants::udp::kCacheTtlMs;
        }
        last_activity_time_ms_ = refresh_now_ms;
        ctx_.add_tx_bytes(pkt_size);
    }
    LOG_CTX_DEBUG(ctx_, "{} udp recv loop stopped", log_event::kMux);
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> remote_udp_session::resolve_target_endpoint(const std::string& host,
                                                                                                   const uint16_t port,
                                                                                                   boost::system::error_code& ec)
{
    ec.clear();
    const auto key = udp_target_key(host, port);
    const auto now_ms = timeout_io::now_ms();
    resolved_targets_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
    auto* cached = resolved_targets_.get(key);
    if (cached != nullptr)
    {
        if (cached->expires_at <= now_ms)
        {
            resolved_targets_.erase(key);
        }
        else
        {
            if (cached->negative)
            {
                ec = cached->last_error;
                co_return boost::asio::ip::udp::endpoint{};
            }
            cached->expires_at = now_ms + constants::udp::kCacheTtlMs;
            co_return cached->endpoint;
        }
    }

    auto res = co_await timeout_io::wait_resolve_with_timeout(udp_resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} stage resolve target {}:{} error {}", log_event::kMux, host, port, ec.message());
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }
    if (res.begin() == res.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_CTX_WARN(ctx_, "{} stage resolve target {}:{} error empty_result", log_event::kMux, host, port);
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }

    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        ec = local_ep_ec;
        LOG_CTX_WARN(ctx_, "{} stage resolve target {}:{} error local_endpoint_failed", log_event::kMux, host, port);
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }
    const bool v4_only = local_ep.address().is_v4();
    boost::asio::ip::udp::endpoint target;
    bool found = false;
    for (const auto& endpoint : res)
    {
        const auto normalized = net::normalize_endpoint(endpoint.endpoint());
        if (v4_only && normalized.address().is_v6())
        {
            continue;
        }
        target = normalized;
        found = true;
        break;
    }
    if (!found)
    {
        ec = boost::asio::error::address_family_not_supported;
        LOG_CTX_WARN(ctx_, "{} stage resolve target {}:{} error no_compatible_endpoint", log_event::kMux, host, port);
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }
    const auto expires_at = now_ms + constants::udp::kCacheTtlMs;
    resolved_targets_.put(key, endpoint_cache_entry{.endpoint=target, .expires_at=expires_at, .last_error={}, .negative=false});
    co_return target;
}

boost::asio::awaitable<void> remote_udp_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }
    auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;
    while (udp_socket_.is_open())
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            break;
        }
        const auto current_ms = timeout_io::now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kMux);
            break;
        }
    }
    LOG_CTX_DEBUG(ctx_, "{} idle watchdog stopped", log_event::kMux);
}

}    // namespace mux
