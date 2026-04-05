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
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "constants.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "scoped_exit.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "mux_session_utils.h"
#include "remote_udp_session.h"
namespace mux
{

namespace
{

[[nodiscard]] bool is_expected_udp_stream_shutdown(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor ||
           ec == boost::asio::experimental::error::channel_errors::channel_closed ||
           ec == boost::asio::experimental::error::channel_errors::channel_cancelled;
}

}    // namespace

remote_udp_session::remote_udp_session(boost::asio::io_context& io_context,
                                       const std::shared_ptr<mux_connection>& connection,
                                       uint32_t id,
                                       uint32_t conn_id,
                                       uint64_t trace_id,
                                       const config& cfg)
    : id_(id),
      trace_id_(trace_id),
      conn_id_(conn_id),
      cfg_(cfg),
      idle_timer_(io_context),
      udp_socket_(io_context),
      udp_resolver_(io_context),
      stream_(connection != nullptr ? connection->create_incoming_stream(id) : nullptr),
      connection_(connection),
      resolved_targets_(constants::udp::kMaxCacheEntries),
      allowed_reply_peers_(constants::udp::kMaxCacheEntries)

{
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
    last_activity_time_ms_ = net::now_ms();
}

bool remote_udp_session::has_stream() const { return stream_ != nullptr; }

boost::asio::awaitable<void> remote_udp_session::start()
{
    if (stream_ == nullptr)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} start udp session without stream",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_);
        co_return;
    }

    co_await start_impl();
}

boost::asio::awaitable<void> remote_udp_session::start_impl()
{
    DEFER(if (auto connection = connection_.lock(); connection != nullptr && stream_ != nullptr) { connection->close_and_remove_stream(stream_); });
    DEFER(boost::system::error_code ignore; ignore = udp_socket_.close(ignore); (void)ignore;);

    boost::system::error_code ec;

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

            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} stage open_dual_stack_udp error {} fallback ipv4",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     ec.message());
            boost::system::error_code close_ec;
            close_ec = udp_socket_.close(close_ec);
            (void)close_ec;
        }
        else
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} stage open_ipv6_udp error {} fallback ipv4",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     ec.message());
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} stage bind_udp_socket error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 ec.message());
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepGenFail);
        co_return;
    }

    boost::system::error_code local_ep_ec;
    const auto local_ep = udp_socket_.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} stage query_bind_endpoint error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 local_ep_ec.message());
        co_await session_util::send_fail_ack(stream_, id_, socks::kRepGenFail);
        co_return;
    }
    bind_host_ = local_ep.address().to_string();
    bind_port_ = local_ep.port();
    const ack_payload ack{
        .socks_rep = socks::kRepSuccess,
        .bnd_addr = bind_host_,
        .bnd_port = bind_port_,
    };
    std::vector<uint8_t> ack_data;
    if (!mux_codec::encode_ack(ack, ack_data))
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} send ack encode failed",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_);
        co_return;
    }
    mux_frame ack_frame;
    ack_frame.h.stream_id = id_;
    ack_frame.h.command = mux::kCmdAck;
    ack_frame.payload = std::move(ack_data);
    co_await stream_->async_write(ack_frame, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} send ack failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 ec.message());
        co_return;
    }
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} udp associate ready bind {}:{}",
             log_event::kConnEstablished,
             trace_id_,
             conn_id_,
             id_,
             bind_host_,
             bind_port_);

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
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} send {} failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     close_command == mux::kCmdRst ? "rst" : "fin",
                     close_ec.message());
        }
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             id_,
             bind_host_,
             bind_port_,
             tx_bytes_,
             rx_bytes_,
             duration_ms);
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
            if (is_expected_udp_stream_shutdown(ec))
            {
                LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage mux_to_udp read_frame stopped {}",
                         log_event::kConnClose,
                         trace_id_,
                         conn_id_,
                         id_,
                         bind_host_,
                         bind_port_,
                         ec.message());
            }
            else
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage mux_to_udp read_frame error {}",
                         log_event::kMux,
                         trace_id_,
                         conn_id_,
                         id_,
                         bind_host_,
                         bind_port_,
                         ec.message());
            }
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage mux_to_udp recv_control cmd {} cmd_name {} payload_size {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     data_frame.h.command,
                     session_util::mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (data_frame.h.command != mux::kCmdDat)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage mux_to_udp unexpected_cmd {} cmd_name {} payload_size {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     data_frame.h.command,
                     session_util::mux_command_name(data_frame.h.command),
                     data_frame.payload.size());
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            ec = boost::asio::error::invalid_argument;
            break;
        }
        co_await on_frame(data_frame, ec);
        if (ec)
        {
            if (ec == boost::asio::error::invalid_argument || ec == boost::system::errc::make_error_code(boost::system::errc::bad_message))
            {
                session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            }
            else
            {
                session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            }
            break;
        }
    }
    LOG_INFO("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} mux_to_udp finished tx_bytes {}",
             log_event::kMux,
             trace_id_,
             conn_id_,
             id_,
             bind_host_,
             bind_port_,
             tx_bytes_);
}

boost::asio::awaitable<void> remote_udp_session::on_frame(const mux_frame& frame, boost::system::error_code& ec)
{
    socks_udp_header header;
    if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage decode_header error invalid_udp_header",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_);
        co_return;
    }
    if (header.frag != 0x00)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage decode_header error unsupported_frag target {}:{} frag {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 header.addr,
                 header.port,
                 header.frag);
        co_return;
    }
    if (header.addr.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage decode_header error empty_target_host",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_);
        co_return;
    }
    if (header.port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage decode_header error invalid_target_port target {}:{}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 header.addr,
                 header.port);
        co_return;
    }

    if (header.header_len > frame.payload.size())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN(
            "event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage decode_header error invalid_header_len target {}:{} header_len {} "
            "packet_len {}",
            log_event::kMux,
            trace_id_,
            conn_id_,
            id_,
            bind_host_,
            bind_port_,
            header.addr,
            header.port,
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} target {}:{} drop oversized udp payload size {} max {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 header.addr,
                 header.port,
                 payload_len,
                 constants::udp::kMaxPayload);
        co_return;
    }
    LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp forwarding {} bytes to {}:{}",
              log_event::kMux,
              trace_id_,
              conn_id_,
              id_,
              bind_host_,
              bind_port_,
              payload_len,
              target_ep.address().to_string(),
              target_ep.port());
    co_await udp_socket_.async_send_to(boost::asio::buffer(frame.payload.data() + header.header_len, payload_len),
                                       target_ep,
                                       boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage send target {}:{} error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 target_ep.address().to_string(),
                 target_ep.port(),
                 ec.message());
        co_return;
    }
    last_activity_time_ms_ = net::now_ms();
    tx_bytes_ += payload_len;
    const auto normalized_target = net::normalize_endpoint(target_ep);
    const auto now_ms = net::now_ms();
    const auto expires_at = now_ms + constants::udp::kCacheTtlMs;
    allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
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
                LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp receive stopped {}",
                          log_event::kMux,
                          trace_id_,
                          conn_id_,
                          id_,
                          bind_host_,
                          bind_port_,
                          ec.message());
            }
            else
            {
                LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp receive error {}",
                         log_event::kMux,
                         trace_id_,
                         conn_id_,
                         id_,
                         bind_host_,
                         bind_port_,
                         ec.message());
            }
            break;
        }

        LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp recv {} bytes from {}:{}",
                  log_event::kMux,
                  trace_id_,
                  conn_id_,
                  id_,
                  bind_host_,
                  bind_port_,
                  n,
                  ep.address().to_string(),
                  ep.port());
        const auto normalized_ep = net::normalize_endpoint(ep);
        const auto now_ms = net::now_ms();
        allowed_reply_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms; });
        auto* peer = allowed_reply_peers_.get(normalized_ep);
        if (peer == nullptr || peer->expires_at <= now_ms)
        {
            if (peer != nullptr && peer->expires_at <= now_ms)
            {
                allowed_reply_peers_.erase(normalized_ep);
            }
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} ignore udp packet from unexpected peer {}:{}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     normalized_ep.address().to_string(),
                     normalized_ep.port());
            continue;
        }
        rx_bytes_ += n;
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
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} peer {}:{} drop oversized udp packet size {} max {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     normalized_ep.address().to_string(),
                     normalized_ep.port(),
                     pkt_size,
                     mux::kMaxPayload);
            continue;
        }
        mux_frame data_frame;
        data_frame.h.stream_id = id_;
        data_frame.h.command = kCmdDat;
        data_frame.payload = std::move(pkt);
        co_await stream_->async_write(data_frame, ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} peer {}:{} send udp packet to mux failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     normalized_ep.address().to_string(),
                     normalized_ep.port(),
                     ec.message());
            break;
        }
        const auto refresh_now_ms = net::now_ms();
        if (auto* refreshed_peer = allowed_reply_peers_.get(normalized_ep); refreshed_peer != nullptr)
        {
            refreshed_peer->expires_at = refresh_now_ms + constants::udp::kCacheTtlMs;
        }
        last_activity_time_ms_ = refresh_now_ms;
        tx_bytes_ += pkt_size;
    }
    LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp recv loop stopped",
              log_event::kMux,
              trace_id_,
              conn_id_,
              id_,
              bind_host_,
              bind_port_);
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> remote_udp_session::resolve_target_endpoint(const std::string& host,
                                                                                                   uint16_t port,
                                                                                                   boost::system::error_code& ec)
{
    ec.clear();
    const auto key = session_util::udp_target_key(host, port);
    const auto now_ms = net::now_ms();
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

    auto res = co_await net::wait_resolve_with_timeout(udp_resolver_, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage resolve target {}:{} error {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 host,
                 port,
                 ec.message());
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }
    if (res.begin() == res.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage resolve target {}:{} error empty_result",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 host,
                 port);
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage resolve target {}:{} error local_endpoint_failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 host,
                 port,
                 local_ep_ec.message());
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
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} stage resolve target {}:{} error no_compatible_endpoint",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 id_,
                 bind_host_,
                 bind_port_,
                 host,
                 port);
        resolved_targets_.put(
            key,
            endpoint_cache_entry{.endpoint = {}, .expires_at = now_ms + constants::udp::kNegativeCacheTtlMs, .last_error = ec, .negative = true});
        co_return boost::asio::ip::udp::endpoint{};
    }
    const auto expires_at = now_ms + constants::udp::kCacheTtlMs;
    resolved_targets_.put(key, endpoint_cache_entry{.endpoint = target, .expires_at = expires_at, .last_error = {}, .negative = false});
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
        const auto current_ms = net::now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} udp session idle closing timeout {}s",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     id_,
                     bind_host_,
                     bind_port_,
                     cfg_.timeout.idle);
            break;
        }
    }
    LOG_DEBUG("event {} trace_id {:016x} conn_id {} stream_id {} bind {}:{} idle watchdog stopped",
              log_event::kMux,
              trace_id_,
              conn_id_,
              id_,
              bind_host_,
              bind_port_);
}

}    // namespace mux
