#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <functional>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "constants.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "mux_session_utils.h"
#include "client_tunnel_pool.h"
#include "connection_tracker.h"
#include "tproxy_udp_session.h"
#include "trace_id.h"
namespace mux
{

namespace
{

void set_socket_reuse_port(int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    constexpr int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
#else
    (void)fd;
    ec = boost::system::error_code(static_cast<int>(boost::system::errc::not_supported), boost::system::generic_category());
#endif
}

boost::asio::awaitable<std::shared_ptr<mux_stream>> connect_remote_udp_stream(const std::shared_ptr<mux_connection>& tunnel,
                                                                              uint32_t conn_id,
                                                                              uint64_t trace_id,
                                                                              const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                              boost::system::error_code& ec)
{
    ec.clear();
    if (tunnel == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_WARN("event {} trace_id {:016x} conn_id {} target {}:{} no active tunnel for udp associate",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
        co_return nullptr;
    }

    auto stream = tunnel->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::operation_aborted;
        LOG_WARN("event {} trace_id {:016x} conn_id {} target {}:{} create udp stream failed tunnel_ptr {}",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 static_cast<const void*>(tunnel.get()));
        co_return nullptr;
    }

    const syn_payload syn{
        .socks_cmd = socks::kCmdUdpAssociate,
        .addr = "0.0.0.0",
        .port = 0,
        .trace_id = trace_id,
    };
    std::vector<uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::asio::error::invalid_argument;
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} encode udp syn failed",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = mux::kCmdSyn;
    syn_frame.payload = std::move(syn_data);
    co_await stream->async_write(std::move(syn_frame), ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} send udp syn failed {}",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 ec.message());
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    const auto ack_frame = co_await stream->async_read(ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} read udp ack failed {}",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 ec.message());
        co_await session_util::send_stream_reset(stream, log_event::kMux, conn_id, "read_udp_ack");
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }
    if (ack_frame.h.command != mux::kCmdAck)
    {
        ec = boost::asio::error::invalid_argument;
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} unexpected udp ack command {}",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 ack_frame.h.command);
        co_await session_util::send_stream_reset(stream, log_event::kMux, conn_id, "unexpected_udp_ack_command");
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    ack_payload ack{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack))
    {
        ec = boost::asio::error::invalid_argument;
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} invalid udp ack payload",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
        co_await session_util::send_stream_reset(stream, log_event::kMux, conn_id, "invalid_udp_ack_payload");
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }
    if (ack.socks_rep != socks::kRepSuccess)
    {
        ec = boost::asio::error::operation_aborted;
        LOG_WARN("event {} trace_id {:016x} conn_id {} stream_id {} target {}:{} udp ack rejected rep {}",
                 log_event::kMux,
                 trace_id,
                 conn_id,
                 stream->id(),
                 target_endpoint.address().to_string(),
                 target_endpoint.port(),
                 ack.socks_rep);
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    co_return stream;
}

}    // namespace

tproxy_udp_session::tproxy_udp_session(io_worker& worker,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       const boost::asio::ip::udp::endpoint& client_endpoint,
                                       const boost::asio::ip::udp::endpoint& target_endpoint,
                                       const route_type route,
                                       uint32_t conn_id,
                                       const config& cfg,
                                       std::function<void()> on_close)
    : trace_id_(generate_trace_id()),
      conn_id_(conn_id),
      cfg_(cfg),
      worker_(worker),
      route_(route),
      last_activity_time_ms_(net::now_ms()),
      idle_timer_(worker.io_context),
      upstream_socket_(worker.io_context),
      tunnel_pool_(std::move(tunnel_pool)),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close)),
      packet_channel_(worker.io_context, constants::udp::kPacketChannelCapacity),
      reply_sockets_(constants::udp::kMaxReplySockets)
{
    active_guard_ = acquire_active_connection_guard();
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
}

void tproxy_udp_session::start()
{
    worker_.group.spawn([self = shared_from_this()]() -> boost::asio::awaitable<void> { co_await self->run(); });
}

void tproxy_udp_session::stop() { close_impl(); }

boost::asio::awaitable<udp_enqueue_result> tproxy_udp_session::enqueue_packet(std::vector<uint8_t> payload)
{
    if (stopped_.load(std::memory_order_relaxed))
    {
        co_return udp_enqueue_result::kClosed;
    }

    if (payload.size() > constants::udp::kMaxPacketSize)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} drop udp packet because payload too large size {} max {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 payload.size(),
                 constants::udp::kMaxPacketSize);
        co_return udp_enqueue_result::kDroppedOverflow;
    }

    const auto [send_ec] =
        co_await packet_channel_.async_send(boost::system::error_code{}, std::move(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        if (stopped_.load(std::memory_order_relaxed) || send_ec == boost::asio::error::operation_aborted ||
            send_ec == boost::asio::error::bad_descriptor || send_ec == boost::asio::experimental::error::channel_errors::channel_closed)
        {
            co_return udp_enqueue_result::kClosed;
        }

        LOG_WARN("event {} trace_id {:016x} conn_id {} enqueue udp packet failed {} client {}:{} target {}:{}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 send_ec.message(),
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port());
        co_return udp_enqueue_result::kClosed;
    }
    last_activity_time_ms_ = net::now_ms();
    co_return udp_enqueue_result::kEnqueued;
}

boost::asio::awaitable<void> tproxy_udp_session::run()
{
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} udp session started",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             mux::to_string(route_));
    const bool completed = (route_ == route_type::kDirect) ? co_await run_direct_mode() : co_await run_proxy_mode();
    notify_closed();
    if (!completed)
    {
        co_return;
    }
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             mux::to_string(route_),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

boost::asio::awaitable<bool> tproxy_udp_session::run_direct_mode()
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (!(co_await open_direct_socket()))
    {
        co_return false;
    }

    if (cfg_.timeout.idle == 0)
    {
        co_await (packets_to_direct() || direct_to_client());
    }
    else
    {
        co_await (packets_to_direct() || direct_to_client() || idle_watchdog());
    }
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::run_proxy_mode()
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (!(co_await open_proxy_stream()))
    {
        co_return false;
    }

    if (cfg_.timeout.idle == 0)
    {
        co_await (packets_to_proxy() || proxy_to_client());
    }
    else
    {
        co_await (packets_to_proxy() || proxy_to_client() || idle_watchdog());
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
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} send udp {} failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     close_command == mux::kCmdRst ? "rst" : "fin",
                     close_ec.message());
        }
    }

    if (tunnel_ != nullptr && stream_ != nullptr)
    {
        tunnel_->close_and_remove_stream(stream_);
    }
    stream_.reset();
    tunnel_.reset();
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::open_direct_socket()
{
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    ec = upstream_socket_.open(protocol, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} open direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    if (cfg_.tproxy.mark != 0)
    {
        net::set_socket_mark(upstream_socket_.native_handle(), cfg_.tproxy.mark, ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} set direct udp mark failed {}",
                     log_event::kConnInit,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            co_return false;
        }
    }

    ec = upstream_socket_.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} bind direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }
    ec = upstream_socket_.connect(target_endpoint_, ec);
    if (ec)
    {
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} connect direct udp socket failed {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    LOG_INFO("event {} trace_id {:016x} conn_id {} opened direct udp socket client {}:{} target {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port());
    co_return true;
}

boost::asio::awaitable<bool> tproxy_udp_session::open_proxy_stream()
{
    boost::system::error_code ec;
    tunnel_ = co_await wait_for_proxy_tunnel(ec);
    if (ec || tunnel_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::timed_out;
        }
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} wait udp tunnel failed {} active_tunnels {} total_slots {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message(),
                 tunnel_pool_ != nullptr ? tunnel_pool_->active_tunnels() : 0,
                 cfg_.limits.max_connections);
        co_return false;
    }
    LOG_DEBUG("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} selected udp tunnel ptr {}",
              log_event::kConnInit,
              trace_id_,
              conn_id_,
              client_endpoint_.address().to_string(),
              client_endpoint_.port(),
              target_endpoint_.address().to_string(),
              target_endpoint_.port(),
              static_cast<const void*>(tunnel_.get()));

    stream_ = co_await connect_remote_udp_stream(tunnel_, conn_id_, trace_id_, target_endpoint_, ec);
    if (ec || stream_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} open proxy udp stream failed {} tunnel_ptr {}",
                 log_event::kConnInit,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message(),
                 static_cast<const void*>(tunnel_.get()));
        tunnel_.reset();
        co_return false;
    }

    LOG_INFO("event {} trace_id {:016x} conn_id {} opened proxy udp stream client {}:{} target {}:{} stream_id {}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             stream_->id());
    co_return true;
}

boost::asio::awaitable<std::shared_ptr<mux_connection>> tproxy_udp_session::wait_for_proxy_tunnel(boost::system::error_code& ec) const
{
    ec.clear();
    const auto start_ms = net::now_ms();
    const auto connect_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.connect);

    for (;;)
    {
        if (stopped_.load(std::memory_order_relaxed))
        {
            ec = boost::asio::error::operation_aborted;
            co_return nullptr;
        }

        const auto tunnel = tunnel_pool_ != nullptr ? tunnel_pool_->select_tunnel() : nullptr;
        if (tunnel != nullptr)
        {
            co_return tunnel;
        }

        if (connect_timeout_ms != 0 && net::now_ms() - start_ms >= connect_timeout_ms)
        {
            ec = boost::asio::error::timed_out;
            co_return nullptr;
        }

        const auto wait_ec = co_await net::wait_for(worker_.io_context, std::chrono::milliseconds(constants::udp::kTunnelPollIntervalMs));
        if (wait_ec)
        {
            ec = wait_ec;
            co_return nullptr;
        }
    }
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_direct()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        const auto sent =
            co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        (void)sent;
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} send direct udp payload failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            break;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::direct_to_client()
{
    std::vector<uint8_t> buffer(65535);
    const auto normalized_target = net::normalize_endpoint(target_endpoint_);
    boost::system::error_code ec;
    for (;;)
    {
        const auto bytes_recv =
            co_await upstream_socket_.async_receive(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        if (!(co_await send_to_client(normalized_target, buffer.data(), bytes_recv)))
        {
            break;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_proxy()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto payload = co_await packet_channel_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            break;
        }

        const socks_udp_header header{
            .frag = 0,
            .addr = target_endpoint_.address().to_string(),
            .port = target_endpoint_.port(),
        };
        const auto header_bytes = socks_codec::encode_udp_header(header);
        mux_frame data_frame;
        data_frame.h.stream_id = stream_->id();
        data_frame.h.command = mux::kCmdDat;
        data_frame.payload.reserve(header_bytes.size() + payload.size());
        data_frame.payload.insert(data_frame.payload.end(), header_bytes.begin(), header_bytes.end());
        data_frame.payload.insert(data_frame.payload.end(), payload.begin(), payload.end());
        if (data_frame.payload.size() > mux::kMaxPayload)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} proxy udp payload too large {} max {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     data_frame.payload.size(),
                     mux::kMaxPayload);
            continue;
        }

        co_await stream_->async_write(std::move(data_frame), ec);
        if (ec)
        {
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} send proxy udp payload failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     ec.message());
            break;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_to_client()
{
    boost::system::error_code ec;
    for (;;)
    {
        const auto read_timeout = (cfg_.timeout.idle == 0) ? cfg_.timeout.read : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto frame = co_await stream_->async_read(read_timeout, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            break;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} unexpected proxy udp frame {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     frame.h.command);
            break;
        }

        socks_udp_header header;
        if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} decode proxy udp header failed",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id());
            break;
        }
        if (header.header_len > frame.payload.size())
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} proxy udp header length invalid {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     header.header_len);
            break;
        }
        if (header.frag != 0x00)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} proxy udp fragment unsupported {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     header.frag);
            break;
        }
        if (header.port == 0)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} proxy udp source port invalid",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id());
            break;
        }

        boost::system::error_code addr_ec;
        const auto source_addr = boost::asio::ip::make_address(header.addr, addr_ec);
        if (addr_ec)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} stream_id {} parse proxy udp source address failed {}",
                     log_event::kMux,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     addr_ec.message());
            break;
        }

        const boost::asio::ip::udp::endpoint source_endpoint(net::normalize_address(source_addr), header.port);
        const auto* payload = frame.payload.data() + header.header_len;
        const auto payload_len = frame.payload.size() - header.header_len;
        if (!(co_await send_to_client(source_endpoint, payload, payload_len)))
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            break;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::idle_watchdog()
{
    const auto idle_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_.load(std::memory_order_relaxed))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_INFO("event {} trace_id {:016x} conn_id {} udp session idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     trace_id_,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
            break;
        }
    }
}

boost::asio::awaitable<bool> tproxy_udp_session::send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                                const uint8_t* payload,
                                                                std::size_t payload_len)
{
    if (stopped_.load(std::memory_order_relaxed))
    {
        co_return false;
    }

    boost::system::error_code ec;
    const auto key = endpoint_key(source);
    const auto reply_socket = get_or_create_reply_socket(source, ec);
    if (ec || reply_socket == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        if (stopped_.load(std::memory_order_relaxed) || session_util::is_normal_close_error(ec))
        {
            co_return false;
        }
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} source {}:{} get reply socket failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 ec.message());
        co_return true;
    }

    const auto [send_ec, bytes_sent] = co_await reply_socket->async_send_to(
        boost::asio::buffer(payload, payload_len), client_endpoint_, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        if (stopped_.load(std::memory_order_relaxed) || session_util::is_normal_close_error(send_ec))
        {
            co_return false;
        }

        boost::system::error_code close_ec;
        close_ec = reply_socket->close(close_ec);
        (void)close_ec;
        reply_sockets_.erase(key);
        LOG_WARN("event {} trace_id {:016x} conn_id {} client {}:{} target {}:{} source {}:{} send udp reply to client failed {}",
                 log_event::kMux,
                 trace_id_,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 send_ec.message());
        co_return true;
    }

    rx_bytes_ += bytes_sent;
    co_return true;
}

std::shared_ptr<boost::asio::ip::udp::socket> tproxy_udp_session::get_or_create_reply_socket(const boost::asio::ip::udp::endpoint& source,
                                                                                             boost::system::error_code& ec)
{
    ec.clear();
    const auto normalized_source = net::normalize_endpoint(source);
    const auto key = endpoint_key(normalized_source);
    if (auto* cached = reply_sockets_.get(key); cached != nullptr)
    {
        return *cached;
    }

    auto socket = std::make_shared<boost::asio::ip::udp::socket>(worker_.io_context);
    ec = socket->open(normalized_source.protocol(), ec);
    if (ec)
    {
        return nullptr;
    }

    ec = socket->set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return nullptr;
    }

    boost::system::error_code reuse_port_ec;
    set_socket_reuse_port(socket->native_handle(), reuse_port_ec);
    (void)reuse_port_ec;

    net::set_socket_transparent(socket->native_handle(), normalized_source.address().is_v6(), ec);
    if (ec)
    {
        return nullptr;
    }

    if (cfg_.tproxy.mark != 0)
    {
        net::set_socket_mark(socket->native_handle(), cfg_.tproxy.mark, ec);
        if (ec)
        {
            return nullptr;
        }
    }

    ec = socket->bind(normalized_source, ec);
    if (ec)
    {
        return nullptr;
    }

    if (auto evicted = reply_sockets_.put_and_evict(key, socket); evicted && evicted->second != nullptr)
    {
        boost::system::error_code close_ec;
        close_ec = evicted->second->close(close_ec);
        (void)close_ec;
    }
    return socket;
}

std::string tproxy_udp_session::endpoint_key(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized = net::normalize_endpoint(endpoint);
    return normalized.address().to_string() + "|" + std::to_string(normalized.port());
}

void tproxy_udp_session::close_impl()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    idle_timer_.cancel();
    packet_channel_.close();
    if (stream_ != nullptr)
    {
        stream_->close();
    }

    boost::system::error_code ec;
    ec = upstream_socket_.close(ec);
    (void)ec;

    reply_sockets_.evict_while(
        [](const auto&, const auto& socket)
        {
            if (socket != nullptr)
            {
                boost::system::error_code close_ec;
                close_ec = socket->close(close_ec);
                (void)close_ec;
            }
            return true;
        });
}

void tproxy_udp_session::notify_closed()
{
    close_impl();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

}    // namespace mux
