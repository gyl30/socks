#include <chrono>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <boost/system/errc.hpp>

#ifdef __linux__
#include <cerrno>
#include <sys/socket.h>
#endif

#include "log.h"
#include "router.h"
#include "config.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "protocol.h"
#include "timeout_io.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "task_group.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "tproxy_udp_session.h"
#include "client_tunnel_pool.h"

namespace mux
{

namespace
{

constexpr std::size_t kPacketChannelCapacity = 1024;
constexpr std::chrono::milliseconds kTunnelPollInterval(200);
constexpr std::uint8_t kNoStreamControl = 0;
constexpr std::size_t kMaxReplySockets = 512;
constexpr std::size_t kMaxUdpPacketSize = 8192;

[[nodiscard]] bool is_normal_close_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor;
}

void update_stream_close_command(std::atomic<std::uint8_t>& stream_close_command, const std::uint8_t next_command)
{
    auto current = stream_close_command.load(std::memory_order_relaxed);
    for (;;)
    {
        std::uint8_t desired = current;
        if (next_command == mux::kCmdRst)
        {
            desired = mux::kCmdRst;
        }
        else if (next_command == kNoStreamControl && current != mux::kCmdRst)
        {
            desired = kNoStreamControl;
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

std::shared_ptr<void> make_active_connection_guard()
{
    return {new int(0),
            [](void* ptr)
            {
                delete static_cast<int*>(ptr);
                statistics::instance().dec_active_connections();
            }};
}

void set_socket_reuse_port(const int fd, boost::system::error_code& ec)
{
    ec.clear();
#ifdef __linux__
    const int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::system_category());
        return;
    }
    return;
#else
    (void)fd;
    ec = boost::system::errc::make_error_code(boost::system::errc::not_supported);
    return;
#endif
}

boost::asio::awaitable<std::shared_ptr<mux_stream>> connect_remote_udp_stream(const std::shared_ptr<mux_tunnel_impl>& tunnel,
                                                                               const connection_context& ctx,
                                                                               boost::system::error_code& ec)
{
    ec.clear();
    if (tunnel == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_CTX_WARN(ctx, "{} no active tunnel for udp associate", log_event::kMux);
        co_return nullptr;
    }

    auto stream = tunnel->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::operation_aborted;
        LOG_CTX_WARN(ctx, "{} create udp stream failed", log_event::kMux);
        co_return nullptr;
    }

    const syn_payload syn{
        .socks_cmd = socks::kCmdUdpAssociate,
        .addr = "0.0.0.0",
        .port = 0,
        .trace_id = ctx.trace_id(),
    };
    std::vector<std::uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::asio::error::invalid_argument;
        LOG_CTX_WARN(ctx, "{} encode udp syn failed", log_event::kMux);
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
        LOG_CTX_WARN(ctx, "{} send udp syn failed {}", log_event::kMux, ec.message());
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    const auto ack_frame = co_await stream->async_read(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} read udp ack failed {}", log_event::kMux, ec.message());
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }
    if (ack_frame.h.command != mux::kCmdAck)
    {
        ec = boost::asio::error::invalid_argument;
        LOG_CTX_WARN(ctx, "{} unexpected udp ack command {}", log_event::kMux, ack_frame.h.command);
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    ack_payload ack{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack))
    {
        ec = boost::asio::error::invalid_argument;
        LOG_CTX_WARN(ctx, "{} invalid udp ack payload", log_event::kMux);
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }
    if (ack.socks_rep != socks::kRepSuccess)
    {
        ec = boost::asio::error::operation_aborted;
        LOG_CTX_WARN(ctx, "{} udp ack rejected {}", log_event::kMux, ack.socks_rep);
        tunnel->close_and_remove_stream(stream);
        co_return nullptr;
    }

    co_return stream;
}

}    // namespace

tproxy_udp_session::tproxy_udp_session(boost::asio::io_context& io_context,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       boost::asio::ip::udp::endpoint client_endpoint,
                                       boost::asio::ip::udp::endpoint target_endpoint,
                                       const route_type route,
                                       connection_context ctx,
                                       const config& cfg,
                                       task_group& group,
                                       std::function<void()> on_close)
    : ctx_(std::move(ctx)),
      cfg_(cfg),
      group_(group),
      route_(route),
      last_activity_time_ms_(timeout_io::now_ms()),
      io_context_(io_context),
      idle_timer_(io_context_),
      upstream_socket_(io_context_),
      tunnel_pool_(std::move(tunnel_pool)),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close)),
      packet_channel_(io_context_, kPacketChannelCapacity),
      reply_sockets_(kMaxReplySockets)
{
    statistics::instance().inc_active_connections();
    active_guard_ = make_active_connection_guard();
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
}

void tproxy_udp_session::start()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(
        io_context_, [self]() -> boost::asio::awaitable<void> { co_await self->run(); }, group_.adapt(boost::asio::detached));
}

void tproxy_udp_session::stop()
{
    close_impl();
}

udp_enqueue_result tproxy_udp_session::try_enqueue_packet(std::vector<std::uint8_t> payload)
{
    if (stopped_)
    {
        return udp_enqueue_result::kClosed;
    }

    last_activity_time_ms_ = timeout_io::now_ms();
    if (payload.size() > kMaxUdpPacketSize)
    {
        LOG_CTX_WARN(ctx_,
                     "{} drop udp packet because payload too large size {} max {}",
                     log_event::kMux,
                     payload.size(),
                     kMaxUdpPacketSize);
        return udp_enqueue_result::kDroppedOverflow;
    }
    if (!packet_channel_.try_send(boost::system::error_code{}, std::move(payload)))
    {
        if (stopped_)
        {
            return udp_enqueue_result::kClosed;
        }

        LOG_CTX_WARN(ctx_,
                     "{} drop udp packet because session queue is full client {}:{} target {}:{}",
                     log_event::kMux,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
        return udp_enqueue_result::kDroppedOverflow;
    }
    return udp_enqueue_result::kEnqueued;
}

boost::asio::awaitable<void> tproxy_udp_session::run()
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (route_ == route_type::kDirect)
    {
        const bool direct_ready = co_await open_direct_socket();
        if (!direct_ready)
        {
            close_impl();
            if (on_close_ != nullptr)
            {
                on_close_();
                on_close_ = nullptr;
            }
            co_return;
        }

        if (cfg_.timeout.idle == 0)
        {
            co_await (packets_to_direct() || direct_to_client());
        }
        else
        {
            co_await (packets_to_direct() || direct_to_client() || idle_watchdog());
        }
    }
    else
    {
        const bool ready = co_await open_proxy_stream();

        if (!ready)
        {
            close_impl();
            if (on_close_ != nullptr)
            {
                on_close_();
                on_close_ = nullptr;
            }
            co_return;
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
        if (stream_ != nullptr && close_command != kNoStreamControl)
        {
            mux_frame close_frame;
            close_frame.h.stream_id = stream_->id();
            close_frame.h.command = close_command;
            boost::system::error_code close_ec;
            co_await stream_->async_write(std::move(close_frame), close_ec);
            if (close_ec)
            {
                LOG_CTX_WARN(ctx_,
                             "{} send udp {} failed {}",
                             log_event::kMux,
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
    }

    close_impl();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
    LOG_CTX_INFO(ctx_, "{} udp session finished {}", log_event::kConnClose, ctx_.stats_summary());
}

boost::asio::awaitable<bool> tproxy_udp_session::open_direct_socket()
{
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    ec = upstream_socket_.open(protocol, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} open direct udp socket failed {}", log_event::kConnInit, ec.message());
        co_return false;
    }

    if (cfg_.tproxy.mark != 0)
    {
        net::set_socket_mark(upstream_socket_.native_handle(), cfg_.tproxy.mark, ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} set direct udp mark failed {}", log_event::kConnInit, ec.message());
            co_return false;
        }
    }

    ec = upstream_socket_.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} bind direct udp socket failed {}", log_event::kConnInit, ec.message());
        co_return false;
    }
    ec = upstream_socket_.connect(target_endpoint_, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} connect direct udp socket failed {}", log_event::kConnInit, ec.message());
        co_return false;
    }

    LOG_CTX_INFO(ctx_,
                 "{} opened direct udp socket client {}:{} target {}:{}",
                 log_event::kConnInit,
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
        LOG_CTX_WARN(ctx_, "{} wait udp tunnel failed {}", log_event::kConnInit, ec.message());
        co_return false;
    }

    stream_ = co_await connect_remote_udp_stream(tunnel_, ctx_, ec);
    if (ec || stream_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        LOG_CTX_WARN(ctx_, "{} open proxy udp stream failed {}", log_event::kConnInit, ec.message());
        tunnel_.reset();
        co_return false;
    }

    LOG_CTX_INFO(ctx_,
                 "{} opened proxy udp stream client {}:{} target {}:{}",
                 log_event::kConnInit,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port());
    co_return true;
}

boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl>> tproxy_udp_session::wait_for_proxy_tunnel(boost::system::error_code& ec)
{
    ec.clear();
    const auto start_ms = timeout_io::now_ms();
    const auto connect_timeout_ms = timeout_io::timeout_seconds_to_milliseconds(cfg_.timeout.connect);
    boost::asio::steady_timer retry_timer(io_context_);

    for (;;)
    {
        if (stopped_)
        {
            ec = boost::asio::error::operation_aborted;
            co_return nullptr;
        }

        const auto tunnel = tunnel_pool_ != nullptr ? tunnel_pool_->select_tunnel() : nullptr;
        if (tunnel != nullptr)
        {
            co_return tunnel;
        }

        if (connect_timeout_ms != 0 && timeout_io::now_ms() - start_ms >= connect_timeout_ms)
        {
            ec = boost::asio::error::timed_out;
            co_return nullptr;
        }

        retry_timer.expires_after(kTunnelPollInterval);
        const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
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
        auto [read_ec, payload] = co_await packet_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = read_ec;
        if (ec)
        {
            break;
        }

        const auto [send_ec, sent] =
            co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
        (void)sent;
        ec = send_ec;
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} send direct udp payload failed {}", log_event::kMux, ec.message());
            break;
        }
        ctx_.add_tx_bytes(payload.size());
        last_activity_time_ms_ = timeout_io::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::direct_to_client()
{
    std::vector<std::uint8_t> buffer(65535);
    const auto normalized_target = net::normalize_endpoint(target_endpoint_);
    boost::system::error_code ec;
    for (;;)
    {
        const auto [recv_ec, bytes_recv] = co_await upstream_socket_.async_receive(boost::asio::buffer(buffer),
                                                                                   boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = recv_ec;
        if (ec)
        {
            break;
        }

        if (!(co_await send_to_client(normalized_target, buffer.data(), bytes_recv)))
        {
            break;
        }
        last_activity_time_ms_ = timeout_io::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::packets_to_proxy()
{
    boost::system::error_code ec;
    for (;;)
    {
        auto [read_ec, payload] = co_await packet_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = read_ec;
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
            LOG_CTX_WARN(ctx_, "{} proxy udp payload too large {} max {}", log_event::kMux, data_frame.payload.size(), mux::kMaxPayload);
            continue;
        }

        co_await stream_->async_write(std::move(data_frame), ec);
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} send proxy udp payload failed {}", log_event::kMux, ec.message());
            break;
        }
        ctx_.add_tx_bytes(payload.size());
        last_activity_time_ms_ = timeout_io::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_to_client()
{
    boost::system::error_code ec;
    for (;;)
    {
        const auto read_timeout = (cfg_.timeout.idle == 0)
                                      ? cfg_.timeout.read
                                      : std::max(cfg_.timeout.read, cfg_.timeout.idle + 2);
        const auto frame = co_await stream_->async_read(read_timeout, ec);
        if (ec)
        {
            if (ec != boost::asio::error::timed_out)
            {
                update_stream_close_command(stream_close_command_, kNoStreamControl);
            }
            break;
        }
        if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
        {
            update_stream_close_command(stream_close_command_, kNoStreamControl);
            break;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} unexpected proxy udp frame {}", log_event::kMux, frame.h.command);
            break;
        }

        socks_udp_header header;
        if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} decode proxy udp header failed", log_event::kMux);
            break;
        }
        if (header.header_len > frame.payload.size())
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} proxy udp header length invalid {}", log_event::kMux, header.header_len);
            break;
        }
        if (header.frag != 0x00)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} proxy udp fragment unsupported {}", log_event::kMux, header.frag);
            break;
        }
        if (header.port == 0)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} proxy udp source port invalid", log_event::kMux);
            break;
        }

        boost::system::error_code addr_ec;
        const auto source_addr = boost::asio::ip::make_address(header.addr, addr_ec);
        if (addr_ec)
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_CTX_WARN(ctx_, "{} parse proxy udp source address failed {}", log_event::kMux, addr_ec.message());
            break;
        }

        const boost::asio::ip::udp::endpoint source_endpoint(net::normalize_address(source_addr), header.port);
        const auto* payload = frame.payload.data() + header.header_len;
        const auto payload_len = frame.payload.size() - header.header_len;
        if (!(co_await send_to_client(source_endpoint, payload, payload_len)))
        {
            update_stream_close_command(stream_close_command_, mux::kCmdRst);
            break;
        }
        last_activity_time_ms_ = timeout_io::now_ms();
    }
}

boost::asio::awaitable<void> tproxy_udp_session::idle_watchdog()
{
    const auto idle_timeout_ms = timeout_io::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        if (timeout_io::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_CTX_INFO(ctx_, "{} udp session idle timeout", log_event::kTimeout);
            break;
        }
    }
}

boost::asio::awaitable<bool> tproxy_udp_session::send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                                const std::uint8_t* payload,
                                                                const std::size_t payload_len)
{
    if (stopped_)
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
        if (stopped_ || is_normal_close_error(ec))
        {
            co_return false;
        }
        LOG_CTX_WARN(ctx_, "{} get reply socket failed {}", log_event::kMux, ec.message());
        co_return true;
    }

    const auto [send_ec, bytes_sent] =
        co_await reply_socket->async_send_to(boost::asio::buffer(payload, payload_len), client_endpoint_, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        if (stopped_ || is_normal_close_error(send_ec))
        {
            co_return false;
        }

        boost::system::error_code close_ec;
        close_ec = reply_socket->close(close_ec);
        (void)close_ec;
        reply_sockets_.erase(key);
        LOG_CTX_WARN(ctx_, "{} send udp reply to client failed {}", log_event::kMux, send_ec.message());
        co_return true;
    }

    ctx_.add_rx_bytes(bytes_sent);
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

    auto socket = std::make_shared<boost::asio::ip::udp::socket>(io_context_);
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
        evicted->second->close(close_ec);
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
    if (stopped_)
    {
        return;
    }
    stopped_ = true;

    idle_timer_.cancel();
    packet_channel_.close();
    if (stream_ != nullptr)
    {
        stream_->close();
    }

    boost::system::error_code ec;
    ec = upstream_socket_.close(ec);
    (void)ec;

    reply_sockets_.evict_while([](const auto&, const auto& socket) {
        if (socket != nullptr)
        {
            boost::system::error_code close_ec;
            close_ec = socket->close(close_ec);
            (void)close_ec;
        }
        return true;
    });
}

}    // namespace mux
