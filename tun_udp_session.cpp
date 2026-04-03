#include <chrono>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "constants.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "tun_udp_session.h"
#include "mux_session_utils.h"
#include "connection_tracker.h"
namespace mux
{

namespace
{

boost::asio::awaitable<std::shared_ptr<mux_stream>> connect_remote_udp_stream(const std::shared_ptr<mux_connection>& tunnel,
                                                                              const uint32_t conn_id,
                                                                              const boost::asio::ip::udp::endpoint& target_endpoint,
                                                                              boost::system::error_code& ec)
{
    ec.clear();
    if (tunnel == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_WARN("event {} conn_id {} target {}:{} no active tunnel for tun udp associate",
                 log_event::kMux,
                 conn_id,
                 target_endpoint.address().to_string(),
                 target_endpoint.port());
        co_return nullptr;
    }

    auto stream = tunnel->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::operation_aborted;
        LOG_WARN("event {} conn_id {} target {}:{} create tun udp stream failed tunnel_ptr {}",
                 log_event::kMux,
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
    };
    std::vector<uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::asio::error::invalid_argument;
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} encode tun udp syn failed",
                 log_event::kMux,
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
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} send tun udp syn failed {}",
                 log_event::kMux,
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
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} read tun udp ack failed {}",
                 log_event::kMux,
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
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} unexpected tun udp ack command {}",
                 log_event::kMux,
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
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} invalid tun udp ack payload",
                 log_event::kMux,
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
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} tun udp ack rejected rep {}",
                 log_event::kMux,
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

tun_udp_session::tun_udp_session(io_worker& worker,
                                 std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                 std::shared_ptr<router> router,
                                 udp_pcb* pcb,
                                 boost::asio::ip::udp::endpoint client_endpoint,
                                 boost::asio::ip::udp::endpoint target_endpoint,
                                 const uint32_t conn_id,
                                 const config& cfg,
                                 std::function<void()> on_close)
    : conn_id_(conn_id),
      cfg_(cfg),
      worker_(worker),
      active_guard_(acquire_active_connection_guard()),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      pcb_(pcb),
      last_activity_time_ms_(net::now_ms()),
      idle_timer_(worker.io_context),
      packet_wait_timer_(worker.io_context),
      upstream_socket_(worker.io_context),
      client_endpoint_(net::normalize_endpoint(client_endpoint)),
      target_endpoint_(net::normalize_endpoint(target_endpoint)),
      on_close_(std::move(on_close))
{
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
    udp_recv(pcb_, &tun_udp_session::on_recv, this);
}

boost::asio::awaitable<void> tun_udp_session::start()
{
    const bool completed = co_await run();
    notify_closed();
    if (!completed)
    {
        co_return;
    }

    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} conn_id {} client {}:{} target {}:{} route {} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
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

void tun_udp_session::stop() { close_impl(); }

void tun_udp_session::enqueue_packet(pbuf* packet)
{
    if (packet == nullptr)
    {
        return;
    }

    auto payload = tun::pbuf_to_vector(packet);
    pbuf_free(packet);

    if (stopped_.load(std::memory_order_relaxed))
    {
        return;
    }

    if (payload.size() > constants::udp::kMaxPayload)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} drop tun udp payload too large {} max {}",
                 log_event::kMux,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 payload.size(),
                 constants::udp::kMaxPayload);
        return;
    }

    if (packet_queue_.size() >= constants::udp::kPacketChannelCapacity)
    {
        packet_queue_.pop_front();
    }
    packet_queue_.push_back(std::move(payload));
    last_activity_time_ms_ = net::now_ms();
    signal_packet_event();
}

void tun_udp_session::on_recv(void* arg, udp_pcb* pcb, pbuf* packet, const ip_addr_t* addr, u16_t port)
{
    (void)pcb;
    (void)addr;
    (void)port;

    auto* self = static_cast<tun_udp_session*>(arg);
    if (self == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return;
    }

    self->enqueue_packet(packet);
}

boost::asio::awaitable<bool> tun_udp_session::run()
{
    route_ = co_await decide_route();
    if (route_ == route_type::kBlock)
    {
        LOG_WARN("event {} conn_id {} blocked tun udp target {}:{}",
                 log_event::kRoute,
                 conn_id_,
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port());
        co_return false;
    }

    LOG_INFO("event {} conn_id {} client {}:{} target {}:{} route {}",
             log_event::kRoute,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             mux::to_string(route_));

    if (route_ == route_type::kDirect)
    {
        co_return co_await run_direct_mode();
    }
    co_return co_await run_proxy_mode();
}

boost::asio::awaitable<route_type> tun_udp_session::decide_route() const
{
    if (router_ == nullptr)
    {
        co_return route_type::kBlock;
    }
    co_return co_await router_->decide_ip(target_endpoint_.address());
}

boost::asio::awaitable<bool> tun_udp_session::open_direct_socket()
{
    boost::system::error_code ec;
    const auto protocol = target_endpoint_.address().is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    upstream_socket_.open(protocol, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} open tun direct udp socket failed {}",
                 log_event::kConnInit,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    upstream_socket_.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} bind tun direct udp socket failed {}",
                 log_event::kConnInit,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    upstream_socket_.connect(target_endpoint_, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} connect tun direct udp socket failed {}",
                 log_event::kConnInit,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 ec.message());
        co_return false;
    }

    LOG_INFO("event {} conn_id {} opened tun direct udp client {}:{} target {}:{}",
             log_event::kConnInit,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port());
    co_return true;
}

boost::asio::awaitable<bool> tun_udp_session::open_proxy_stream()
{
    boost::system::error_code ec;
    tunnel_ = co_await wait_for_proxy_tunnel(ec);
    if (ec || tunnel_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::timed_out;
        }
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} wait tun udp tunnel failed {} active_tunnels {} total_slots {}",
                 log_event::kConnInit,
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
    LOG_DEBUG("event {} conn_id {} client {}:{} target {}:{} selected tun udp tunnel ptr {}",
              log_event::kConnInit,
              conn_id_,
              client_endpoint_.address().to_string(),
              client_endpoint_.port(),
              target_endpoint_.address().to_string(),
              target_endpoint_.port(),
              static_cast<const void*>(tunnel_.get()));

    stream_ = co_await connect_remote_udp_stream(tunnel_, conn_id_, target_endpoint_, ec);
    if (ec || stream_ == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::operation_aborted;
        }
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} open tun proxy udp stream failed {} tunnel_ptr {}",
                 log_event::kConnInit,
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

    LOG_INFO("event {} conn_id {} opened tun proxy udp stream client {}:{} target {}:{} stream_id {}",
             log_event::kConnInit,
             conn_id_,
             client_endpoint_.address().to_string(),
             client_endpoint_.port(),
             target_endpoint_.address().to_string(),
             target_endpoint_.port(),
             stream_->id());
    co_return true;
}

boost::asio::awaitable<bool> tun_udp_session::run_direct_mode()
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

boost::asio::awaitable<bool> tun_udp_session::run_proxy_mode()
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
        (void)close_ec;
    }

    if (tunnel_ != nullptr && stream_ != nullptr)
    {
        tunnel_->close_and_remove_stream(stream_);
    }
    stream_.reset();
    tunnel_.reset();
    co_return true;
}

boost::asio::awaitable<std::shared_ptr<mux_connection>> tun_udp_session::wait_for_proxy_tunnel(boost::system::error_code& ec) const
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

boost::asio::awaitable<void> tun_udp_session::packets_to_direct()
{
    boost::system::error_code ec;
    std::vector<uint8_t> payload;
    for (;;)
    {
        while (!pop_packet(payload) && !stopped_.load(std::memory_order_relaxed))
        {
            co_await wait_for_packet();
        }
        if (stopped_.load(std::memory_order_relaxed))
        {
            co_return;
        }

        const auto sent =
            co_await upstream_socket_.async_send(boost::asio::buffer(payload), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        (void)sent;
        if (ec)
        {
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} send tun direct udp payload failed {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     ec.message());
            co_return;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::direct_to_client()
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
            co_return;
        }

        if (!(co_await send_to_client(normalized_target, buffer.data(), bytes_recv)))
        {
            co_return;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::packets_to_proxy()
{
    boost::system::error_code ec;
    std::vector<uint8_t> payload;
    for (;;)
    {
        while (!pop_packet(payload) && !stopped_.load(std::memory_order_relaxed))
        {
            co_await wait_for_packet();
        }
        if (stopped_.load(std::memory_order_relaxed))
        {
            co_return;
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
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} tun proxy udp payload too large {} max {}",
                     log_event::kMux,
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
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} send tun proxy udp payload failed {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     ec.message());
            co_return;
        }
        tx_bytes_ += payload.size();
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::proxy_to_client()
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
            co_return;
        }

        if (frame.h.command == mux::kCmdFin || frame.h.command == mux::kCmdRst)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            co_return;
        }
        if (frame.h.command != mux::kCmdDat)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} unexpected tun proxy udp frame {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     frame.h.command);
            co_return;
        }

        socks_udp_header header;
        if (!socks_codec::decode_udp_header(frame.payload.data(), frame.payload.size(), header))
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} decode tun proxy udp header failed",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id());
            co_return;
        }
        if (header.header_len > frame.payload.size())
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} tun proxy udp header length invalid {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     header.header_len);
            co_return;
        }
        if (header.frag != 0x00)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} tun proxy udp fragment unsupported {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     header.frag);
            co_return;
        }
        if (header.port == 0)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} tun proxy udp source port invalid",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id());
            co_return;
        }

        boost::system::error_code addr_ec;
        const auto source_addr = boost::asio::ip::make_address(header.addr, addr_ec);
        if (addr_ec)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} target {}:{} stream_id {} parse tun proxy udp source address failed {}",
                     log_event::kMux,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port(),
                     stream_->id(),
                     addr_ec.message());
            co_return;
        }

        const boost::asio::ip::udp::endpoint source_endpoint(net::normalize_address(source_addr), header.port);
        const auto* payload = frame.payload.data() + header.header_len;
        const auto payload_len = frame.payload.size() - header.header_len;
        if (!(co_await send_to_client(source_endpoint, payload, payload_len)))
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            co_return;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> tun_udp_session::idle_watchdog()
{
    const auto idle_timeout_ms = net::timeout_seconds_to_milliseconds(cfg_.timeout.idle);
    while (!stopped_.load(std::memory_order_relaxed))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            co_return;
        }

        if (net::now_ms() - last_activity_time_ms_ > idle_timeout_ms)
        {
            LOG_INFO("event {} conn_id {} tun udp idle timeout client {}:{} target {}:{}",
                     log_event::kTimeout,
                     conn_id_,
                     client_endpoint_.address().to_string(),
                     client_endpoint_.port(),
                     target_endpoint_.address().to_string(),
                     target_endpoint_.port());
            co_return;
        }
    }
}

boost::asio::awaitable<void> tun_udp_session::wait_for_packet()
{
    packet_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    const auto [ec] = co_await packet_wait_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)ec;
}

boost::asio::awaitable<bool> tun_udp_session::send_to_client(const boost::asio::ip::udp::endpoint& source,
                                                             const uint8_t* payload,
                                                             const std::size_t payload_len)
{
    if (stopped_.load(std::memory_order_relaxed) || pcb_ == nullptr)
    {
        co_return false;
    }

    ip_addr_t source_addr{};
    if (!tun::address_to_lwip(source.address(), source_addr))
    {
        co_return false;
    }

    auto* out = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload_len), PBUF_RAM);
    if (out == nullptr)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} source {}:{} alloc lwip udp payload failed {}",
                 log_event::kMux,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 payload_len);
        co_return true;
    }

    if (pbuf_take(out, payload, static_cast<u16_t>(payload_len)) != ERR_OK)
    {
        pbuf_free(out);
        co_return false;
    }

    const auto send_err = udp_sendfrom(pcb_, out, &source_addr, source.port());
    pbuf_free(out);
    if (send_err != ERR_OK)
    {
        LOG_WARN("event {} conn_id {} client {}:{} target {}:{} source {}:{} send tun udp reply failed {}",
                 log_event::kMux,
                 conn_id_,
                 client_endpoint_.address().to_string(),
                 client_endpoint_.port(),
                 target_endpoint_.address().to_string(),
                 target_endpoint_.port(),
                 source.address().to_string(),
                 source.port(),
                 tun::lwip_error_message(send_err));
        co_return false;
    }

    rx_bytes_ += payload_len;
    co_return true;
}

bool tun_udp_session::pop_packet(std::vector<uint8_t>& payload)
{
    if (packet_queue_.empty())
    {
        return false;
    }

    payload = std::move(packet_queue_.front());
    packet_queue_.pop_front();
    return true;
}

void tun_udp_session::signal_packet_event()
{
    packet_wait_timer_.cancel();
}

void tun_udp_session::close_impl()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    boost::system::error_code ec;
    idle_timer_.cancel();
    packet_wait_timer_.cancel();
    if (stream_ != nullptr)
    {
        stream_->close();
    }
    upstream_socket_.close(ec);

    if (pcb_ != nullptr)
    {
        udp_recv(pcb_, nullptr, nullptr);
        udp_remove(pcb_);
        pcb_ = nullptr;
    }
}

void tun_udp_session::notify_closed()
{
    close_impl();
    if (on_close_ != nullptr)
    {
        on_close_();
        on_close_ = nullptr;
    }
}

}    // namespace mux
