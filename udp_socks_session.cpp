#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "timeout_io.h"
#include "scoped_exit.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "client_tunnel_pool.h"
#include "udp_socks_session.h"

namespace mux
{

namespace
{

[[nodiscard]] std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct proxy_udp_stream
{
    std::shared_ptr<mux_tunnel_impl> tunnel;
    std::shared_ptr<mux_stream> stream;
};

boost::asio::awaitable<void> write_socks_error_reply(boost::asio::ip::tcp::socket& socket,
                                                     const std::uint8_t rep,
                                                     const connection_context& ctx,
                                                     const std::uint32_t timeout_sec)
{
    std::uint8_t err[] = {socks::kVer, rep, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    boost::system::error_code ec;
    co_await timeout_io::wait_write_with_timeout(socket, boost::asio::buffer(err), timeout_sec, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} write error reply failed {}", log_event::kSocks, ec.message());
    }
    co_return;
}

void open_and_bind_udp_socket(boost::asio::ip::udp::socket& sock, const boost::asio::ip::address& local_addr, boost::system::error_code& ec)
{
    const auto protocol = local_addr.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    ec = sock.open(protocol, ec);
    if (ec)
    {
        return;
    }
    if (local_addr.is_v6() && local_addr.to_v6().is_unspecified())
    {
        ec = sock.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return;
        }
    }
    ec = sock.bind(boost::asio::ip::udp::endpoint(local_addr, 0), ec);
    if (ec)
    {
        return;
    }
}

void bind_local_udp_address(boost::asio::ip::tcp::socket& tcp_socket,
                            boost::asio::ip::udp::socket& udp_socket,
                            const connection_context& ctx,
                            boost::asio::ip::address& local_addr,
                            std::uint16_t& udp_bind_port,
                            boost::system::error_code& ec)
{
    const auto tcp_local_ep = tcp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} failed to get local endpoint {}", log_event::kSocks, ec.message());
        return;
    }

    local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    open_and_bind_udp_socket(udp_socket, local_addr, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} bind udp socket failed {}", log_event::kSocks, ec.message());
        return;
    }
    const auto udp_local_ep = udp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} query udp endpoint failed {}", log_event::kSocks, ec.message());
        return;
    }
    udp_bind_port = udp_local_ep.port();
    LOG_CTX_INFO(ctx, "{} started bound at {} {}", log_event::kSocks, local_addr.to_string(), udp_bind_port);
}

boost::asio::awaitable<proxy_udp_stream> connect_remote_address(const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                                boost::asio::io_context& io_context,
                                                                const connection_context& ctx,
                                                                boost::system::error_code& ec)
{
    ec.clear();
    if (tunnel_pool == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_CTX_ERROR(ctx, "{} failed to create stream no tunnel pool", log_event::kSocks);
        co_return proxy_udp_stream{};
    }

    const auto tunnel = co_await tunnel_pool->wait_for_tunnel(io_context, ec);
    if (ec || tunnel == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::not_connected;
        }
        LOG_CTX_ERROR(ctx, "{} wait tunnel failed {}", log_event::kSocks, ec.message());
        co_return proxy_udp_stream{};
    }

    auto stream = tunnel->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::connection_aborted;
        LOG_CTX_ERROR(ctx, "{} failed to create stream", log_event::kSocks);
        co_return proxy_udp_stream{};
    }
    bool keep_stream = false;
    DEFER(
        if (!keep_stream)
        {
            tunnel->remove_stream(stream);
        });

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0, .trace_id = ctx.trace_id()};
    std::vector<std::uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        LOG_CTX_WARN(ctx, "{} syn encode failed", log_event::kSocks);
        co_return proxy_udp_stream{};
    }
    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = kCmdSyn;
    syn_frame.payload.swap(syn_data);
    co_await stream->async_write(syn_frame, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} syn failed {}", log_event::kSocks, ec.message());
        co_return proxy_udp_stream{};
    }

    auto ack_frame = co_await stream->async_read(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} ack failed {}", log_event::kSocks, ec.message());
        co_return proxy_udp_stream{};
    }
    if (ack_frame.h.command != mux::kCmdAck)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        LOG_CTX_WARN(ctx, "{} ack failed unexpected cmd {}", log_event::kSocks, ack_frame.h.command);
        co_return proxy_udp_stream{};
    }

    ack_payload ack_pl{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack_pl))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_CTX_WARN(ctx, "{} ack invalid payload", log_event::kSocks);
        co_return proxy_udp_stream{};
    }
    if (ack_pl.socks_rep != socks::kRepSuccess)
    {
        ec = boost::asio::error::connection_refused;
        LOG_CTX_WARN(ctx, "{} ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_return proxy_udp_stream{};
    }

    keep_stream = true;
    co_return proxy_udp_stream{.tunnel = tunnel, .stream = stream};
}

}    // namespace

namespace detail
{

std::vector<std::uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, const std::uint16_t udp_bind_port)
{
    std::vector<std::uint8_t> final_rep;
    final_rep.reserve(22);
    final_rep.push_back(socks::kVer);
    final_rep.push_back(socks::kRepSuccess);
    final_rep.push_back(0x00);

    if (local_addr.is_v4())
    {
        final_rep.push_back(socks::kAtypIpv4);
        const auto bytes = local_addr.to_v4().to_bytes();
        final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
    }
    else
    {
        final_rep.push_back(socks::kAtypIpv6);
        const auto bytes = local_addr.to_v6().to_bytes();
        final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
    }

    final_rep.push_back(static_cast<std::uint8_t>((udp_bind_port >> 8) & 0xFF));
    final_rep.push_back(static_cast<std::uint8_t>(udp_bind_port & 0xFF));
    return final_rep;
}

}    // namespace detail

namespace
{

[[nodiscard]] bool decode_client_udp_header(const std::vector<std::uint8_t>& buf,
                                            const std::size_t packet_len,
                                            socks_udp_header& udp_header,
                                            const connection_context& ctx)
{
    if (!socks_codec::decode_udp_header(buf.data(), packet_len, udp_header))
    {
        LOG_CTX_WARN(ctx, "{} received invalid udp packet", log_event::kSocks);
        return false;
    }

    if (udp_header.frag != 0x00)
    {
        LOG_CTX_WARN(ctx, "{} received a fragmented packet ignore it", log_event::kSocks);
        return false;
    }
    if (udp_header.addr.empty())
    {
        LOG_CTX_WARN(ctx, "{} received udp packet with empty target host", log_event::kSocks);
        return false;
    }
    if (udp_header.port == 0)
    {
        LOG_CTX_WARN(ctx, "{} received udp packet with invalid target port 0", log_event::kSocks);
        return false;
    }

    return true;
}

}    // namespace

udp_socks_session::udp_socks_session(boost::asio::ip::tcp::socket socket,
                                     boost::asio::io_context& io_context,
                                     std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                     std::shared_ptr<router> router,
                                     const std::uint32_t sid,
                                     const config& cfg,
                                     task_group& group,
                                     std::shared_ptr<void> active_connection_guard)
    : cfg_(cfg),
      group_(group),
      io_context_(io_context),
      timer_(io_context_),
      idle_timer_(io_context_),
      socket_(std::move(socket)),
      udp_socket_(io_context_),
      router_(std::move(router)),
      tunnel_pool_(std::move(tunnel_pool)),
      active_connection_guard_(std::move(active_connection_guard))
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_ = now_ms();
}

void udp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(
        io_context_, [self, host, port]() -> boost::asio::awaitable<void> { co_await self->run(host, port); }, group_.adapt(boost::asio::detached));
}

void udp_socks_session::close_impl()
{
    timer_.cancel();
    idle_timer_.cancel();
    boost::system::error_code tcp_close_ec;
    tcp_close_ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, tcp_close_ec);
    tcp_close_ec = socket_.close(tcp_close_ec);
    (void)tcp_close_ec;
    boost::system::error_code close_ec;
    close_ec = udp_socket_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close udp socket failed {}", log_event::kSocks, close_ec.message());
    }
}

boost::asio::awaitable<void> udp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    apply_request_peer_constraint(host, port);
    boost::system::error_code ec;
    std::uint16_t udp_port = 0;
    boost::asio::ip::address local_addr;
    // step 1 bind local upd address
    bind_local_udp_address(socket_, udp_socket_, ctx_, local_addr, udp_port, ec);
    if (ec)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, ctx_, cfg_.timeout.write);
        co_return;
    }
    // step 2 connect remote address
    const auto proxy_stream = co_await connect_remote_address(tunnel_pool_, io_context_, ctx_, ec);
    if (ec || proxy_stream.stream == nullptr || proxy_stream.tunnel == nullptr)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, ctx_, cfg_.timeout.write);
        co_return;
    }
    const auto& tunnel = proxy_stream.tunnel;
    const auto& stream = proxy_stream.stream;
    // step 3 reply to tcp socket
    const auto final_rep = detail::build_udp_associate_reply(local_addr, udp_port);
    co_await timeout_io::wait_write_with_timeout(socket_, boost::asio::buffer(final_rep), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} write failed {}", log_event::kSocks, ec.message());
        co_return;
    }
    // step 4 forward data
    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (udp_socket_loop(stream) || stream_to_udp_sock(stream) || keep_tcp_alive() || idle_watchdog());

    mux_frame fin_frame;
    fin_frame.h.stream_id = stream->id();
    fin_frame.h.command = mux::kCmdFin;
    boost::system::error_code fin_ec;
    co_await stream->async_write(std::move(fin_frame), fin_ec);
    if (fin_ec)
    {
        LOG_CTX_WARN(ctx_, "{} send fin failed {}", log_event::kSocks, fin_ec.message());
    }
    tunnel->remove_stream(stream);
    LOG_CTX_INFO(ctx_, "{} finished", log_event::kSocks);
}

void udp_socks_session::apply_request_peer_constraint(const std::string& host, const std::uint16_t port)
{
    has_request_client_addr_ = false;
    has_request_client_port_ = false;
    request_client_port_ = 0;
    if (port != 0)
    {
        has_request_client_port_ = true;
        request_client_port_ = port;
    }

    boost::system::error_code ec;
    const auto request_addr = boost::asio::ip::make_address(host, ec);
    if (!ec)
    {
        const auto normalized_addr = socks_codec::normalize_ip_address(request_addr);
        if (!normalized_addr.is_unspecified())
        {
            has_request_client_addr_ = true;
            request_client_addr_ = normalized_addr;
        }
    }
    else if (!host.empty())
    {
        LOG_CTX_WARN(ctx_,
                     "{} udp associate request host {} is not ip ignore host constraint",
                     log_event::kSocks,
                     host);
    }

    if (has_request_client_addr_ || has_request_client_port_)
    {
        LOG_CTX_INFO(ctx_,
                     "{} udp associate peer constraint host {} port {}",
                     log_event::kSocks,
                     has_request_client_addr_ ? request_client_addr_.to_string() : "*",
                     has_request_client_port_ ? std::to_string(request_client_port_) : "*");
    }
}

bool udp_socks_session::sender_matches_request_peer(const boost::asio::ip::udp::endpoint& sender) const
{
    if (has_request_client_addr_)
    {
        const auto sender_addr = socks_codec::normalize_ip_address(sender.address());
        if (sender_addr != request_client_addr_)
        {
            return false;
        }
    }
    if (has_request_client_port_ && sender.port() != request_client_port_)
    {
        return false;
    }
    return true;
}

std::string udp_socks_session::endpoint_key(const boost::asio::ip::udp::endpoint& endpoint)
{
    const auto normalized_endpoint = net::normalize_endpoint(endpoint);
    return normalized_endpoint.address().to_string() + ":" + std::to_string(normalized_endpoint.port());
}

boost::asio::awaitable<route_type> udp_socks_session::decide_udp_route(const socks_udp_header& header) const
{
    if (router_ == nullptr)
    {
        co_return route_type::kProxy;
    }

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(header.addr, ec);
    if (ec)
    {
        co_return co_await router_->decide_domain(ctx_, header.addr);
    }
    co_return co_await router_->decide_ip(ctx_, socks_codec::normalize_ip_address(addr));
}

boost::asio::awaitable<void> udp_socks_session::forward_direct_packet(const socks_udp_header& header,
                                                                      const std::uint8_t* payload,
                                                                      const std::size_t payload_len,
                                                                      boost::system::error_code& ec)
{
    ec.clear();
    boost::asio::ip::udp::resolver resolver(io_context_);
    auto endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver, header.addr, std::to_string(header.port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp direct resolve failed {}:{} error={}", log_event::kRoute, header.addr, header.port, ec.message());
        co_return;
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_CTX_WARN(ctx_, "{} udp direct resolve empty {}:{}", log_event::kRoute, header.addr, header.port);
        co_return;
    }

    const auto target = net::normalize_endpoint(endpoints.begin()->endpoint());
    const auto [send_ec, send_n] = co_await udp_socket_.async_send_to(
        boost::asio::buffer(payload, payload_len), target, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    ec = send_ec;
    if (ec)
    {
        LOG_CTX_WARN(ctx_,
                     "{} udp direct send failed {}:{} error={}",
                     log_event::kRoute,
                     target.address().to_string(),
                     target.port(),
                     ec.message());
        co_return;
    }

    direct_peers_.insert(endpoint_key(target));
}

boost::asio::awaitable<void> udp_socks_session::forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                                const std::uint8_t* payload,
                                                                                const std::size_t payload_len,
                                                                                boost::system::error_code& ec)
{
    ec.clear();
    if (!has_client_addr_)
    {
        co_return;
    }

    const auto normalized_sender = net::normalize_endpoint(sender);
    const socks_udp_header header{.frag = 0, .addr = normalized_sender.address().to_string(), .port = normalized_sender.port()};
    const auto udp_header = socks_codec::encode_udp_header(header);

    std::vector<std::uint8_t> packet;
    packet.reserve(udp_header.size() + payload_len);
    packet.insert(packet.end(), udp_header.begin(), udp_header.end());
    packet.insert(packet.end(), payload, payload + payload_len);

    const auto [send_ec, send_n] =
        co_await udp_socket_.async_send_to(boost::asio::buffer(packet), client_addr_, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    ec = send_ec;
    if (ec)
    {
        LOG_CTX_WARN(ctx_,
                     "{} udp direct reply failed {}:{} error={}",
                     log_event::kRoute,
                     client_addr_.address().to_string(),
                     client_addr_.port(),
                     ec.message());
    }
}

boost::asio::awaitable<void> udp_socks_session::udp_socket_loop(std::shared_ptr<mux_stream> stream)
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    while (true)
    {
        const auto [recv_ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            LOG_CTX_WARN(ctx_, "{} receive error {}", log_event::kSocks, recv_ec.message());
            break;
        }
        if (!has_client_addr_ || sender == client_addr_)
        {
            if (!has_client_addr_)
            {
                if (!sender_matches_request_peer(sender))
                {
                    LOG_CTX_WARN(ctx_,
                                 "{} ignore udp packet from unexpected peer {}:{} request expects {}:{}",
                                 log_event::kSocks,
                                 sender.address().to_string(),
                                 sender.port(),
                                 has_request_client_addr_ ? request_client_addr_.to_string() : "*",
                                 has_request_client_port_ ? std::to_string(request_client_port_) : "*");
                    continue;
                }
                client_addr_ = sender;
                has_client_addr_ = true;
                LOG_CTX_INFO(ctx_,
                             "{} udp peer bound to {}:{}",
                             log_event::kSocks,
                             client_addr_.address().to_string(),
                             client_addr_.port());
            }

            socks_udp_header udp_header;
            if (!decode_client_udp_header(buf, n, udp_header, ctx_))
            {
                continue;
            }

            const auto route = co_await decide_udp_route(udp_header);
            if (route == route_type::kBlock)
            {
                LOG_CTX_INFO(ctx_, "{} udp blocked {}:{}", log_event::kRoute, udp_header.addr, udp_header.port);
                last_activity_time_ms_ = now_ms();
                continue;
            }

            const auto payload_len = n - udp_header.header_len;
            if (route == route_type::kProxy)
            {
                if (n > mux::kMaxPayloadPerRecord)
                {
                    LOG_CTX_WARN(ctx_, "{} udp packet too large for single record {}", log_event::kSocks, n);
                    continue;
                }

                mux_frame data_frame;
                data_frame.h.stream_id = stream->id();
                data_frame.h.command = mux::kCmdDat;
                data_frame.payload.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
                boost::system::error_code write_ec;
                co_await stream->async_write(data_frame, write_ec);
                if (write_ec)
                {
                    LOG_CTX_ERROR(ctx_, "{} write to stream failed {}", log_event::kSocks, write_ec.message());
                    break;
                }
                last_activity_time_ms_ = now_ms();
                continue;
            }

            boost::system::error_code ec;
            co_await forward_direct_packet(udp_header, buf.data() + udp_header.header_len, payload_len, ec);
            if (ec)
            {
                break;
            }
            last_activity_time_ms_ = now_ms();
            continue;
        }

        boost::system::error_code ec;
        if (!direct_peers_.contains(endpoint_key(sender)))
        {
            LOG_CTX_WARN(ctx_,
                         "{} ignore udp packet from unexpected peer {}:{} expected {}:{}",
                         log_event::kSocks,
                         sender.address().to_string(),
                         sender.port(),
                         client_addr_.address().to_string(),
                         client_addr_.port());
            continue;
        }

        co_await forward_direct_reply_to_client(sender, buf.data(), n, ec);
        if (ec)
        {
            break;
        }
        last_activity_time_ms_ = now_ms();
    }
}

boost::asio::awaitable<void> udp_socks_session::stream_to_udp_sock(std::shared_ptr<mux_stream> stream)
{
    boost::system::error_code ec;
    while (true)
    {
        auto data_frame = co_await stream->async_read(ec);
        if (ec)
        {
            break;
        }
        if (!has_client_addr_)
        {
            continue;
        }
        if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
        {
            LOG_CTX_INFO(ctx_, "{} recv control cmd {} closing", log_event::kSocks, data_frame.h.command);
            break;
        }
        if (data_frame.h.command != mux::kCmdDat)
        {
            LOG_CTX_WARN(ctx_, "{} recv unexpected cmd {} dropping session", log_event::kSocks, data_frame.h.command);
            break;
        }

        const auto [send_ec, send_n] = co_await udp_socket_.async_send_to(
            boost::asio::buffer(data_frame.payload), client_addr_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (send_ec)
        {
            LOG_CTX_ERROR(ctx_, "{} send error {}", log_event::kSocks, send_ec.message());
            co_return;
        }
        (void)send_n;
        last_activity_time_ms_ = now_ms();
    }
}

boost::asio::awaitable<void> udp_socks_session::keep_tcp_alive()
{
    for (;;)
    {
        char b[1];
        const auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec)
        {
            continue;
        }
        LOG_CTX_ERROR(ctx_, "{} keep tcp alive error {}", log_event::kSocks, ec.message());
        break;
    }
}

boost::asio::awaitable<void> udp_socks_session::idle_watchdog()
{
    if (cfg_.timeout.idle == 0)
    {
        co_return;
    }

    while (true)
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto elapsed_ms = now_ms() - last_activity_time_ms_;
        const auto idle_timeout_ms = static_cast<std::uint64_t>(cfg_.timeout.idle) * 1000ULL;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kSocks);
            break;
        }
    }
}

}    // namespace mux
