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
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "timeout_io.h"
#include "log_context.h"
#include "mux_protocol.h"
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

boost::asio::awaitable<std::shared_ptr<mux_stream>> connect_remote_address(std::shared_ptr<mux_tunnel_impl> tunnel_manager,
                                                                           const connection_context& ctx)
{
    auto stream = tunnel_manager->create_stream();
    if (stream == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to create stream", log_event::kSocks);
        co_return nullptr;
    }

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0, .trace_id = ctx.trace_id()};
    std::vector<std::uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        LOG_CTX_WARN(ctx, "{} syn encode failed", log_event::kSocks);
        co_return nullptr;
    }
    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = kCmdSyn;
    syn_frame.payload.swap(syn_data);
    boost::system::error_code ec;
    co_await stream->async_write(syn_frame, ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} syn failed {}", log_event::kSocks, ec.message());
        co_return nullptr;
    }

    auto ack_frame = co_await stream->async_read(ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} ack failed {}", log_event::kSocks, ec.message());
        co_return nullptr;
    }
    if (ack_frame.h.command != mux::kCmdAck)
    {
        LOG_CTX_WARN(ctx, "{} ack failed unexpected cmd {}", log_event::kSocks, ack_frame.h.command);
        co_return nullptr;
    }

    ack_payload ack_pl{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack_pl))
    {
        LOG_CTX_WARN(ctx, "{} ack invalid payload", log_event::kSocks);
        co_return nullptr;
    }
    if (ack_pl.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx, "{} ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_return nullptr;
    }

    co_return stream;
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

[[nodiscard]] bool validate_udp_header(const std::vector<std::uint8_t>& buf, const std::size_t packet_len, const connection_context& ctx)
{
    socks_udp_header udp_header;
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

    if (packet_len > mux::kMaxPayloadPerRecord)
    {
        LOG_CTX_WARN(ctx, "{} udp packet too large for single record {}", log_event::kSocks, packet_len);
        return false;
    }
    return true;
}

}    // namespace

udp_socks_session::udp_socks_session(boost::asio::ip::tcp::socket socket,
                                     boost::asio::io_context& io_context,
                                     std::shared_ptr<mux_tunnel_impl> tunnel_manager,
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
      tunnel_manager_(std::move(tunnel_manager)),
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
    (void)host;
    (void)port;
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
    const auto stream = co_await connect_remote_address(tunnel_manager_, ctx_);
    if (stream == nullptr)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, ctx_, cfg_.timeout.write);
        co_return;
    }
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
    co_await (udp_sock_to_stream(stream) || stream_to_udp_sock(stream) || keep_tcp_alive() || idle_watchdog());
    tunnel_manager_->remove_stream(stream);
    LOG_CTX_INFO(ctx_, "{} finished", log_event::kSocks);
}

boost::asio::awaitable<void> udp_socks_session::udp_sock_to_stream(std::shared_ptr<mux_stream> stream)
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    while (true)
    {
        const auto [ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_CTX_WARN(ctx_, "{} receive error {}", log_event::kSocks, ec.message());
            break;
        }
        if (!has_client_addr_)
        {
            client_addr_ = sender;
            has_client_addr_ = true;
        }
        if (sender != client_addr_)
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
        if (!validate_udp_header(buf, n, ctx_))
        {
            continue;
        }
        {
            mux_frame data_frame;
            data_frame.h.stream_id = stream->id();
            data_frame.h.command = mux::kCmdDat;
            data_frame.payload.assign(buf.begin(), buf.begin() + static_cast<int>(n));
            boost::system::error_code ec;
            co_await stream->async_write(data_frame, ec);
            if (ec)
            {
                LOG_CTX_ERROR(ctx_, "{} write to stream failed {}", log_event::kSocks, ec.message());
                break;
            }
            last_activity_time_ms_ = now_ms();
        }
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
