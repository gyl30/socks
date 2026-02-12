#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/post.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/channel_error.hpp>
#include <asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
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

[[nodiscard]] bool is_expected_channel_recv_error(const std::error_code& ec)
{
    return ec == asio::error::operation_aborted || ec == asio::experimental::error::channel_closed ||
           ec == asio::experimental::error::channel_cancelled;
}

[[nodiscard]] bool is_expected_keepalive_error(const std::error_code& ec)
{
    return ec == asio::error::eof || ec == asio::error::operation_aborted || ec == asio::error::bad_descriptor || ec == asio::error::not_connected;
}

asio::awaitable<void> write_socks_error_reply(asio::ip::tcp::socket& socket, const std::uint8_t rep)
{
    std::uint8_t err[] = {socks::kVer, rep, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    co_await asio::async_write(socket, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
}

bool bind_udp_socket_for_associate(asio::ip::tcp::socket& tcp_socket,
                                   asio::ip::udp::socket& udp_socket,
                                   const connection_context& ctx,
                                   asio::ip::address& local_addr,
                                   std::uint16_t& udp_bind_port)
{
    std::error_code ec;
    const auto tcp_local_ep = tcp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} failed to get local endpoint {}", log_event::kSocks, ec.message());
        return false;
    }

    local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    const auto udp_protocol = local_addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4();

    ec = udp_socket.open(udp_protocol, ec);
    if (!ec)
    {
        if (local_addr.is_v6())
        {
            ec = udp_socket.set_option(asio::ip::v6_only(false), ec);
        }
        ec = udp_socket.bind(asio::ip::udp::endpoint(local_addr, 0), ec);
    }

    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} bind failed {}", log_event::kSocks, ec.message());
        return false;
    }

    const auto udp_local_ep = udp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} query udp endpoint failed {}", log_event::kSocks, ec.message());
        return false;
    }
    udp_bind_port = udp_local_ep.port();
    LOG_CTX_INFO(ctx, "{} started bound at {} {}", log_event::kSocks, local_addr.to_string(), udp_bind_port);
    return true;
}

asio::awaitable<std::shared_ptr<mux_stream>> establish_udp_associate_stream(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                                                                            const connection_context& ctx)
{
    const auto stream = tunnel_manager->create_stream();
    if (stream == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to create stream", log_event::kSocks);
        co_return nullptr;
    }

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    auto ec = co_await tunnel_manager->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} syn failed {}", log_event::kSocks, ec.message());
        co_await stream->close();
        co_return nullptr;
    }

    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx, "{} ack failed {}", log_event::kSocks, ack_ec.message());
        co_await stream->close();
        co_return nullptr;
    }

    ack_payload ack_pl;
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx, "{} ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_await stream->close();
        co_return nullptr;
    }

    co_return stream;
}

std::vector<std::uint8_t> build_udp_associate_reply(const asio::ip::address& local_addr, const std::uint16_t udp_bind_port)
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

}    // namespace

udp_socks_session::udp_socks_session(asio::ip::tcp::socket socket,
                                     asio::io_context& io_context,
                                     std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                                     const std::uint32_t sid,
                                     const config::timeout_t& timeout_cfg)
    : io_context_(io_context),
      timer_(io_context_),
      idle_timer_(io_context_),
      socket_(std::move(socket)),
      udp_socket_(io_context_),
      tunnel_manager_(std::move(tunnel_manager)),
      recv_channel_(io_context_, 128),
      timeout_config_(timeout_cfg)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_.store(now_ms(), std::memory_order_release);
}

void udp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    const auto self = shared_from_this();
    asio::co_spawn(io_context_, [self, host, port]() -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
}

void udp_socks_session::on_data(std::vector<std::uint8_t> data) { recv_channel_.try_send(std::error_code(), std::move(data)); }

void udp_socks_session::on_close()
{
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    const auto self = shared_from_this();
    asio::post(io_context_, [self]() { self->close_impl(); });
}

void udp_socks_session::close_impl()
{
    recv_channel_.close();
    timer_.cancel();
    idle_timer_.cancel();
    std::error_code close_ec;
    udp_socket_.close(close_ec);
    if (close_ec && close_ec != asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close udp socket failed {}", log_event::kSocks, close_ec.message());
    }
}

void udp_socks_session::on_reset() { on_close(); }

asio::awaitable<void> udp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    (void)host;
    (void)port;

    asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    if (!bind_udp_socket_for_associate(socket_, udp_socket_, ctx_, local_addr, udp_bind_port))
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail);
        co_return;
    }

    if (tunnel_manager_ == nullptr || tunnel_manager_->connection() == nullptr || !tunnel_manager_->connection()->is_open())
    {
        LOG_CTX_WARN(ctx_, "{} tunnel unavailable", log_event::kSocks);
        co_await write_socks_error_reply(socket_, socks::kRepHostUnreach);
        on_close();
        co_return;
    }

    const auto stream = co_await establish_udp_associate_stream(tunnel_manager_, ctx_);
    if (stream == nullptr)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail);
        on_close();
        co_return;
    }

    const auto final_rep = build_udp_associate_reply(local_addr, udp_bind_port);
    const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(final_rep), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_CTX_WARN(ctx_, "{} write failed {}", log_event::kSocks, we.message());
        co_await stream->close();
        co_return;
    }

    const auto client_ep_ptr = std::make_shared<asio::ip::udp::endpoint>();

    tunnel_manager_->register_stream(stream->id(), shared_from_this());

    using asio::experimental::awaitable_operators::operator||;
    co_await (udp_sock_to_stream(stream, client_ep_ptr) || stream_to_udp_sock(stream, client_ep_ptr) || keep_tcp_alive() || idle_watchdog());

    on_close();
    tunnel_manager_->remove_stream(stream->id());
    co_await stream->close();
    LOG_CTX_INFO(ctx_, "{} finished", log_event::kSocks);
}

asio::awaitable<void> udp_socks_session::udp_sock_to_stream(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
{
    std::vector<std::uint8_t> buf(65535);
    asio::ip::udp::endpoint sender;
    while (!closed_.load(std::memory_order_acquire))
    {
        const auto [recv_ec, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} receive error {}", log_event::kSocks, recv_ec.message());
            }
            break;
        }
        socks_udp_header h;
        if (!socks_codec::decode_udp_header(buf.data(), n, h))
        {
            LOG_CTX_WARN(ctx_, "{} received invalid udp packet from {}", log_event::kSocks, sender.address().to_string());
            continue;
        }

        if (h.frag != 0x00)
        {
            LOG_CTX_WARN(ctx_, "{} received a fragmented packet ignore it", log_event::kSocks);
            continue;
        }

        if (n > mux::kMaxPayload)
        {
            LOG_CTX_WARN(ctx_, "{} udp packet too large {}", log_event::kSocks, n);
            continue;
        }

        if (!has_client_ep_)
        {
            client_ep_ = sender;
            has_client_ep_ = true;
        }
        else if (sender.address() != client_ep_.address() || sender.port() != client_ep_.port())
        {
            LOG_CTX_WARN(ctx_, "{} udp client endpoint mismatch ignore", log_event::kSocks);
            continue;
        }

        const auto write_ec = co_await stream->async_write_some(buf.data(), n);
        if (write_ec)
        {
            LOG_CTX_ERROR(ctx_, "{} write to stream failed {}", log_event::kSocks, write_ec.message());
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
}

asio::awaitable<void> udp_socks_session::stream_to_udp_sock(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
{
    while (!closed_.load(std::memory_order_acquire))
    {
        const auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec || data.empty())
        {
            if (ec && !is_expected_channel_recv_error(ec))
            {
                LOG_CTX_ERROR(ctx_, "{} recv error {}", log_event::kSocks, ec.message());
            }
            else if (ec)
            {
                LOG_CTX_DEBUG(ctx_, "{} recv stopped {}", log_event::kSocks, ec.message());
            }
            break;
        }

        if (!has_client_ep_)
        {
            LOG_CTX_WARN(ctx_, "{} client ep port is 0 ignore it", log_event::kSocks);
            continue;
        }
        const auto ep = client_ep_;

        if (ep.port() == 0)
        {
            LOG_CTX_WARN(ctx_, "{} client ep port is 0 ignore it", log_event::kSocks);
            continue;
        }

        const auto [se, sn] = co_await udp_socket_.async_send_to(asio::buffer(data), ep, asio::as_tuple(asio::use_awaitable));
        if (se)
        {
            LOG_CTX_ERROR(ctx_, "{} send error {}", log_event::kSocks, se.message());
        }
        else
        {
            last_activity_time_ms_.store(now_ms(), std::memory_order_release);
        }
    }
}

asio::awaitable<void> udp_socks_session::keep_tcp_alive()
{
    char b[1];
    const auto [ec, n] = co_await socket_.async_read_some(asio::buffer(b), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        if (is_expected_keepalive_error(ec))
        {
            LOG_CTX_DEBUG(ctx_, "{} keep tcp alive stopped {}", log_event::kSocks, ec.message());
        }
        else
        {
            LOG_CTX_ERROR(ctx_, "{} keep tcp alive error {}", log_event::kSocks, ec.message());
        }
    }
}

asio::awaitable<void> udp_socks_session::idle_watchdog()
{
    while (!closed_.load(std::memory_order_acquire))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        const auto current_ms = now_ms();
        const auto elapsed_ms = current_ms - last_activity_time_ms_.load(std::memory_order_acquire);
        const auto idle_timeout_ms = static_cast<std::uint64_t>(timeout_config_.idle) * 1000ULL;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_CTX_WARN(ctx_, "{} udp session idle closing", log_event::kSocks);
            on_close();
            break;
        }
    }
}

}    // namespace mux
