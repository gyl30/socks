#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/error.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "mux_codec.h"
#include "mux_stream.h"
#include "mux_protocol.h"
#include "tproxy_udp_session.h"

namespace mux
{

namespace
{

asio::ip::udp::endpoint map_v4_to_v6(const asio::ip::udp::endpoint& ep)
{
    if (!ep.address().is_v4())
    {
        return ep;
    }
    const auto v4 = ep.address().to_v4();
    const auto v4_bytes = v4.to_bytes();
    asio::ip::address_v6::bytes_type v6_bytes = {0};
    v6_bytes[10] = 0xFF;
    v6_bytes[11] = 0xFF;
    v6_bytes[12] = v4_bytes[0];
    v6_bytes[13] = v4_bytes[1];
    v6_bytes[14] = v4_bytes[2];
    v6_bytes[15] = v4_bytes[3];
    return asio::ip::udp::endpoint(asio::ip::address_v6(v6_bytes), ep.port());
}

}    // namespace

tproxy_udp_session::tproxy_udp_session(const asio::any_io_executor& ex,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       std::shared_ptr<router> router,
                                       std::shared_ptr<tproxy_udp_sender> sender,
                                       const std::uint32_t sid,
                                       const config& cfg,
                                       asio::ip::udp::endpoint client_ep)
    : direct_socket_(ex),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      sender_(std::move(sender)),
      recv_channel_(ex, 128),
      client_ep_(net::normalize_endpoint(client_ep)),
      mark_(cfg.tproxy.mark)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_ms_.store(now_ms(), std::memory_order_relaxed);
}

void tproxy_udp_session::start()
{
    std::error_code ec;
    ec = direct_socket_.open(asio::ip::udp::v6(), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp open failed {}", log_event::kSocks, ec.message());
        return;
    }
    ec = direct_socket_.set_option(asio::ip::v6_only(false), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp v6 only failed {}", log_event::kSocks, ec.message());
    }
    if (mark_ != 0)
    {
        std::error_code mark_ec;
        if (!net::set_socket_mark(direct_socket_.native_handle(), mark_, mark_ec))
        {
            LOG_CTX_WARN(ctx_, "{} udp set mark failed {}", log_event::kSocks, mark_ec.message());
        }
    }
    ec = direct_socket_.bind(asio::ip::udp::endpoint(asio::ip::address_v6::any(), 0), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp bind failed {}", log_event::kSocks, ec.message());
        return;
    }

    asio::co_spawn(direct_socket_.get_executor(),
                   [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->direct_read_loop(); },
                   asio::detached);
}

asio::awaitable<void> tproxy_udp_session::handle_packet(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, const std::size_t len)
{
    touch();
    const auto host = dst_ep.address().to_string();
    const auto route = co_await router_->decide_ip(ctx_, host, dst_ep.address(), direct_socket_.get_executor());

    if (route == route_type::block)
    {
        LOG_CTX_WARN(ctx_, "{} blocked udp {}", log_event::kRoute, host);
        co_return;
    }

    if (route == route_type::direct)
    {
        co_await send_direct(dst_ep, data, len);
        co_return;
    }

    co_await send_proxy(dst_ep, data, len);
}

void tproxy_udp_session::stop()
{
    recv_channel_.close();
    if (tunnel_ != nullptr && stream_ != nullptr)
    {
        tunnel_->remove_stream(stream_->id());
    }
    stream_.reset();
    tunnel_.reset();
    std::error_code ignore;
    ignore = direct_socket_.close(ignore);
}

void tproxy_udp_session::on_data(std::vector<std::uint8_t> data) { recv_channel_.try_send(std::error_code(), std::move(data)); }

void tproxy_udp_session::on_close()
{
    if (tunnel_ != nullptr && stream_ != nullptr)
    {
        tunnel_->remove_stream(stream_->id());
    }
    stream_.reset();
    tunnel_.reset();
}

void tproxy_udp_session::on_reset() { on_close(); }

bool tproxy_udp_session::is_idle(const std::uint64_t now_ms, const std::uint64_t idle_ms) const
{
    if (idle_ms == 0)
    {
        return false;
    }
    const auto last = last_activity_ms_.load(std::memory_order_relaxed);
    return now_ms > last + idle_ms;
}

std::uint64_t tproxy_udp_session::now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void tproxy_udp_session::touch() { last_activity_ms_.store(now_ms(), std::memory_order_relaxed); }

asio::awaitable<bool> tproxy_udp_session::ensure_proxy_stream()
{
    const std::lock_guard<std::mutex> lock(stream_mutex_);
    if (stream_ != nullptr)
    {
        co_return true;
    }

    const auto tunnel = tunnel_pool_->select_tunnel();
    if (tunnel == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy no active tunnel", log_event::kSocks);
        co_return false;
    }

    const auto stream = tunnel->create_stream(ctx_.trace_id());
    if (stream == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy create stream failed", log_event::kSocks);
        co_return false;
    }

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    if (const auto ec = co_await tunnel->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data)))
    {
        LOG_CTX_WARN(ctx_, "{} udp syn failed {}", log_event::kSocks, ec.message());
        co_await stream->close();
        co_return false;
    }

    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp ack failed {}", log_event::kSocks, ack_ec.message());
        co_await stream->close();
        co_return false;
    }

    ack_payload ack_pl;
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx_, "{} udp ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_await stream->close();
        co_return false;
    }

    tunnel->register_stream(stream->id(), shared_from_this());
    stream_ = stream;
    tunnel_ = tunnel;

    if (!proxy_reader_started_)
    {
        proxy_reader_started_ = true;
        asio::co_spawn(direct_socket_.get_executor(),
                       [self = shared_from_this()]() -> asio::awaitable<void> { co_await self->proxy_read_loop(); },
                       asio::detached);
    }

    co_return true;
}

asio::awaitable<void> tproxy_udp_session::send_proxy(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, const std::size_t len)
{
    if (!co_await ensure_proxy_stream())
    {
        co_return;
    }

    socks_udp_header h;
    h.addr = dst_ep.address().to_string();
    h.port = dst_ep.port();
    std::vector<std::uint8_t> pkt = socks_codec::encode_udp_header(h);
    if (pkt.size() + len > mux::kMaxPayload)
    {
        LOG_CTX_WARN(ctx_, "{} udp packet too large {}", log_event::kSocks, len);
        co_return;
    }
    pkt.insert(pkt.end(), data, data + len);

    if (const auto write_ec = co_await stream_->async_write_some(pkt.data(), pkt.size()))
    {
        LOG_CTX_WARN(ctx_, "{} udp write to stream failed {}", log_event::kSocks, write_ec.message());
    }
}

asio::awaitable<void> tproxy_udp_session::send_direct(const asio::ip::udp::endpoint& dst_ep, const std::uint8_t* data, const std::size_t len)
{
    const auto target = map_v4_to_v6(dst_ep);
    const auto [ec, n] = co_await direct_socket_.async_send_to(asio::buffer(data, len), target, asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp direct send failed {}", log_event::kSocks, ec.message());
    }
}

asio::awaitable<void> tproxy_udp_session::direct_read_loop()
{
    std::vector<std::uint8_t> buf(65535);
    asio::ip::udp::endpoint sender;
    for (;;)
    {
        const auto [recv_ec, n] = co_await direct_socket_.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} udp direct recv failed {}", log_event::kSocks, recv_ec.message());
            }
            break;
        }

        touch();
        const auto norm_sender = net::normalize_endpoint(sender);
        std::vector<std::uint8_t> payload(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
        co_await sender_->send_to_client(client_ep_, norm_sender, payload);
    }
}

asio::awaitable<void> tproxy_udp_session::proxy_read_loop()
{
    for (;;)
    {
        const auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec || data.empty())
        {
            break;
        }

        touch();
        socks_udp_header h;
        if (!socks_codec::decode_udp_header(data.data(), data.size(), h))
        {
            LOG_CTX_WARN(ctx_, "{} udp decode header failed", log_event::kSocks);
            continue;
        }

        if (h.header_len > data.size())
        {
            LOG_CTX_WARN(ctx_, "{} udp header len invalid", log_event::kSocks);
            continue;
        }

        std::error_code addr_ec;
        const auto addr = asio::ip::make_address(h.addr, addr_ec);
        if (addr_ec)
        {
            LOG_CTX_WARN(ctx_, "{} udp parse addr failed {}", log_event::kSocks, addr_ec.message());
            continue;
        }
        asio::ip::udp::endpoint src_ep(addr, h.port);
        std::vector<std::uint8_t> payload(data.begin() + static_cast<std::ptrdiff_t>(h.header_len), data.end());
        co_await sender_->send_to_client(client_ep_, src_ep, payload);
    }
}

}    // namespace mux
