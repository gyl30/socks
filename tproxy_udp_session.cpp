#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "mux_codec.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "statistics.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "stop_dispatch.h"
#include "tproxy_udp_sender.h"
#include "client_tunnel_pool.h"
#include "tproxy_udp_session.h"

namespace mux
{

namespace
{

void close_start_failed_socket(boost::asio::ip::udp::socket& socket, const connection_context& ctx)
{
    boost::system::error_code close_ec;
    close_ec = socket.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx, "{} udp close failed {}", log_event::kSocks, close_ec.message());
    }
}

boost::asio::ip::udp::endpoint map_v4_to_v6(const boost::asio::ip::udp::endpoint& ep)
{
    if (!ep.address().is_v4())
    {
        return ep;
    }
    const auto v4 = ep.address().to_v4();
    const auto v4_bytes = v4.to_bytes();
    boost::asio::ip::address_v6::bytes_type v6_bytes = {0};
    v6_bytes[10] = 0xFF;
    v6_bytes[11] = 0xFF;
    v6_bytes[12] = v4_bytes[0];
    v6_bytes[13] = v4_bytes[1];
    v6_bytes[14] = v4_bytes[2];
    v6_bytes[15] = v4_bytes[3];
    return {boost::asio::ip::address_v6(v6_bytes), ep.port()};
}

void log_tproxy_udp_recv_channel_unavailable_on_data(const connection_context& ctx)
{
    LOG_CTX_WARN(ctx, "{} recv channel unavailable on data", log_event::kSocks);
}

}    // namespace

tproxy_udp_session::tproxy_udp_session(boost::asio::io_context& io_context,
                                       std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                       std::shared_ptr<router> router,
                                       std::shared_ptr<tproxy_udp_sender> sender,
                                       const std::uint32_t sid,
                                       const config& cfg,
                                       const boost::asio::ip::udp::endpoint& client_ep)
    : io_context_(io_context),
      direct_socket_(io_context_),
      tunnel_pool_(std::move(tunnel_pool)),
      router_(std::move(router)),
      sender_(std::move(sender)),
      recv_channel_(io_context_, cfg.queues.udp_session_recv_channel_capacity),
      client_ep_(net::normalize_endpoint(client_ep)),
      mark_(cfg.tproxy.mark)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_ms_.store(now_ms(), std::memory_order_relaxed);
}

bool tproxy_udp_session::start()
{
    terminated_.store(false, std::memory_order_release);
    boost::system::error_code ec;
    ec = direct_socket_.open(boost::asio::ip::udp::v6(), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp open failed {}", log_event::kSocks, ec.message());
        terminated_.store(true, std::memory_order_release);
        close_start_failed_socket(direct_socket_, ctx_);
        return false;
    }
    ec = direct_socket_.set_option(boost::asio::ip::v6_only(false), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp v6 only failed {}", log_event::kSocks, ec.message());
    }
    if (mark_ != 0)
    {
        if (auto r = net::set_socket_mark(direct_socket_.native_handle(), mark_); !r)
        {
            LOG_CTX_WARN(ctx_, "{} udp set mark failed {}", log_event::kSocks, r.error().message());
        }
    }
    ec = direct_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp bind failed {}", log_event::kSocks, ec.message());
        terminated_.store(true, std::memory_order_release);
        close_start_failed_socket(direct_socket_, ctx_);
        return false;
    }

    boost::asio::co_spawn(io_context_, direct_read_loop_detached(shared_from_this()), boost::asio::detached);
    return true;
}

boost::asio::awaitable<void> tproxy_udp_session::direct_read_loop_detached(std::shared_ptr<tproxy_udp_session> self)
{
    co_await self->direct_read_loop();
}

boost::asio::awaitable<void> tproxy_udp_session::handle_packet(const boost::asio::ip::udp::endpoint& dst_ep, std::vector<std::uint8_t> data)
{
    co_await boost::asio::dispatch(io_context_, boost::asio::use_awaitable);
    co_await handle_packet_inner(dst_ep, std::move(data));
}

boost::asio::awaitable<void> tproxy_udp_session::handle_packet(const boost::asio::ip::udp::endpoint& dst_ep,
                                                               const std::uint8_t* data,
                                                               const std::size_t len)
{
    auto payload = std::vector<std::uint8_t>(data, data + len);
    co_await handle_packet(dst_ep, std::move(payload));
}

boost::asio::awaitable<void> tproxy_udp_session::handle_packet_inner(boost::asio::ip::udp::endpoint dst_ep, std::vector<std::uint8_t> data)
{
    if (terminated_.load(std::memory_order_acquire))
    {
        co_return;
    }
    dst_ep = net::normalize_endpoint(dst_ep);
    if (dst_ep.address().is_unspecified() || dst_ep.port() == 0)
    {
        LOG_CTX_WARN(ctx_, "{} udp invalid target {} {}", log_event::kSocks, dst_ep.address().to_string(), dst_ep.port());
        co_return;
    }
    touch();
    if (router_ == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp router unavailable", log_event::kRoute);
        stop_local(true);
        co_return;
    }
    const auto host = dst_ep.address().to_string();
    const auto route = co_await router_->decide_ip(ctx_, host, dst_ep.address());
    if (terminated_.load(std::memory_order_acquire))
    {
        co_return;
    }

    if (route == route_type::kBlock)
    {
        statistics::instance().inc_routing_blocked();
        LOG_CTX_WARN(ctx_, "{} blocked udp {}", log_event::kRoute, host);
        co_return;
    }

    if (route == route_type::kDirect)
    {
        co_await send_direct(dst_ep, data.data(), data.size());
        co_return;
    }

    co_await send_proxy(dst_ep, data.data(), data.size());
}

void tproxy_udp_session::stop()
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   self->stop_local(true);
                                               }
                                           });
}

void tproxy_udp_session::on_data(std::vector<std::uint8_t> data)
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [self = shared_from_this(), data = std::move(data)]() mutable
                                           {
                                               if (!self->recv_channel_.try_send(boost::system::error_code(), std::move(data)))
                                               {
                                                   log_tproxy_udp_recv_channel_unavailable_on_data(self->ctx_);
                                                   self->stop();
                                               }
                                           });
}

void tproxy_udp_session::on_close()
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   self->on_close_local();
                                               }
                                           });
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

void tproxy_udp_session::stop_local(const bool allow_async_stream_close)
{
    const auto already_terminated = terminated_.exchange(true, std::memory_order_acq_rel);
    if (already_terminated)
    {
        return;
    }

    recv_channel_.close();
    auto stream = stream_;
    auto tunnel = tunnel_.lock();
    stream_.reset();
    tunnel_.reset();

    if (stream != nullptr && tunnel != nullptr)
    {
        tunnel->remove_stream(stream->id());
    }

    if (stream != nullptr && allow_async_stream_close)
    {
        if (io_context_.stopped())
        {
            stream->on_reset();
        }
        else if (io_context_.get_executor().running_in_this_thread())
        {
            boost::asio::co_spawn(io_context_, [stream]() -> boost::asio::awaitable<void> { co_await stream->close(); }, boost::asio::detached);
        }
        else
        {
            // io_context may not be running yet. Keep close asynchronous so FIN can
            // still be sent once the event loop starts.
            boost::asio::co_spawn(io_context_, [stream]() -> boost::asio::awaitable<void> { co_await stream->close(); }, boost::asio::detached);
        }
    }

    boost::system::error_code ignore;
    ignore = direct_socket_.close(ignore);
}

void tproxy_udp_session::on_close_local() { stop_local(false); }

boost::asio::awaitable<bool> tproxy_udp_session::negotiate_proxy_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                                        const std::shared_ptr<mux_stream>& stream) const
{
    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0, .trace_id = ctx_.trace_id()};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    if (const auto ec = co_await tunnel->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data)))
    {
        LOG_CTX_WARN(ctx_, "{} udp syn failed {}", log_event::kSocks, ec.message());
        co_return false;
    }

    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp ack failed {}", log_event::kSocks, ack_ec.message());
        co_return false;
    }

    ack_payload ack_pl;
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl) || ack_pl.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx_, "{} udp ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<void> tproxy_udp_session::cleanup_proxy_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                                                      const std::shared_ptr<mux_stream>& stream)
{
    co_await stream->close();
    tunnel->remove_stream(stream->id());
}

bool tproxy_udp_session::install_proxy_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel,
                                              const std::shared_ptr<mux_stream>& stream,
                                              bool& should_start_reader)
{
    if (terminated_.load(std::memory_order_acquire))
    {
        return false;
    }

    if (stream_ != nullptr)
    {
        return false;
    }

    if (!tunnel->register_stream(stream->id(), shared_from_this()))
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy register stream failed {}", log_event::kSocks, stream->id());
        return false;
    }

    if (terminated_.load(std::memory_order_acquire))
    {
        return false;
    }

    stream_ = stream;
    tunnel_ = tunnel;
    if (!proxy_reader_started_)
    {
        proxy_reader_started_ = true;
        should_start_reader = true;
    }
    return true;
}

boost::asio::awaitable<std::optional<bool>> tproxy_udp_session::open_proxy_stream()
{
    if (tunnel_pool_ == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy tunnel pool unavailable", log_event::kSocks);
        co_return std::nullopt;
    }

    const auto tunnel = tunnel_pool_->select_tunnel();
    if (tunnel == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy no active tunnel", log_event::kSocks);
        co_return std::nullopt;
    }

    const auto stream = tunnel->create_stream(ctx_.trace_id());
    if (stream == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy create stream failed", log_event::kSocks);
        co_return std::nullopt;
    }

    if (!co_await negotiate_proxy_stream(tunnel, stream))
    {
        co_await cleanup_proxy_stream(tunnel, stream);
        co_return std::nullopt;
    }

    bool should_start_reader = false;
    if (!install_proxy_stream(tunnel, stream, should_start_reader))
    {
        co_await cleanup_proxy_stream(tunnel, stream);
        co_return false;
    }
    co_return should_start_reader;
}

void tproxy_udp_session::maybe_start_proxy_reader(const bool should_start_reader)
{
    if (!should_start_reader)
    {
        return;
    }
    boost::asio::co_spawn(io_context_, proxy_read_loop_detached(shared_from_this()), boost::asio::detached);
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_read_loop_detached(std::shared_ptr<tproxy_udp_session> self)
{
    co_await self->proxy_read_loop();
}

boost::asio::awaitable<bool> tproxy_udp_session::ensure_proxy_stream()
{
    if (terminated_.load(std::memory_order_acquire))
    {
        co_return false;
    }

    if (stream_ != nullptr)
    {
        co_return true;
    }

    const auto open_result = co_await open_proxy_stream();
    if (terminated_.load(std::memory_order_acquire))
    {
        co_return false;
    }
    if (!open_result.has_value())
    {
        co_return false;
    }
    if (!open_result.value())
    {
        // Another coroutine may have installed a stream while this coroutine was
        // waiting for SYN/ACK. Treat it as success if stream_ is now available.
        if (stream_ != nullptr)
        {
            co_return true;
        }
        LOG_CTX_WARN(ctx_, "{} udp proxy stream install failed", log_event::kSocks);
        co_return false;
    }
    maybe_start_proxy_reader(*open_result);
    co_return stream_ != nullptr;
}

void tproxy_udp_session::refresh_cached_proxy_header(const boost::asio::ip::udp::endpoint& dst_ep)
{
    if (has_cached_proxy_header_ && cached_proxy_dst_ep_ == dst_ep)
    {
        return;
    }
    socks_udp_header h;
    h.addr = dst_ep.address().to_string();
    h.port = dst_ep.port();
    cached_proxy_header_ = socks_codec::encode_udp_header(h);
    cached_proxy_dst_ep_ = dst_ep;
    has_cached_proxy_header_ = true;
}

bool tproxy_udp_session::build_proxy_packet(const boost::asio::ip::udp::endpoint& dst_ep,
                                            const std::uint8_t* data,
                                            const std::size_t len,
                                            std::vector<std::uint8_t>& packet)
{
    refresh_cached_proxy_header(dst_ep);
    if (cached_proxy_header_.size() + len > mux::kMaxPayload)
    {
        LOG_CTX_WARN(ctx_, "{} udp packet too large {}", log_event::kSocks, len);
        return false;
    }

    packet.clear();
    packet.reserve(cached_proxy_header_.size() + len);
    packet.insert(packet.end(), cached_proxy_header_.begin(), cached_proxy_header_.end());
    packet.insert(packet.end(), data, data + len);
    return true;
}

boost::asio::awaitable<void> tproxy_udp_session::handle_proxy_write_failure(const std::shared_ptr<mux_stream>& stream,
                                                                            const boost::system::error_code& write_ec)
{
    LOG_CTX_WARN(ctx_, "{} udp write to stream failed {}", log_event::kSocks, write_ec.message());
    auto tunnel = tunnel_.lock();
    if (stream_ == stream)
    {
        stream_.reset();
        tunnel_.reset();
    }
    co_await stream->close();
    if (tunnel != nullptr)
    {
        tunnel->remove_stream(stream->id());
    }
}

boost::asio::awaitable<void> tproxy_udp_session::send_proxy(const boost::asio::ip::udp::endpoint& dst_ep,
                                                            const std::uint8_t* data,
                                                            const std::size_t len)
{
    if (terminated_.load(std::memory_order_acquire))
    {
        co_return;
    }

    if (!co_await ensure_proxy_stream())
    {
        co_return;
    }

    if (terminated_.load(std::memory_order_acquire))
    {
        co_return;
    }

    std::vector<std::uint8_t> pkt;
    if (!build_proxy_packet(dst_ep, data, len, pkt))
    {
        co_return;
    }

    auto stream = stream_;
    if (stream == nullptr)
    {
        LOG_CTX_WARN(ctx_, "{} udp proxy stream unavailable after ensure", log_event::kSocks);
        co_return;
    }

    const auto write_ec = co_await stream->async_write_some(std::move(pkt));
    if (write_ec)
    {
        if (write_ec == boost::asio::error::message_size)
        {
            LOG_CTX_WARN(ctx_, "{} udp drop oversized proxy packet size {}", log_event::kSocks, len);
            co_return;
        }
        co_await handle_proxy_write_failure(stream, write_ec);
    }
}

boost::asio::awaitable<void> tproxy_udp_session::send_direct(const boost::asio::ip::udp::endpoint& dst_ep,
                                                             const std::uint8_t* data,
                                                             const std::size_t len)
{
    const auto target = map_v4_to_v6(dst_ep);
    const auto [ec, n] =
        co_await direct_socket_.async_send_to(boost::asio::buffer(data, len), target, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp direct send failed {}", log_event::kSocks, ec.message());
    }
}

boost::asio::awaitable<void> tproxy_udp_session::direct_read_loop()
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    for (;;)
    {
        const auto [recv_ec, n] =
            co_await direct_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != boost::asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} udp direct recv failed {}", log_event::kSocks, recv_ec.message());
            }
            break;
        }

        touch();
        const auto norm_sender = net::normalize_endpoint(sender);
        auto sender = sender_;
        if (sender == nullptr)
        {
            LOG_CTX_WARN(ctx_, "{} udp sender unavailable", log_event::kSocks);
            continue;
        }
        co_await sender->send_to_client(client_ep_, norm_sender, boost::asio::buffer(buf.data(), n));
    }
}

boost::asio::awaitable<void> tproxy_udp_session::proxy_read_loop()
{
    for (;;)
    {
        const auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec || data.empty())
        {
            break;
        }

        touch();
        boost::asio::ip::udp::endpoint src_ep;
        std::size_t payload_offset = 0;
        if (!decode_proxy_packet(data, src_ep, payload_offset))
        {
            continue;
        }
        auto sender = sender_;
        if (sender == nullptr)
        {
            LOG_CTX_WARN(ctx_, "{} udp sender unavailable", log_event::kSocks);
            continue;
        }
        co_await sender->send_to_client(
            client_ep_, src_ep, boost::asio::buffer(data.data() + static_cast<std::ptrdiff_t>(payload_offset), data.size() - payload_offset));
    }
}

bool tproxy_udp_session::decode_proxy_packet(const std::vector<std::uint8_t>& data,
                                             boost::asio::ip::udp::endpoint& src_ep,
                                             std::size_t& payload_offset) const
{
    socks_udp_header h;
    if (!socks_codec::decode_udp_header(data.data(), data.size(), h))
    {
        LOG_CTX_WARN(ctx_, "{} udp decode header failed", log_event::kSocks);
        return false;
    }
    if (h.frag != 0x00)
    {
        LOG_CTX_WARN(ctx_, "{} udp unsupported frag {}", log_event::kSocks, h.frag);
        return false;
    }
    if (h.port == 0)
    {
        LOG_CTX_WARN(ctx_, "{} udp target port invalid 0", log_event::kSocks);
        return false;
    }
    if (h.header_len > data.size())
    {
        LOG_CTX_WARN(ctx_, "{} udp header len invalid", log_event::kSocks);
        return false;
    }

    boost::system::error_code addr_ec;
    const auto addr = boost::asio::ip::make_address(h.addr, addr_ec);
    if (addr_ec)
    {
        LOG_CTX_WARN(ctx_, "{} udp parse addr failed {}", log_event::kSocks, addr_ec.message());
        return false;
    }
    if (addr.is_unspecified())
    {
        LOG_CTX_WARN(ctx_, "{} udp source addr unspecified", log_event::kSocks);
        return false;
    }
    src_ep = boost::asio::ip::udp::endpoint(addr, h.port);
    payload_offset = h.header_len;
    return true;
}

}    // namespace mux
