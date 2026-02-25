#include <atomic>
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
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "mux_stream.h"
#include "mux_tunnel.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "stop_dispatch.h"
#include "timeout_io.h"
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

[[nodiscard]] bool is_expected_channel_recv_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::experimental::error::channel_closed ||
           ec == boost::asio::experimental::error::channel_cancelled;
}

[[nodiscard]] bool is_expected_keepalive_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::eof || ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor ||
           ec == boost::asio::error::not_connected;
}

void log_udp_recv_channel_unavailable_on_data(const connection_context& ctx)
{
    LOG_CTX_WARN(ctx, "{} recv channel unavailable on data", log_event::kSocks);
}

boost::asio::awaitable<void> write_socks_error_reply(boost::asio::ip::tcp::socket& socket,
                                                     const std::uint8_t rep,
                                                     const connection_context& ctx,
                                                     const std::uint32_t timeout_sec)
{
    std::uint8_t err[] = {socks::kVer, rep, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    const auto write_res = co_await timeout_io::async_write_with_timeout(socket, boost::asio::buffer(err), timeout_sec, "udp socks session");
    if (write_res.ok)
    {
        co_return;
    }
    if (write_res.timed_out)
    {
        LOG_CTX_WARN(ctx, "{} write error reply timeout {}s", log_event::kSocks, timeout_sec);
        co_return;
    }
    LOG_CTX_WARN(ctx, "{} write error reply failed {}", log_event::kSocks, write_res.ec.message());
}

void close_udp_socket_on_prepare_failure(boost::asio::ip::udp::socket& udp_socket, const connection_context& ctx)
{
    boost::system::error_code close_ec;
    close_ec = udp_socket.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx, "{} close udp socket failed {}", log_event::kSocks, close_ec.message());
    }
}

bool open_and_bind_udp_socket(boost::asio::ip::udp::socket& udp_socket, const boost::asio::ip::address& local_addr, const connection_context& ctx)
{
    const auto udp_protocol = local_addr.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4();
    boost::system::error_code ec;
    const char* failed_step = nullptr;
    ec = udp_socket.open(udp_protocol, ec);
    if (ec)
    {
        failed_step = "open";
    }
    if (!ec && local_addr.is_v6())
    {
        ec = udp_socket.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            failed_step = "set v6 only";
        }
    }
    if (!ec)
    {
        ec = udp_socket.bind(boost::asio::ip::udp::endpoint(local_addr, 0), ec);
        if (ec)
        {
            failed_step = "bind";
        }
    }
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} udp {} failed {}", log_event::kSocks, failed_step, ec.message());
        close_udp_socket_on_prepare_failure(udp_socket, ctx);
        return false;
    }
    return true;
}

bool query_udp_bind_port(boost::asio::ip::udp::socket& udp_socket, const connection_context& ctx, std::uint16_t& udp_bind_port)
{
    boost::system::error_code ec;
    const auto udp_local_ep = udp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} query udp endpoint failed {}", log_event::kSocks, ec.message());
        close_udp_socket_on_prepare_failure(udp_socket, ctx);
        return false;
    }
    udp_bind_port = udp_local_ep.port();
    return true;
}

bool bind_udp_socket_for_associate(boost::asio::ip::tcp::socket& tcp_socket,
                                   boost::asio::ip::udp::socket& udp_socket,
                                   const connection_context& ctx,
                                   boost::asio::ip::address& local_addr,
                                   std::uint16_t& udp_bind_port)
{
    boost::system::error_code ec;
    const auto tcp_local_ep = tcp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} failed to get local endpoint {}", log_event::kSocks, ec.message());
        return false;
    }

    local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    if (!open_and_bind_udp_socket(udp_socket, local_addr, ctx))
    {
        return false;
    }

    if (!query_udp_bind_port(udp_socket, ctx, udp_bind_port))
    {
        return false;
    }
    LOG_CTX_INFO(ctx, "{} started bound at {} {}", log_event::kSocks, local_addr.to_string(), udp_bind_port);
    return true;
}

void configure_expected_client_constraint(const std::string& host,
                                          const std::uint16_t port,
                                          std::optional<boost::asio::ip::address>& expected_addr,
                                          std::optional<std::uint16_t>& expected_port)
{
    expected_addr.reset();
    expected_port.reset();
    if (port != 0)
    {
        expected_port = port;
    }

    boost::system::error_code addr_ec;
    auto parsed_addr = boost::asio::ip::make_address(host, addr_ec);
    if (addr_ec)
    {
        return;
    }

    parsed_addr = socks_codec::normalize_ip_address(parsed_addr);
    if (!parsed_addr.is_unspecified())
    {
        expected_addr = parsed_addr;
    }
}

boost::asio::awaitable<void> close_and_remove_stream(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel_manager,
                                                     const std::shared_ptr<mux_stream>& stream)
{
    if (stream == nullptr)
    {
        co_return;
    }

    co_await stream->close();
    if (tunnel_manager != nullptr)
    {
        tunnel_manager->remove_stream(stream->id());
    }
}

boost::asio::awaitable<std::shared_ptr<mux_stream>> establish_udp_associate_stream(
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager, const connection_context& ctx, const std::uint32_t timeout_sec)
{
    const auto stream = tunnel_manager->create_stream();
    if (stream == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to create stream", log_event::kSocks);
        co_return nullptr;
    }

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0, .trace_id = ctx.trace_id()};
    std::vector<std::uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    auto ec = co_await tunnel_manager->connection()->send_async(stream->id(), kCmdSyn, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_WARN(ctx, "{} syn failed {}", log_event::kSocks, ec.message());
        co_await close_and_remove_stream(tunnel_manager, stream);
        co_return nullptr;
    }

    auto timeout_fired = std::make_shared<std::atomic<bool>>(false);
    auto wait_done = std::make_shared<std::atomic<bool>>(false);
    auto ex = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer ack_timer(ex);
    if (timeout_sec > 0)
    {
        ack_timer.expires_after(std::chrono::seconds(timeout_sec));
        ack_timer.async_wait(
            [stream, timeout_fired, wait_done](const boost::system::error_code& timer_ec)
            {
                if (timer_ec)
                {
                    return;
                }
                bool expected = false;
                if (!wait_done->compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
                timeout_fired->store(true, std::memory_order_release);
                stream->on_reset();
            });
    }

    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (timeout_sec > 0)
    {
        bool expected = false;
        (void)wait_done->compare_exchange_strong(expected, true, std::memory_order_acq_rel, std::memory_order_acquire);
        ack_timer.cancel();
    }
    if (timeout_fired->load(std::memory_order_acquire))
    {
        LOG_CTX_WARN(ctx, "{} ack timeout {}s", log_event::kSocks, timeout_sec);
        co_await close_and_remove_stream(tunnel_manager, stream);
        co_return nullptr;
    }
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx, "{} ack failed {}", log_event::kSocks, ack_ec.message());
        co_await close_and_remove_stream(tunnel_manager, stream);
        co_return nullptr;
    }

    ack_payload ack_pl{};
    if (!mux_codec::decode_ack(ack_data.data(), ack_data.size(), ack_pl))
    {
        LOG_CTX_WARN(ctx, "{} ack invalid payload", log_event::kSocks);
        co_await close_and_remove_stream(tunnel_manager, stream);
        co_return nullptr;
    }
    if (ack_pl.socks_rep != socks::kRepSuccess)
    {
        LOG_CTX_WARN(ctx, "{} ack rejected {}", log_event::kSocks, ack_pl.socks_rep);
        co_await close_and_remove_stream(tunnel_manager, stream);
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

[[nodiscard]] bool is_tunnel_available(const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& tunnel_manager,
                                       const connection_context& ctx)
{
    if (tunnel_manager == nullptr || tunnel_manager->connection() == nullptr || !tunnel_manager->connection()->is_open())
    {
        LOG_CTX_WARN(ctx, "{} tunnel unavailable", log_event::kSocks);
        return false;
    }
    return true;
}

boost::asio::awaitable<bool> send_udp_associate_success_reply(boost::asio::ip::tcp::socket& socket,
                                                              const boost::asio::ip::address& local_addr,
                                                              const std::uint16_t udp_bind_port,
                                                              const connection_context& ctx,
                                                              const std::uint32_t timeout_sec)
{
    const auto final_rep = detail::build_udp_associate_reply(local_addr, udp_bind_port);
    const auto write_res = co_await timeout_io::async_write_with_timeout(socket, boost::asio::buffer(final_rep), timeout_sec, "udp socks session");
    if (!write_res.ok)
    {
        if (write_res.timed_out)
        {
            LOG_CTX_WARN(ctx, "{} write timeout {}s", log_event::kSocks, timeout_sec);
        }
        else
        {
            LOG_CTX_WARN(ctx, "{} write failed {}", log_event::kSocks, write_res.ec.message());
        }
        co_return false;
    }
    co_return true;
}

[[nodiscard]] bool validate_and_track_client_endpoint(const boost::asio::ip::udp::endpoint& sender,
                                                      boost::asio::ip::udp::endpoint& client_ep,
                                                      bool& has_client_ep,
                                                      const std::optional<boost::asio::ip::address>& expected_client_addr,
                                                      const std::optional<std::uint16_t>& expected_client_port,
                                                      const connection_context& ctx)
{
    const auto normalized_sender_addr = socks_codec::normalize_ip_address(sender.address());
    if (!has_client_ep)
    {
        if (expected_client_addr.has_value())
        {
            const auto normalized_expected = socks_codec::normalize_ip_address(*expected_client_addr);
            if (normalized_sender_addr != normalized_expected)
            {
                LOG_CTX_WARN(ctx,
                             "{} udp client endpoint mismatch expected addr {} got {}",
                             log_event::kSocks,
                             normalized_expected.to_string(),
                             normalized_sender_addr.to_string());
                return false;
            }
        }
        if (expected_client_port.has_value() && sender.port() != *expected_client_port)
        {
            LOG_CTX_WARN(
                ctx, "{} udp client endpoint mismatch expected port {} got {}", log_event::kSocks, *expected_client_port, sender.port());
            return false;
        }
        client_ep = boost::asio::ip::udp::endpoint(normalized_sender_addr, sender.port());
        has_client_ep = true;
        return true;
    }

    const auto normalized_client_addr = socks_codec::normalize_ip_address(client_ep.address());
    if (normalized_sender_addr != normalized_client_addr || sender.port() != client_ep.port())
    {
        LOG_CTX_WARN(ctx, "{} udp client endpoint mismatch ignore", log_event::kSocks);
        return false;
    }
    return true;
}

[[nodiscard]] bool validate_udp_client_packet(const std::vector<std::uint8_t>& buf,
                                              const std::size_t packet_len,
                                              const boost::asio::ip::udp::endpoint& sender,
                                              boost::asio::ip::udp::endpoint& client_ep,
                                              bool& has_client_ep,
                                              const std::optional<boost::asio::ip::address>& expected_client_addr,
                                              const std::optional<std::uint16_t>& expected_client_port,
                                              const connection_context& ctx)
{
    socks_udp_header udp_header;
    if (!socks_codec::decode_udp_header(buf.data(), packet_len, udp_header))
    {
        LOG_CTX_WARN(ctx, "{} received invalid udp packet from {}", log_event::kSocks, sender.address().to_string());
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

    return validate_and_track_client_endpoint(sender, client_ep, has_client_ep, expected_client_addr, expected_client_port, ctx);
}

[[nodiscard]] bool has_valid_client_endpoint(const bool has_client_ep, const boost::asio::ip::udp::endpoint& client_ep, const connection_context& ctx)
{
    if (!has_client_ep || client_ep.port() == 0)
    {
        LOG_CTX_WARN(ctx, "{} client ep port is 0 ignore it", log_event::kSocks);
        return false;
    }
    return true;
}

}    // namespace

udp_socks_session::udp_socks_session(boost::asio::ip::tcp::socket socket,
                                     boost::asio::io_context& io_context,
                                     std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager,
                                     const std::uint32_t sid,
                                     const config::timeout_t& timeout_cfg,
                                     std::shared_ptr<void> active_connection_guard,
                                     const std::size_t recv_channel_capacity)
    : io_context_(io_context),
      timer_(io_context_),
      idle_timer_(io_context_),
      socket_(std::move(socket)),
      udp_socket_(io_context_),
      tunnel_manager_(std::move(tunnel_manager)),
      recv_channel_(io_context_, recv_channel_capacity),
      active_connection_guard_(std::move(active_connection_guard)),
      timeout_config_(timeout_cfg)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
    last_activity_time_ms_.store(now_ms(), std::memory_order_release);
}

void udp_socks_session::start(const std::string& host, const std::uint16_t port)
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(
        io_context_, [self, host, port]() -> boost::asio::awaitable<void> { co_await self->run(host, port); }, boost::asio::detached);
}

void udp_socks_session::on_data(std::vector<std::uint8_t> data)
{
    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [self = shared_from_this(), data = std::move(data)]() mutable
                                           {
                                               if (!self->recv_channel_.try_send(boost::system::error_code(), std::move(data)))
                                               {
                                                   log_udp_recv_channel_unavailable_on_data(self->ctx_);
                                                   self->on_close();
                                               }
                                           });
}

void udp_socks_session::on_close()
{
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        return;
    }

    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   self->close_impl();
                                               }
                                           });
}

void udp_socks_session::close_impl()
{
    recv_channel_.close();
    timer_.cancel();
    idle_timer_.cancel();
    boost::system::error_code close_ec;
    close_ec = udp_socket_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_CTX_WARN(ctx_, "{} close udp socket failed {}", log_event::kSocks, close_ec.message());
    }
}

void udp_socks_session::apply_expected_client_constraint(const std::string& host, const std::uint16_t port)
{
    configure_expected_client_constraint(host, port, expected_client_addr_, expected_client_port_);
    if (expected_client_addr_.has_value())
    {
        return;
    }

    boost::system::error_code peer_ec;
    const auto peer_ep = socket_.remote_endpoint(peer_ec);
    if (peer_ec)
    {
        return;
    }

    const auto peer_addr = socks_codec::normalize_ip_address(peer_ep.address());
    if (peer_addr.is_unspecified())
    {
        return;
    }
    expected_client_addr_ = peer_addr;
}

boost::asio::awaitable<std::shared_ptr<mux_stream>> udp_socks_session::prepare_udp_associate(boost::asio::ip::address& local_addr,
                                                                                             std::uint16_t& udp_bind_port)
{
    if (closed_.load(std::memory_order_acquire))
    {
        co_return nullptr;
    }

    if (!bind_udp_socket_for_associate(socket_, udp_socket_, ctx_, local_addr, udp_bind_port))
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, ctx_, timeout_config_.write);
        on_close();
        co_return nullptr;
    }

    if (closed_.load(std::memory_order_acquire))
    {
        on_close();
        co_return nullptr;
    }

    if (!is_tunnel_available(tunnel_manager_, ctx_))
    {
        co_await write_socks_error_reply(socket_, socks::kRepHostUnreach, ctx_, timeout_config_.write);
        on_close();
        co_return nullptr;
    }

    const auto stream = co_await establish_udp_associate_stream(tunnel_manager_, ctx_, timeout_config_.connect);
    if (stream == nullptr)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, ctx_, timeout_config_.write);
        on_close();
        co_return nullptr;
    }

    if (closed_.load(std::memory_order_acquire))
    {
        co_await close_and_remove_stream(tunnel_manager_, stream);
        on_close();
        co_return nullptr;
    }

    if (!co_await send_udp_associate_success_reply(socket_, local_addr, udp_bind_port, ctx_, timeout_config_.write))
    {
        co_await close_and_remove_stream(tunnel_manager_, stream);
        on_close();
        co_return nullptr;
    }
    co_return stream;
}

boost::asio::awaitable<void> udp_socks_session::finalize_udp_associate(const std::shared_ptr<mux_stream>& stream)
{
    on_close();
    if (stream != nullptr)
    {
        co_await stream->close();
        tunnel_manager_->remove_stream(stream->id());
    }
}

bool udp_socks_session::should_stop_stream_to_udp(const boost::system::error_code& ec, const std::vector<std::uint8_t>& data) const
{
    if (!ec && !data.empty())
    {
        return false;
    }
    if (ec && !is_expected_channel_recv_error(ec))
    {
        LOG_CTX_ERROR(ctx_, "{} recv error {}", log_event::kSocks, ec.message());
    }
    else if (ec)
    {
        LOG_CTX_DEBUG(ctx_, "{} recv stopped {}", log_event::kSocks, ec.message());
    }
    return true;
}

boost::asio::awaitable<void> udp_socks_session::forward_stream_data_to_client(const std::vector<std::uint8_t>& data)
{
    if (!has_valid_client_endpoint(has_client_ep_, client_ep_, ctx_))
    {
        co_return;
    }
    const auto ep = client_ep_;
    const auto [send_ec, send_n] =
        co_await udp_socket_.async_send_to(boost::asio::buffer(data), ep, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    if (send_ec)
    {
        LOG_CTX_ERROR(ctx_, "{} send error {}", log_event::kSocks, send_ec.message());
        co_return;
    }
    last_activity_time_ms_.store(now_ms(), std::memory_order_release);
}

void udp_socks_session::on_reset() { on_close(); }

boost::asio::awaitable<void> udp_socks_session::run(const std::string& host, const std::uint16_t port)
{
    apply_expected_client_constraint(host, port);

    if (closed_.load(std::memory_order_acquire))
    {
        co_return;
    }

    boost::asio::ip::address local_addr;
    std::uint16_t udp_bind_port = 0;
    const auto stream = co_await prepare_udp_associate(local_addr, udp_bind_port);
    if (stream == nullptr)
    {
        co_return;
    }

    if (closed_.load(std::memory_order_acquire))
    {
        co_await finalize_udp_associate(stream);
        co_return;
    }

    if (!tunnel_manager_->register_stream(stream->id(), shared_from_this()))
    {
        LOG_CTX_ERROR(ctx_, "{} register stream failed {}", log_event::kSocks, stream->id());
        co_await finalize_udp_associate(stream);
        co_return;
    }

    using boost::asio::experimental::awaitable_operators::operator||;
    co_await (udp_sock_to_stream(stream) || stream_to_udp_sock(stream) || keep_tcp_alive() || idle_watchdog());

    co_await finalize_udp_associate(stream);
    LOG_CTX_INFO(ctx_, "{} finished", log_event::kSocks);
}

boost::asio::awaitable<void> udp_socks_session::udp_sock_to_stream(std::shared_ptr<mux_stream> stream)
{
    std::vector<std::uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    while (!closed_.load(std::memory_order_acquire))
    {
        const auto [recv_ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != boost::asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} receive error {}", log_event::kSocks, recv_ec.message());
            }
            break;
        }
        if (!validate_udp_client_packet(buf, n, sender, client_ep_, has_client_ep_, expected_client_addr_, expected_client_port_, ctx_))
        {
            continue;
        }

        const auto write_ec = co_await stream->async_write_some(buf.data(), n);
        if (write_ec)
        {
            if (write_ec == boost::asio::error::message_size)
            {
                LOG_CTX_WARN(ctx_, "{} drop oversized udp packet size {}", log_event::kSocks, n);
                continue;
            }
            LOG_CTX_ERROR(ctx_, "{} write to stream failed {}", log_event::kSocks, write_ec.message());
            break;
        }
        last_activity_time_ms_.store(now_ms(), std::memory_order_release);
    }
}

boost::asio::awaitable<void> udp_socks_session::stream_to_udp_sock(std::shared_ptr<mux_stream> stream)
{
    (void)stream;
    while (!closed_.load(std::memory_order_acquire))
    {
        const auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (should_stop_stream_to_udp(ec, data))
        {
            break;
        }
        co_await forward_stream_data_to_client(data);
    }
}

boost::asio::awaitable<void> udp_socks_session::keep_tcp_alive()
{
    for (;;)
    {
        char b[1];
        const auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec && n > 0)
        {
            continue;
        }
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
        else
        {
            LOG_CTX_DEBUG(ctx_, "{} keep tcp alive stopped", log_event::kSocks);
        }
        break;
    }
}

boost::asio::awaitable<void> udp_socks_session::idle_watchdog()
{
    if (timeout_config_.idle == 0)
    {
        co_return;
    }

    while (!closed_.load(std::memory_order_acquire))
    {
        idle_timer_.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await idle_timer_.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
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
