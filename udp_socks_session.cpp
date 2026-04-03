#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "protocol.h"
#include "constants.h"
#include "net_utils.h"
#include "mux_stream.h"
#include "scoped_exit.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "mux_connection.h"
#include "mux_session_utils.h"
#include "udp_socks_session.h"
#include "client_tunnel_pool.h"
namespace mux
{

namespace
{

struct proxy_udp_stream
{
    std::shared_ptr<mux_connection> tunnel;
    std::shared_ptr<mux_stream> stream;
};

boost::asio::awaitable<void> write_socks_error_reply(boost::asio::ip::tcp::socket& socket,
                                                     uint8_t rep,
                                                     uint32_t conn_id,
                                                     uint32_t timeout_sec)
{
    uint8_t err[] = {socks::kVer, rep, 0, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(err), timeout_sec, ec);
    if (ec)
    {
        const auto write_ec_message = ec.message();
        std::string local_host = "unknown";
        uint16_t local_port = 0;
        std::string remote_host = "unknown";
        uint16_t remote_port = 0;

        ec.clear();
        const auto local_ep = socket.local_endpoint(ec);
        if (!ec)
        {
            local_host = local_ep.address().to_string();
            local_port = local_ep.port();
        }
        ec.clear();
        const auto remote_ep = socket.remote_endpoint(ec);
        if (!ec)
        {
            remote_host = remote_ep.address().to_string();
            remote_port = remote_ep.port();
        }
        LOG_WARN("event {} conn_id {} local {}:{} remote {}:{} write error reply failed {}",
                 log_event::kSocks,
                 conn_id,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port,
                 write_ec_message);
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

void bind_local_udp_address(const boost::asio::ip::tcp::socket& tcp_socket,
                            boost::asio::ip::udp::socket& udp_socket,
                            uint32_t conn_id,
                            boost::asio::ip::address& local_addr,
                            uint16_t& udp_bind_port,
                            boost::system::error_code& ec)
{
    const auto tcp_local_ep = tcp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} stage query_tcp_local_endpoint error {}", log_event::kSocks, conn_id, ec.message());
        return;
    }

    local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    open_and_bind_udp_socket(udp_socket, local_addr, ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} tcp local {}:{} bind udp socket failed {}",
                  log_event::kSocks,
                  conn_id,
                  local_addr.to_string(),
                  tcp_local_ep.port(),
                  ec.message());
        return;
    }
    const auto udp_local_ep = udp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} tcp local {}:{} query udp endpoint failed {}",
                  log_event::kSocks,
                  conn_id,
                  local_addr.to_string(),
                  tcp_local_ep.port(),
                  ec.message());
        return;
    }
    udp_bind_port = udp_local_ep.port();
    LOG_INFO("event {} conn_id {} tcp local {}:{} udp associate bound {}:{}",
             log_event::kSocks,
             conn_id,
             local_addr.to_string(),
             tcp_local_ep.port(),
             local_addr.to_string(),
             udp_bind_port);
}

boost::asio::awaitable<proxy_udp_stream> connect_remote_address(const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                                uint32_t conn_id,
                                                                const std::string& target_host,
                                                                uint16_t target_port,
                                                                boost::system::error_code& ec)
{
    if (tunnel_pool == nullptr)
    {
        ec = boost::asio::error::not_connected;
        LOG_ERROR("event {} conn_id {} target {}:{} failed to create udp proxy stream no tunnel pool",
                  log_event::kSocks,
                  conn_id,
                  target_host,
                  target_port);
        co_return proxy_udp_stream{};
    }
    auto tunnel = tunnel_pool->select_tunnel();
    if (!tunnel)
    {
        ec = boost::asio::error::not_connected;
        LOG_ERROR("event {} conn_id {} target {}:{} wait tunnel failed active_tunnels {}",
                  log_event::kSocks,
                  conn_id,
                  target_host,
                  target_port,
                  tunnel_pool->active_tunnels());
        co_return proxy_udp_stream{};
    }

    auto stream = tunnel->create_stream();
    if (stream == nullptr)
    {
        ec = boost::asio::error::connection_aborted;
        LOG_ERROR("event {} conn_id {} target {}:{} failed to create udp proxy stream tunnel_ptr {}",
                  log_event::kSocks,
                  conn_id,
                  target_host,
                  target_port,
                  static_cast<const void*>(tunnel.get()));
        co_return proxy_udp_stream{};
    }
    bool keep_stream = false;
    DEFER(if (!keep_stream) { tunnel->close_and_remove_stream(stream); });

    const syn_payload syn{.socks_cmd = socks::kCmdUdpAssociate, .addr = "0.0.0.0", .port = 0};
    std::vector<uint8_t> syn_data;
    if (!mux_codec::encode_syn(syn, syn_data))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp syn encode failed",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port);
        co_return proxy_udp_stream{};
    }
    mux_frame syn_frame;
    syn_frame.h.stream_id = stream->id();
    syn_frame.h.command = kCmdSyn;
    syn_frame.payload.swap(syn_data);
    co_await stream->async_write(syn_frame, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp syn failed {}",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port,
                 ec.message());
        co_return proxy_udp_stream{};
    }

    auto ack_frame = co_await stream->async_read(ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp ack failed {}",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port,
                 ec.message());
        co_await session_util::send_stream_reset(stream, log_event::kSocks, conn_id, "read_udp_ack");
        co_return proxy_udp_stream{};
    }
    if (ack_frame.h.command != mux::kCmdAck)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp ack failed unexpected cmd {}",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port,
                 ack_frame.h.command);
        co_await session_util::send_stream_reset(stream, log_event::kSocks, conn_id, "unexpected_udp_ack_command");
        co_return proxy_udp_stream{};
    }

    ack_payload ack_pl{};
    if (!mux_codec::decode_ack(ack_frame.payload.data(), ack_frame.payload.size(), ack_pl))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp ack invalid payload",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port);
        co_await session_util::send_stream_reset(stream, log_event::kSocks, conn_id, "invalid_udp_ack_payload");
        co_return proxy_udp_stream{};
    }
    if (ack_pl.socks_rep != socks::kRepSuccess)
    {
        ec = boost::asio::error::connection_refused;
        LOG_WARN("event {} conn_id {} stream_id {} target {}:{} udp ack rejected rep {}",
                 log_event::kSocks,
                 conn_id,
                 stream->id(),
                 target_host,
                 target_port,
                 ack_pl.socks_rep);
        co_return proxy_udp_stream{};
    }

    keep_stream = true;
    co_return proxy_udp_stream{.tunnel = tunnel, .stream = stream};
}

}    // namespace

namespace detail
{

std::vector<uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, uint16_t udp_bind_port)
{
    std::vector<uint8_t> final_rep;
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

    final_rep.push_back(static_cast<uint8_t>((udp_bind_port >> 8) & 0xFF));
    final_rep.push_back(static_cast<uint8_t>(udp_bind_port & 0xFF));
    return final_rep;
}

}    // namespace detail

namespace
{

[[nodiscard]] bool decode_client_udp_header(const std::vector<uint8_t>& buf,
                                            std::size_t packet_len,
                                            socks_udp_header& udp_header,
                                            const boost::asio::ip::udp::endpoint& sender,
                                            const std::string& bind_host,
                                            uint16_t bind_port,
                                            uint32_t conn_id)
{
    if (!socks_codec::decode_udp_header(buf.data(), packet_len, udp_header))
    {
        LOG_WARN("event {} conn_id {} peer {}:{} bind {}:{} received invalid udp packet",
                 log_event::kSocks,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port);
        return false;
    }

    if (udp_header.frag != 0x00)
    {
        LOG_WARN("event {} conn_id {} peer {}:{} bind {}:{} received fragmented udp packet frag {}",
                 log_event::kSocks,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port,
                 udp_header.frag);
        return false;
    }
    if (udp_header.addr.empty())
    {
        LOG_WARN("event {} conn_id {} peer {}:{} bind {}:{} received udp packet with empty target host",
                 log_event::kSocks,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port);
        return false;
    }
    if (udp_header.port == 0)
    {
        LOG_WARN("event {} conn_id {} peer {}:{} bind {}:{} received udp packet with invalid target port 0",
                 log_event::kSocks,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port);
        return false;
    }

    return true;
}

}    // namespace

udp_socks_session::udp_socks_session(boost::asio::ip::tcp::socket socket,
                                     io_worker& worker,
                                     std::shared_ptr<client_tunnel_pool> tunnel_pool,
                                     std::shared_ptr<router> router,
                                     uint32_t sid,
                                     const config& cfg,
                                     std::shared_ptr<void> active_connection_guard)
    : conn_id_(sid),
      cfg_(cfg),
      worker_(worker),
      timer_(worker.io_context),
      idle_timer_(worker.io_context),
      socket_(std::move(socket)),
      udp_socket_(worker.io_context),
      direct_udp_socket_v4_(worker.io_context),
      direct_udp_socket_v6_(worker.io_context),
      router_(std::move(router)),
      tunnel_pool_(std::move(tunnel_pool)),
      resolved_targets_(constants::udp::kMaxCacheEntries),
      direct_peers_(constants::udp::kMaxCacheEntries),
      active_connection_guard_(std::move(active_connection_guard)),
      proxy_stream_channel_(worker.io_context, 1)
{
    stream_close_command_.store(mux::kCmdFin, std::memory_order_relaxed);
    last_activity_time_ms_ = net::now_ms();
}

void udp_socks_session::start(const std::string& host, uint16_t port)
{
    worker_.group.spawn([self = shared_from_this(), host, port]() -> boost::asio::awaitable<void> { co_await self->run(host, port); });
}

void udp_socks_session::close_impl()
{
    if (stopped_)
    {
        return;
    }
    stopped_ = true;
    timer_.cancel();
    idle_timer_.cancel();
    proxy_stream_channel_.close();
    boost::system::error_code tcp_close_ec;
    tcp_close_ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, tcp_close_ec);
    tcp_close_ec = socket_.close(tcp_close_ec);
    (void)tcp_close_ec;
    boost::system::error_code close_ec;
    close_ec = udp_socket_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} close udp socket failed {}",
                 log_event::kSocks,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 close_ec.message());
    }
    close_ec = direct_udp_socket_v4_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} close direct udp v4 socket failed {}",
                 log_event::kSocks,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 close_ec.message());
    }
    close_ec = direct_udp_socket_v6_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} close direct udp v6 socket failed {}",
                 log_event::kSocks,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 close_ec.message());
    }
}

boost::asio::awaitable<void> udp_socks_session::run(const std::string& host, uint16_t port)
{
    apply_request_peer_constraint(host, port);
    boost::system::error_code ec;
    uint16_t udp_port = 0;
    boost::asio::ip::address local_addr;
    // step 1 bind local upd address
    bind_local_udp_address(socket_, udp_socket_, conn_id_, local_addr, udp_port, ec);
    if (ec)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, conn_id_, cfg_.timeout.write);
        co_return;
    }
    udp_bind_host_ = local_addr.to_string();
    udp_bind_port_ = udp_port;
    const auto tcp_remote_ep = socket_.remote_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("event {} conn_id {} bind {}:{} get tcp peer failed {}",
                  log_event::kSocks,
                  conn_id_,
                  udp_bind_host_,
                  udp_bind_port_,
                  ec.message());
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, conn_id_, cfg_.timeout.write);
        co_return;
    }
    client_ip_ = net::normalize_address(tcp_remote_ep.address());
    has_client_ip_ = true;
    tcp_peer_host_ = client_ip_.to_string();
    tcp_peer_port_ = tcp_remote_ep.port();
    LOG_INFO("event {} conn_id {} tcp peer {}:{} udp bind {}:{}",
             log_event::kConnInit,
             conn_id_,
             tcp_peer_host_,
             tcp_peer_port_,
             udp_bind_host_,
             udp_bind_port_);
    // step 2 reply to tcp socket
    const auto final_rep = detail::build_udp_associate_reply(local_addr, udp_port);
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(final_rep), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} write udp associate reply failed {}",
                 log_event::kSocks,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 ec.message());
        co_return;
    }
    boost::system::error_code direct_socket_ec;
    open_direct_udp_socket(direct_udp_socket_v4_, boost::asio::ip::udp::v4(), "v4", direct_socket_ec);
    open_direct_udp_socket(direct_udp_socket_v6_, boost::asio::ip::udp::v6(), "v6", direct_socket_ec);
    start_direct_udp_socket_loops();
    // step 3 forward data
    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (udp_socket_loop() || wait_and_stream_to_udp_sock() || keep_tcp_alive());
    }
    else
    {
        co_await (udp_socket_loop() || wait_and_stream_to_udp_sock() || keep_tcp_alive() || idle_watchdog());
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
            LOG_WARN("event {} conn_id {} stream_id {} send {} failed {}",
                     log_event::kSocks,
                     conn_id_,
                     stream_->id(),
                     close_command == mux::kCmdRst ? "rst" : "fin",
                     close_ec.message());
        }
    }
    if (tunnel_ != nullptr && stream_ != nullptr)
    {
        tunnel_->close_and_remove_stream(stream_);
    }
    close_impl();
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    LOG_INFO("event {} conn_id {} tcp peer {}:{} udp bind {}:{} client {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             conn_id_,
             tcp_peer_host_,
             tcp_peer_port_,
             udp_bind_host_,
             udp_bind_port_,
             current_client_host(),
             current_client_port(),
             tx_bytes_,
             rx_bytes_,
             duration_ms);
}

void udp_socks_session::apply_request_peer_constraint(const std::string& host, uint16_t port) const
{
    if (!host.empty() || port != 0)
    {
        std::string local_host = "unknown";
        uint16_t local_port = 0;
        std::string remote_host = "unknown";
        uint16_t remote_port = 0;
        boost::system::error_code ec;
        const auto local_ep = socket_.local_endpoint(ec);
        if (!ec)
        {
            local_host = local_ep.address().to_string();
            local_port = local_ep.port();
        }
        ec.clear();
        const auto remote_ep = socket_.remote_endpoint(ec);
        if (!ec)
        {
            remote_host = remote_ep.address().to_string();
            remote_port = remote_ep.port();
        }
        LOG_INFO("event {} conn_id {} local {}:{} remote {}:{} udp associate request peer ignored host {} port {}",
                 log_event::kSocks,
                 conn_id_,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port,
                 host,
                 port);
    }
}

std::string udp_socks_session::current_client_host() const
{
    if (has_client_addr_)
    {
        return client_addr_.address().to_string();
    }
    if (has_client_ip_)
    {
        return client_ip_.to_string();
    }
    return tcp_peer_host_;
}

uint16_t udp_socks_session::current_client_port() const
{
    if (has_client_addr_)
    {
        return client_addr_.port();
    }
    return tcp_peer_port_;
}

void udp_socks_session::open_direct_udp_socket(boost::asio::ip::udp::socket& direct_socket,
                                               const boost::asio::ip::udp& protocol,
                                               const char* family,
                                               boost::system::error_code& ec) const
{
    ec = direct_socket.open(protocol, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} open direct udp {} socket failed {}",
                 log_event::kRoute,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 family,
                 ec.message());
        return;
    }
    const auto connect_mark = cfg_.tproxy.enabled ? cfg_.tproxy.mark : 0U;
    if (connect_mark != 0)
    {
        net::set_socket_mark(direct_socket.native_handle(), connect_mark, ec);
        if (ec)
        {
            LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} set direct udp {} mark failed {}",
                     log_event::kRoute,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     family,
                     ec.message());
            boost::system::error_code close_ec;
            close_ec = direct_socket.close(close_ec);
            (void)close_ec;
            return;
        }
    }
    ec = direct_socket.bind(boost::asio::ip::udp::endpoint(protocol, 0), ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} bind direct udp {} socket failed {}",
                 log_event::kRoute,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 family,
                 ec.message());
        boost::system::error_code close_ec;
        close_ec = direct_socket.close(close_ec);
        (void)close_ec;
        return;
    }
}

boost::asio::ip::udp::socket* udp_socks_session::select_direct_udp_socket(const boost::asio::ip::udp::endpoint& target)
{
    if (target.address().is_v6())
    {
        if (!direct_udp_socket_v6_.is_open())
        {
            boost::system::error_code direct_socket_ec;
            open_direct_udp_socket(direct_udp_socket_v6_, boost::asio::ip::udp::v6(), "v6", direct_socket_ec);
            if (direct_udp_socket_v6_.is_open())
            {
                start_direct_udp_socket_loops();
            }
        }
        if (!direct_udp_socket_v6_.is_open())
        {
            return nullptr;
        }
        return &direct_udp_socket_v6_;
    }
    if (!direct_udp_socket_v4_.is_open())
    {
        boost::system::error_code direct_socket_ec;
        open_direct_udp_socket(direct_udp_socket_v4_, boost::asio::ip::udp::v4(), "v4", direct_socket_ec);
        if (direct_udp_socket_v4_.is_open())
        {
            start_direct_udp_socket_loops();
        }
    }
    if (!direct_udp_socket_v4_.is_open())
    {
        return nullptr;
    }
    return &direct_udp_socket_v4_;
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
        co_return co_await router_->decide_domain(header.addr);
    }
    co_return co_await router_->decide_ip(socks_codec::normalize_ip_address(addr));
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> udp_socks_session::resolve_target_endpoint(const std::string& host,
                                                                                                  uint16_t port,
                                                                                                  boost::system::error_code& ec)
{
    const auto key = session_util::udp_target_key(host, port);
    const auto now_ms_value = net::now_ms();
    resolved_targets_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms_value; });

    auto* cached = resolved_targets_.get(key);
    if (cached != nullptr)
    {
        if (cached->expires_at <= now_ms_value)
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
            cached->expires_at = now_ms_value + constants::udp::kCacheTtlMs;
            co_return cached->endpoint;
        }
    }

    boost::asio::ip::udp::resolver resolver(worker_.io_context);
    auto endpoints = co_await net::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct resolve failed {}:{} error {}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 host,
                 port,
                 ec.message());
        resolved_targets_.put(key,
                              endpoint_cache_entry{
                                  .endpoint = {},
                                  .expires_at = now_ms_value + constants::udp::kNegativeCacheTtlMs,
                                  .last_error = ec,
                                  .negative = true,
                              });
        co_return boost::asio::ip::udp::endpoint{};
    }
    if (endpoints.begin() == endpoints.end())
    {
        ec = boost::asio::error::host_not_found;
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct resolve empty {}:{}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 host,
                 port);
        resolved_targets_.put(key,
                              endpoint_cache_entry{
                                  .endpoint = {},
                                  .expires_at = now_ms_value + constants::udp::kNegativeCacheTtlMs,
                                  .last_error = ec,
                                  .negative = true,
                              });
        co_return boost::asio::ip::udp::endpoint{};
    }

    boost::asio::ip::udp::endpoint target;
    bool found = false;
    for (const auto& endpoint : endpoints)
    {
        const auto normalized = net::normalize_endpoint(endpoint.endpoint());
        if (select_direct_udp_socket(normalized) == nullptr)
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
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct resolve no compatible endpoint {}:{}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 host,
                 port);
        resolved_targets_.put(key,
                              endpoint_cache_entry{
                                  .endpoint = {},
                                  .expires_at = now_ms_value + constants::udp::kNegativeCacheTtlMs,
                                  .last_error = ec,
                                  .negative = true,
                              });
        co_return boost::asio::ip::udp::endpoint{};
    }
    const auto expires_at = now_ms_value + constants::udp::kCacheTtlMs;
    resolved_targets_.put(key, endpoint_cache_entry{.endpoint = target, .expires_at = expires_at, .last_error = {}, .negative = false});
    co_return target;
}

boost::asio::awaitable<void> udp_socks_session::forward_direct_packet(const socks_udp_header& header,
                                                                      const uint8_t* payload,
                                                                      std::size_t payload_len,
                                                                      boost::system::error_code& ec)
{
    const auto target = co_await resolve_target_endpoint(header.addr, header.port, ec);
    if (ec)
    {
        if (!session_util::is_normal_close_error(ec))
        {
            ec.clear();
        }
        co_return;
    }
    auto* direct_socket = select_direct_udp_socket(target);
    if (direct_socket == nullptr)
    {
        const auto direct_socket_ec = boost::system::error_code(boost::asio::error::address_family_not_supported);
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct socket unavailable {}:{} error {}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 target.address().to_string(),
                 target.port(),
                 direct_socket_ec.message());
        co_return;
    }
    const auto [send_ec, send_n] =
        co_await direct_socket->async_send_to(boost::asio::buffer(payload, payload_len), target, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    if (send_ec)
    {
        if (session_util::is_normal_close_error(send_ec))
        {
            ec = send_ec;
        }
        else
        {
            LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct send failed {}:{} error {}",
                     log_event::kRoute,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     target.address().to_string(),
                     target.port(),
                     send_ec.message());
        }
        co_return;
    }

    const auto normalized_target = net::normalize_endpoint(target);
    const auto now_ms_value = net::now_ms();
    const auto expires_at = now_ms_value + constants::udp::kCacheTtlMs;
    direct_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms_value; });
    direct_peers_.put(normalized_target, peer_cache_entry{expires_at});
    tx_bytes_ += payload_len;
    last_activity_time_ms_ = now_ms_value;
}

boost::asio::awaitable<void> udp_socks_session::direct_udp_socket_loop(boost::asio::ip::udp::socket& direct_socket)
{
    std::vector<uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    boost::system::error_code ec;
    while (true)
    {
        const auto n =
            co_await direct_socket.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (!session_util::is_normal_close_error(ec))
            {
                LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} direct udp receive error {}",
                         log_event::kRoute,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         ec.message());
                ec = direct_socket.close(ec);
                (void)ec;
            }
            break;
        }
        const auto now_ms_value = net::now_ms();
        direct_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms_value; });
        const auto normalized_sender = net::normalize_endpoint(sender);
        auto* peer = direct_peers_.get(normalized_sender);
        if (peer == nullptr || peer->expires_at <= now_ms_value)
        {
            if (peer != nullptr && peer->expires_at <= now_ms_value)
            {
                direct_peers_.erase(normalized_sender);
            }
            LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} ignore udp packet from unexpected direct peer {}:{}",
                     log_event::kRoute,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     sender.address().to_string(),
                     sender.port());
            continue;
        }

        co_await forward_direct_reply_to_client(sender, buf.data(), n, ec);
        if (ec)
        {
            if (!session_util::is_normal_close_error(ec))
            {
                ec = direct_socket.close(ec);
                (void)ec;
            }
            break;
        }
        last_activity_time_ms_ = net::now_ms();
    }
}

void udp_socks_session::start_direct_udp_socket_loops()
{
    const auto self = shared_from_this();
    if (direct_udp_socket_v4_.is_open())
    {
        if (!direct_udp_v4_running_)
        {
            direct_udp_v4_running_ = true;
            worker_.group.spawn(
                [self]() -> boost::asio::awaitable<void>
                {
                    co_await self->direct_udp_socket_loop(self->direct_udp_socket_v4_);
                    self->direct_udp_v4_running_ = false;
                });
        }
    }
    if (direct_udp_socket_v6_.is_open())
    {
        if (!direct_udp_v6_running_)
        {
            direct_udp_v6_running_ = true;
            worker_.group.spawn(
                [self]() -> boost::asio::awaitable<void>
                {
                    co_await self->direct_udp_socket_loop(self->direct_udp_socket_v6_);
                    self->direct_udp_v6_running_ = false;
                });
        }
    }
}

boost::asio::awaitable<void> udp_socks_session::forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                               const uint8_t* payload,
                                                                               std::size_t payload_len,
                                                                               boost::system::error_code& ec)
{
    if (!has_client_addr_)
    {
        co_return;
    }

    const auto normalized_sender = net::normalize_endpoint(sender);
    const socks_udp_header header{.frag = 0, .addr = normalized_sender.address().to_string(), .port = normalized_sender.port()};
    const auto udp_header = socks_codec::encode_udp_header(header);
    const auto packet_len = udp_header.size() + payload_len;
    if (packet_len > constants::udp::kMaxPayload)
    {
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp reply oversized drop size {} max {}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 packet_len,
                 constants::udp::kMaxPayload);
        co_return;
    }

    std::vector<uint8_t> packet;
    packet.reserve(packet_len);
    packet.insert(packet.end(), udp_header.begin(), udp_header.end());
    packet.insert(packet.end(), payload, payload + payload_len);

    const auto [send_ec, send_n] =
        co_await udp_socket_.async_send_to(boost::asio::buffer(packet), client_addr_, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    ec = send_ec;
    if (ec)
    {
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp direct reply failed {}:{} error {}",
                 log_event::kRoute,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 client_addr_.address().to_string(),
                 client_addr_.port(),
                 ec.message());
        co_return;
    }
    rx_bytes_ += packet_len;
}

boost::asio::awaitable<bool> udp_socks_session::ensure_proxy_stream(boost::system::error_code& ec)
{
    if (stream_ != nullptr && tunnel_ != nullptr)
    {
        co_return true;
    }

    const auto proxy_stream = co_await connect_remote_address(tunnel_pool_,
                                                              conn_id_,
                                                              has_last_target_ ? last_target_addr_ : "unknown",
                                                              has_last_target_ ? last_target_port_ : 0,
                                                              ec);
    if (ec || proxy_stream.stream == nullptr || proxy_stream.tunnel == nullptr)
    {
        if (!ec)
        {
            ec = boost::asio::error::not_connected;
        }
        LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} target {}:{} connect proxy udp stream failed {}",
                 log_event::kSocks,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 has_last_target_ ? last_target_addr_ : "unknown",
                 has_last_target_ ? last_target_port_ : 0,
                 ec.message());
        co_return false;
    }

    tunnel_ = proxy_stream.tunnel;
    stream_ = proxy_stream.stream;
    LOG_INFO("event {} conn_id {} client {}:{} udp bind {}:{} target {}:{} proxy udp stream ready stream_id {} tunnel_ptr {}",
             log_event::kSocks,
             conn_id_,
             current_client_host(),
             current_client_port(),
             udp_bind_host_,
             udp_bind_port_,
             has_last_target_ ? last_target_addr_ : "unknown",
             has_last_target_ ? last_target_port_ : 0,
             stream_->id(),
             static_cast<const void*>(tunnel_.get()));
    if (!proxy_stream_started_)
    {
        const auto [send_ec] =
            co_await proxy_stream_channel_.async_send(boost::system::error_code{}, stream_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (send_ec)
        {
            ec = send_ec;
            LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} target {}:{} start proxy udp reader failed {}",
                     log_event::kSocks,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     has_last_target_ ? last_target_addr_ : "unknown",
                     has_last_target_ ? last_target_port_ : 0,
                     ec.message());
            tunnel_->close_and_remove_stream(stream_);
            stream_.reset();
            tunnel_.reset();
            co_return false;
        }
        proxy_stream_started_ = true;
    }
    co_return true;
}

void udp_socks_session::clear_proxy_stream_if_current(const std::shared_ptr<mux_stream>& stream)
{
    if (stream == nullptr || stream_ != stream)
    {
        return;
    }

    if (tunnel_ != nullptr)
    {
        tunnel_->close_and_remove_stream(stream_);
    }
    stream_.reset();
    tunnel_.reset();
    proxy_stream_started_ = false;
}

boost::asio::awaitable<void> udp_socks_session::udp_socket_loop()
{
    std::vector<uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    while (true)
    {
        const auto [recv_ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            if (!stopped_ && !session_util::is_normal_close_error(recv_ec))
            {
                LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} receive error {}",
                         log_event::kSocks,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         recv_ec.message());
            }
            break;
        }
        const auto normalized_sender = net::normalize_endpoint(sender);
        if (has_client_ip_ && normalized_sender.address() != client_ip_)
        {
            LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} ignore udp packet from unexpected peer {} expected {}",
                     log_event::kSocks,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     normalized_sender.address().to_string(),
                     client_ip_.to_string());
            continue;
        }
        if (has_client_addr_ && normalized_sender != client_addr_)
        {
            LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} ignore udp packet from unexpected peer {}:{} expected {}:{}",
                     log_event::kSocks,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     normalized_sender.address().to_string(),
                     normalized_sender.port(),
                     client_addr_.address().to_string(),
                     client_addr_.port());
            continue;
        }
        if (!has_client_addr_)
        {
            client_addr_ = normalized_sender;
            has_client_addr_ = true;
            LOG_INFO("event {} conn_id {} tcp peer {}:{} udp bind {}:{} udp peer bound to {}:{}",
                     log_event::kSocks,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     client_addr_.address().to_string(),
                     client_addr_.port());
        }

        socks_udp_header udp_header;
        if (!decode_client_udp_header(buf, n, udp_header, normalized_sender, udp_bind_host_, udp_bind_port_, conn_id_))
        {
            continue;
        }
        last_target_addr_ = udp_header.addr;
        last_target_port_ = udp_header.port;
        has_last_target_ = true;

        const auto route = co_await decide_udp_route(udp_header);
        if (route == route_type::kBlock)
        {
            LOG_INFO("event {} conn_id {} client {}:{} udp bind {}:{} udp blocked {}:{}",
                     log_event::kRoute,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     udp_header.addr,
                     udp_header.port);
            continue;
        }

        const auto payload_len = n - udp_header.header_len;
        if (route == route_type::kProxy)
        {
            if (n > mux::kMaxPayload)
            {
                LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} udp packet too large for mux frame {}",
                         log_event::kSocks,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         n);
                continue;
            }
            boost::system::error_code open_ec;
            const auto ready = co_await ensure_proxy_stream(open_ec);
            if (!ready)
            {
                session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
                break;
            }

            const auto stream = stream_;
            mux_frame data_frame;
            data_frame.h.stream_id = stream->id();
            data_frame.h.command = mux::kCmdDat;
            data_frame.payload.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
            boost::system::error_code write_ec;
            co_await stream->async_write(data_frame, write_ec);
            if (write_ec)
            {
                session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
                clear_proxy_stream_if_current(stream);
                LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} stream_id {} write to stream failed {}",
                         log_event::kSocks,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         stream->id(),
                         write_ec.message());
                continue;
            }
            tx_bytes_ += n;
            last_activity_time_ms_ = net::now_ms();
            continue;
        }

        boost::system::error_code ec;
        co_await forward_direct_packet(udp_header, buf.data() + udp_header.header_len, payload_len, ec);
        if (ec)
        {
            break;
        }
    }
}

boost::asio::awaitable<void> udp_socks_session::wait_and_stream_to_udp_sock()
{
    while (true)
    {
        auto [read_ec, stream] = co_await proxy_stream_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (read_ec)
        {
            co_return;
        }
        if (stream == nullptr)
        {
            continue;
        }

        co_await stream_to_udp_sock(stream);
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
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            clear_proxy_stream_if_current(stream);
            break;
        }
        if (data_frame.h.command == mux::kCmdRst || data_frame.h.command == mux::kCmdFin)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kNoStreamControl);
            clear_proxy_stream_if_current(stream);
            LOG_INFO("event {} conn_id {} client {}:{} udp bind {}:{} stream_id {} recv control cmd {} closing",
                     log_event::kSocks,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     stream->id(),
                     data_frame.h.command);
            break;
        }
        if (data_frame.h.command != mux::kCmdDat)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} stream_id {} recv unexpected cmd {} dropping session",
                     log_event::kSocks,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     stream->id(),
                     data_frame.h.command);
            close_impl();
            co_return;
        }
        if (!has_client_addr_)
        {
            continue;
        }

        if (data_frame.payload.size() > constants::udp::kMaxPayload)
        {
            LOG_WARN("event {} conn_id {} client {}:{} udp bind {}:{} stream_id {} udp reply oversized drop size {} max {}",
                     log_event::kSocks,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     stream->id(),
                     data_frame.payload.size(),
                     constants::udp::kMaxPayload);
            continue;
        }

        const auto [send_ec, send_n] = co_await udp_socket_.async_send_to(
            boost::asio::buffer(data_frame.payload), client_addr_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (send_ec)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_ERROR("event {} conn_id {} client {}:{} udp bind {}:{} stream_id {} send error {}",
                      log_event::kSocks,
                      conn_id_,
                      current_client_host(),
                      current_client_port(),
                      udp_bind_host_,
                      udp_bind_port_,
                      stream->id(),
                      send_ec.message());
            close_impl();
            co_return;
        }
        rx_bytes_ += send_n;
        last_activity_time_ms_ = net::now_ms();
    }
}

boost::asio::awaitable<void> udp_socks_session::keep_tcp_alive()
{
    std::array<char, constants::udp::kTcpControlReadBufferSize> buf{};
    std::size_t ignored_bytes = 0;
    for (;;)
    {
        const auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                LOG_INFO("event {} conn_id {} tcp peer {}:{} udp bind {}:{} client {}:{} tcp control channel closed eof",
                         log_event::kConnClose,
                         conn_id_,
                         tcp_peer_host_,
                         tcp_peer_port_,
                         udp_bind_host_,
                         udp_bind_port_,
                         current_client_host(),
                         current_client_port());
            }
            else if (ec != boost::asio::error::operation_aborted)
            {
                LOG_ERROR("event {} conn_id {} tcp peer {}:{} udp bind {}:{} client {}:{} keep tcp alive error {}",
                          log_event::kSocks,
                          conn_id_,
                          tcp_peer_host_,
                          tcp_peer_port_,
                          udp_bind_host_,
                          udp_bind_port_,
                          current_client_host(),
                          current_client_port(),
                          ec.message());
            }
            break;
        }
        if (n == 0)
        {
            continue;
        }
        ignored_bytes += n;
        if (ignored_bytes >= constants::udp::kTcpControlIgnoreLimitBytes)
        {
            session_util::update_stream_close_command(stream_close_command_, mux::kCmdRst);
            LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} client {}:{} tcp control channel flooded ignored_bytes {}",
                     log_event::kSocks,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     current_client_host(),
                     current_client_port(),
                     ignored_bytes);
            close_impl();
            co_return;
        }
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
        const auto elapsed_ms = net::now_ms() - last_activity_time_ms_;
        const auto idle_timeout_ms = static_cast<uint64_t>(cfg_.timeout.idle) * 1000ULL;
        if (elapsed_ms > idle_timeout_ms)
        {
            LOG_WARN("event {} conn_id {} tcp peer {}:{} udp bind {}:{} client {}:{} last_target {}:{} udp session idle closing",
                     log_event::kSocks,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     current_client_host(),
                     current_client_port(),
                     has_last_target_ ? last_target_addr_ : "unknown",
                     has_last_target_ ? last_target_port_ : 0);
            break;
        }
    }
}

}    // namespace mux
