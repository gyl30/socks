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
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "config.h"
#include "outbound.h"
#include "router.h"
#include "protocol.h"
#include "trace_store.h"
#include "constants.h"
#include "datagram_relay.h"
#include "net_utils.h"
#include "context_pool.h"
#include "request_context.h"
#include "socks_udp_session.h"
#include "udp_session_flow.h"

namespace relay
{

namespace detail
{

std::vector<uint8_t> build_udp_associate_reply(const boost::asio::ip::address& local_addr, const uint16_t udp_bind_port)
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

[[nodiscard]] std::string udp_target_key(const std::string& host, const uint16_t port) { return host + "|" + std::to_string(port); }

boost::asio::awaitable<void> write_socks_error_reply(
    boost::asio::ip::tcp::socket& socket, const uint8_t rep, const uint64_t trace_id, const uint32_t conn_id, const uint32_t timeout_sec)
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
        LOG_WARN("{} trace {:016x} conn {} local {}:{} remote {}:{} write error reply failed {}",
                 log_event::kSocks,
                 trace_id,
                 conn_id,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port,
                 write_ec_message);
    }
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
}

void bind_local_udp_address(const boost::asio::ip::tcp::socket& tcp_socket,
                            boost::asio::ip::udp::socket& udp_socket,
                            const uint64_t trace_id,
                            const uint32_t conn_id,
                            boost::asio::ip::address& local_addr,
                            uint16_t& udp_bind_port,
                            boost::system::error_code& ec)
{
    const auto tcp_local_ep = tcp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} stage query_tcp_local_endpoint error {}", log_event::kSocks, trace_id, conn_id, ec.message());
        return;
    }

    local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    open_and_bind_udp_socket(udp_socket, local_addr, ec);
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} tcp local {}:{} bind udp socket failed {}",
                  log_event::kSocks,
                  trace_id,
                  conn_id,
                  local_addr.to_string(),
                  tcp_local_ep.port(),
                  ec.message());
        return;
    }
    const auto udp_local_ep = udp_socket.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} tcp local {}:{} query udp endpoint failed {}",
                  log_event::kSocks,
                  trace_id,
                  conn_id,
                  local_addr.to_string(),
                  tcp_local_ep.port(),
                  ec.message());
        return;
    }
    udp_bind_port = udp_local_ep.port();
    LOG_INFO("{} trace {:016x} conn {} tcp local {}:{} udp associate bound {}:{}",
             log_event::kSocks,
             trace_id,
             conn_id,
             local_addr.to_string(),
             tcp_local_ep.port(),
             local_addr.to_string(),
             udp_bind_port);
}

[[nodiscard]] bool decode_client_udp_header(const std::vector<uint8_t>& buf,
                                            const std::size_t packet_len,
                                            socks_udp_header& udp_header,
                                            const uint64_t trace_id,
                                            const boost::asio::ip::udp::endpoint& sender,
                                            const std::string& bind_host,
                                            const uint16_t bind_port,
                                            const uint32_t conn_id)
{
    if (!socks_codec::decode_udp_header(buf.data(), packet_len, udp_header))
    {
        LOG_WARN("{} trace {:016x} conn {} peer {}:{} bind {}:{} received invalid udp packet",
                 log_event::kSocks,
                 trace_id,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port);
        return false;
    }

    if (udp_header.frag != 0x00)
    {
        LOG_WARN("{} trace {:016x} conn {} peer {}:{} bind {}:{} received fragmented udp packet frag {}",
                 log_event::kSocks,
                 trace_id,
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
        LOG_WARN("{} trace {:016x} conn {} peer {}:{} bind {}:{} received udp packet with empty target host",
                 log_event::kSocks,
                 trace_id,
                 conn_id,
                 sender.address().to_string(),
                 sender.port(),
                 bind_host,
                 bind_port);
        return false;
    }
    if (udp_header.port == 0)
    {
        LOG_WARN("{} trace {:016x} conn {} peer {}:{} bind {}:{} received udp packet with invalid target port 0",
                 log_event::kSocks,
                 trace_id,
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

socks_udp_session::socks_udp_session(boost::asio::ip::tcp::socket socket,
                                                         io_worker& worker,
                                                         std::shared_ptr<router> router,
                                                         const uint32_t sid,
                                                         const uint64_t trace_id,
                                                         std::string inbound_tag,
                                                         const config& cfg)
    : trace_id_(trace_id),
      conn_id_(sid),
      inbound_tag_(std::move(inbound_tag)),
      cfg_(cfg),
      worker_(worker),
      timer_(worker.io_context),
      idle_timer_(worker.io_context),
      socket_(std::move(socket)),
      udp_socket_(worker.io_context),
      direct_udp_socket_v4_(worker.io_context),
      direct_udp_socket_v6_(worker.io_context),
      router_(std::move(router)),
      resolved_targets_(constants::udp::kMaxCacheEntries),
      direct_peers_(constants::udp::kMaxCacheEntries),
      proxy_outbound_channel_(worker.io_context, 1)
{
    last_activity_time_ms_ = net::now_ms();
}

void socks_udp_session::start(const std::string& host, const uint16_t port)
{
    worker_.group.spawn([self = shared_from_this(), host, port]() -> boost::asio::awaitable<void> { co_await self->run(host, port); });
}

void socks_udp_session::close_impl()
{
    if (stopped_)
    {
        return;
    }

    stopped_ = true;
    timer_.cancel();
    idle_timer_.cancel();
    proxy_outbound_channel_.close();
    if (proxy_outbound_ != nullptr)
    {
        worker_.group.spawn([outbound = proxy_outbound_]() -> boost::asio::awaitable<void> { co_await outbound->close(); });
        proxy_outbound_.reset();
        proxy_outbound_started_ = false;
    }

    boost::system::error_code tcp_close_ec;
    tcp_close_ec = socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, tcp_close_ec);
    tcp_close_ec = socket_.close(tcp_close_ec);
    (void)tcp_close_ec;

    boost::system::error_code close_ec;
    close_ec = udp_socket_.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} close udp socket failed {}",
                 log_event::kSocks,
                 trace_id_,
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
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} close direct udp v4 socket failed {}",
                 log_event::kSocks,
                 trace_id_,
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
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} close direct udp v6 socket failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 close_ec.message());
    }
}

boost::asio::awaitable<bool> socks_udp_session::send_udp_associate_reply(const boost::asio::ip::address& local_addr, const uint16_t udp_port)
{
    const auto reply = detail::build_udp_associate_reply(local_addr, udp_port);
    boost::system::error_code ec;
    co_await net::wait_write_with_timeout(socket_, boost::asio::buffer(reply), cfg_.timeout.write, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} write udp associate reply failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 ec.message());
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> socks_udp_session::prepare_udp_associate(const std::string& host, const uint16_t port)
{
    apply_request_peer_constraint(host, port);

    boost::system::error_code ec;
    uint16_t udp_port = 0;
    boost::asio::ip::address local_addr;
    bind_local_udp_address(socket_, udp_socket_, trace_id_, conn_id_, local_addr, udp_port, ec);
    if (ec)
    {
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, trace_id_, conn_id_, cfg_.timeout.write);
        co_return false;
    }

    udp_bind_host_ = local_addr.to_string();
    udp_bind_port_ = udp_port;
    const auto tcp_remote_ep = socket_.remote_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} bind {}:{} get tcp peer failed {}",
                  log_event::kSocks,
                  trace_id_,
                  conn_id_,
                  udp_bind_host_,
                  udp_bind_port_,
                  ec.message());
        co_await write_socks_error_reply(socket_, socks::kRepGenFail, trace_id_, conn_id_, cfg_.timeout.write);
        co_return false;
    }

    client_ip_ = net::normalize_address(tcp_remote_ep.address());
    has_client_ip_ = true;
    tcp_peer_host_ = client_ip_.to_string();
    tcp_peer_port_ = tcp_remote_ep.port();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kConnAccepted,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
        .remote_host = tcp_peer_host_,
        .remote_port = tcp_peer_port_,
    });
    LOG_INFO("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{}",
             log_event::kConnInit,
             trace_id_,
             conn_id_,
             tcp_peer_host_,
             tcp_peer_port_,
             udp_bind_host_,
             udp_bind_port_);

    co_return co_await send_udp_associate_reply(local_addr, udp_port);
}

boost::asio::awaitable<void> socks_udp_session::run(const std::string& host, const uint16_t port)
{
    if (!(co_await prepare_udp_associate(host, port)))
    {
        co_return;
    }

    boost::system::error_code direct_socket_ec;
    open_direct_udp_socket(direct_udp_socket_v4_, boost::asio::ip::udp::v4(), "v4", direct_socket_ec);
    open_direct_udp_socket(direct_udp_socket_v6_, boost::asio::ip::udp::v6(), "v6", direct_socket_ec);
    start_direct_udp_socket_loops();

    using boost::asio::experimental::awaitable_operators::operator||;
    if (cfg_.timeout.idle == 0)
    {
        co_await (udp_socket_loop() || wait_and_proxy_to_udp_sock() || keep_tcp_alive());
    }
    else
    {
        co_await (udp_socket_loop() || wait_and_proxy_to_udp_sock() || keep_tcp_alive() || idle_watchdog());
    }

    if (proxy_outbound_ != nullptr)
    {
        co_await proxy_outbound_->close();
        proxy_outbound_.reset();
        proxy_outbound_started_ = false;
    }

    close_impl();
    const auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time_).count();
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kSessionClose,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = proxy_outbound_tag_,
        .outbound_type = proxy_outbound_ != nullptr ? "proxy" : "direct",
        .target_host = has_last_target_ ? last_target_addr_ : "unknown",
        .target_port = static_cast<uint16_t>(has_last_target_ ? last_target_port_ : 0U),
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
        .remote_host = tcp_peer_host_,
        .remote_port = tcp_peer_port_,
        .bytes_tx = tx_bytes_,
        .bytes_rx = rx_bytes_,
        .extra = {{"duration_ms", std::to_string(duration_ms)}},
    });
    LOG_INFO("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} client {}:{} tx_bytes {} rx_bytes {} duration_ms {}",
             log_event::kConnClose,
             trace_id_,
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

void socks_udp_session::apply_request_peer_constraint(const std::string& host, const uint16_t port) const
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
        LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} udp associate request peer ignored host {} port {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 local_host,
                 local_port,
                 remote_host,
                 remote_port,
                 host,
                 port);
    }
}

std::string socks_udp_session::current_client_host() const
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

uint16_t socks_udp_session::current_client_port() const
{
    if (has_client_addr_)
    {
        return client_addr_.port();
    }
    return tcp_peer_port_;
}

request_context socks_udp_session::make_proxy_outbound_request() const
{
    return request_context{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = has_last_target_ ? last_target_addr_ : "unknown",
        .target_port = static_cast<uint16_t>(has_last_target_ ? last_target_port_ : 0U),
        .client_host = current_client_host(),
        .client_port = current_client_port(),
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
    };
}

void socks_udp_session::open_direct_udp_socket(boost::asio::ip::udp::socket& direct_socket,
                                               const boost::asio::ip::udp& protocol,
                                               const char* family,
                                               boost::system::error_code& ec) const
{
    ec = direct_socket.open(protocol, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} open direct udp {} socket failed {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 tcp_peer_host_,
                 tcp_peer_port_,
                 udp_bind_host_,
                 udp_bind_port_,
                 family,
                 ec.message());
        return;
    }
    const auto connect_mark = resolve_socket_mark(cfg_);
    if (connect_mark != 0)
    {
        net::set_socket_mark(direct_socket.native_handle(), connect_mark, ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} set direct udp {} mark failed {}",
                     log_event::kRoute,
                     trace_id_,
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
        LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} bind direct udp {} socket failed {}",
                 log_event::kRoute,
                 trace_id_,
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

boost::asio::ip::udp::socket* socks_udp_session::select_direct_udp_socket(const boost::asio::ip::udp::endpoint& target)
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

boost::asio::awaitable<route_decision> socks_udp_session::decide_udp_route(const socks_udp_header& header) const
{
    request_context request{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .transport = request_transport::kUdp,
        .command = request_command::kDatagram,
        .inbound_tag = inbound_tag_,
        .inbound_type = inbound_type_,
        .target_host = header.addr,
        .target_port = header.port,
        .client_host = current_client_host(),
        .client_port = current_client_port(),
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
    };
    const auto flow_result = co_await prepare_udp_route_flow(request, router_);
    co_return flow_result.decision;
}

boost::asio::awaitable<bool> socks_udp_session::process_udp_packet(const socks_udp_header& udp_header,
                                                                   const route_decision& decision,
                                                                   const uint8_t* payload,
                                                                   const std::size_t payload_len)
{
    if (decision.route == route_type::kBlock)
    {
        LOG_INFO("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp blocked {}:{}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 udp_header.addr,
                 udp_header.port);
        co_return true;
    }

    if (decision.route == route_type::kProxy)
    {
        boost::system::error_code open_ec;
        if (!(co_await ensure_proxy_outbound(open_ec)))
        {
            co_return false;
        }

        const auto outbound = proxy_outbound_;
        if (outbound == nullptr)
        {
            co_return false;
        }

        boost::system::error_code write_ec;
        co_await outbound->send_datagram(udp_header.addr, udp_header.port, payload, payload_len, write_ec);
        if (write_ec)
        {
            clear_proxy_outbound_if_current(outbound);
            co_await outbound->close();
            LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} target {}:{} write proxy udp datagram failed {}",
                     log_event::kSocks,
                     trace_id_,
                     conn_id_,
                     current_client_host(),
                     current_client_port(),
                     udp_bind_host_,
                     udp_bind_port_,
                     udp_header.addr,
                     udp_header.port,
                     write_ec.message());
            co_return true;
        }

        tx_bytes_ += payload_len;
        trace_store::instance().add_live_tx_bytes(payload_len);
        last_activity_time_ms_ = net::now_ms();
        co_return true;
    }

    boost::system::error_code ec;
    co_await forward_direct_packet(udp_header, payload, payload_len, ec);
    if (ec)
    {
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> socks_udp_session::resolve_target_endpoint(const std::string& host,
                                                                                                  const uint16_t port,
                                                                                                  boost::system::error_code& ec)
{
    const auto key = udp_target_key(host, port);
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

    co_return co_await resolve_target_endpoint_uncached(key, host, port, now_ms_value, ec);
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> socks_udp_session::resolve_target_endpoint_uncached(
    const std::string& key,
    const std::string& host,
    const uint16_t port,
    const uint64_t now_ms_value,
    boost::system::error_code& ec)
{
    boost::asio::ip::udp::resolver resolver(worker_.io_context);
    auto endpoints = co_await net::wait_resolve_with_timeout(resolver, host, std::to_string(port), cfg_.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct resolve failed {}:{} error {}",
                 log_event::kRoute,
                 trace_id_,
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
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct resolve empty {}:{}",
                 log_event::kRoute,
                 trace_id_,
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
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct resolve no compatible endpoint {}:{}",
                 log_event::kRoute,
                 trace_id_,
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

boost::asio::awaitable<void> socks_udp_session::forward_direct_packet(const socks_udp_header& header,
                                                                      const uint8_t* payload,
                                                                      const std::size_t payload_len,
                                                                      boost::system::error_code& ec)
{
    const auto target = co_await resolve_target_endpoint(header.addr, header.port, ec);
    if (ec)
    {
        if (!net::is_socket_close_error(ec))
        {
            ec.clear();
        }
        co_return;
    }
    auto* direct_socket = select_direct_udp_socket(target);
    if (direct_socket == nullptr)
    {
        const auto direct_socket_ec = boost::system::error_code(boost::asio::error::address_family_not_supported);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct socket unavailable {}:{} error {}",
                 log_event::kRoute,
                 trace_id_,
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
        if (net::is_socket_close_error(send_ec))
        {
            ec = send_ec;
        }
        else
        {
            LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct send failed {}:{} error {}",
                     log_event::kRoute,
                     trace_id_,
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
    trace_store::instance().add_live_tx_bytes(payload_len);
    last_activity_time_ms_ = now_ms_value;
}

boost::asio::awaitable<void> socks_udp_session::direct_udp_socket_loop(boost::asio::ip::udp::socket& direct_socket)
{
    udp_socket_reply_relay_context relay_context{
        .socket = direct_socket,
        .last_activity_time_ms = last_activity_time_ms_,
        .rx_bytes = rx_bytes_,
    };
    co_await relay_udp_socket_replies(
        relay_context,
        [this](const boost::asio::ip::udp::endpoint& sender, const uint64_t now_ms_value)
        {
            direct_peers_.evict_if([&](const auto&, const auto& entry) { return entry.expires_at <= now_ms_value; });
            const auto normalized_sender = net::normalize_endpoint(sender);
            auto* peer = direct_peers_.get(normalized_sender);
            if (peer == nullptr || peer->expires_at <= now_ms_value)
            {
                if (peer != nullptr && peer->expires_at <= now_ms_value)
                {
                    direct_peers_.erase(normalized_sender);
                }
                LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} ignore udp packet from unexpected direct peer {}:{}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         sender.address().to_string(),
                         sender.port());
                return false;
            }
            return true;
        },
        [this](const boost::asio::ip::udp::endpoint& sender, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec)
            -> boost::asio::awaitable<std::size_t> { co_return co_await forward_direct_reply_to_client(sender, payload, payload_len, ec); },
        [this, &direct_socket](const boost::system::error_code& ec)
        {
            if (!net::is_socket_close_error(ec))
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} direct udp receive error {}",
                         log_event::kRoute,
                         trace_id_,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         ec.message());
                boost::system::error_code close_ec;
                close_ec = direct_socket.close(close_ec);
                (void)close_ec;
            }
        });
}

void socks_udp_session::start_direct_udp_socket_loops()
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

boost::asio::awaitable<std::size_t> socks_udp_session::forward_direct_reply_to_client(const boost::asio::ip::udp::endpoint& sender,
                                                                                       const uint8_t* payload,
                                                                                       const std::size_t payload_len,
                                                                                       boost::system::error_code& ec)
{
    if (!has_client_addr_)
    {
        co_return 0;
    }

    const auto normalized_sender = net::normalize_endpoint(sender);
    const socks_udp_header header{.frag = 0, .addr = normalized_sender.address().to_string(), .port = normalized_sender.port()};
    const auto udp_header = socks_codec::encode_udp_header(header);
    const auto packet_len = udp_header.size() + payload_len;
    if (packet_len > constants::udp::kMaxPayload)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp reply oversized drop size {} max {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 packet_len,
                 constants::udp::kMaxPayload);
        co_return 0;
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
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp direct reply failed {}:{} error {}",
                 log_event::kRoute,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 client_addr_.address().to_string(),
                 client_addr_.port(),
                 ec.message());
        co_return 0;
    }
    co_return packet_len;
}

boost::asio::awaitable<std::size_t> socks_udp_session::forward_proxy_reply_to_client(const proxy::udp_datagram& datagram,
                                                                                      boost::system::error_code& ec,
                                                                                      bool& send_reply_failed)
{
    if (!has_client_addr_)
    {
        co_return 0;
    }

    const socks_udp_header header{.frag = 0, .addr = datagram.target_host, .port = datagram.target_port};
    const auto udp_header = socks_codec::encode_udp_header(header);
    if (udp_header.empty())
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} invalid proxy udp source {}:{}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 datagram.target_host,
                 datagram.target_port);
        co_return 0;
    }

    const auto packet_len = udp_header.size() + datagram.payload.size();
    if (packet_len > constants::udp::kMaxPayload)
    {
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} proxy udp reply oversized drop size {} max {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 packet_len,
                 constants::udp::kMaxPayload);
        co_return 0;
    }

    std::vector<uint8_t> packet;
    packet.reserve(packet_len);
    packet.insert(packet.end(), udp_header.begin(), udp_header.end());
    packet.insert(packet.end(), datagram.payload.begin(), datagram.payload.end());

    const auto [send_ec, send_n] =
        co_await udp_socket_.async_send_to(boost::asio::buffer(packet), client_addr_, boost::asio::as_tuple(boost::asio::use_awaitable));
    ec = send_ec;
    if (ec)
    {
        LOG_ERROR("{} trace {:016x} conn {} client {}:{} udp bind {}:{} send proxy udp reply failed {}",
                  log_event::kSocks,
                  trace_id_,
                  conn_id_,
                  current_client_host(),
                  current_client_port(),
                  udp_bind_host_,
                  udp_bind_port_,
                  ec.message());
        send_reply_failed = true;
        co_return 0;
    }
    co_return send_n;
}

boost::asio::awaitable<bool> socks_udp_session::connect_proxy_outbound(boost::system::error_code& ec)
{
    trace_store::instance().record_event(trace_event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectStart,
        .result = trace_result::kOk,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = proxy_outbound_tag_,
        .outbound_type = "proxy",
        .target_host = has_last_target_ ? last_target_addr_ : "unknown",
        .target_port = static_cast<uint16_t>(has_last_target_ ? last_target_port_ : 0U),
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
        .remote_host = tcp_peer_host_,
        .remote_port = tcp_peer_port_,
    });
    const auto request = make_proxy_outbound_request();
    const auto connect_result = co_await connect_udp_proxy_flow(worker_.io_context.get_executor(), request, proxy_outbound_tag_, cfg_);
    co_return co_await apply_proxy_outbound_connect_result(connect_result, ec);
}

void socks_udp_session::record_proxy_outbound_connect_result(const bool success, const boost::system::error_code& ec) const
{
    trace_event event{
        .trace_id = trace_id_,
        .conn_id = conn_id_,
        .stage = trace_stage::kOutboundConnectDone,
        .result = success ? trace_result::kOk : trace_result::kFail,
        .inbound_tag = inbound_tag_,
        .inbound_type = "socks",
        .outbound_tag = proxy_outbound_tag_,
        .outbound_type = "proxy",
        .target_host = has_last_target_ ? last_target_addr_ : "unknown",
        .target_port = static_cast<uint16_t>(has_last_target_ ? last_target_port_ : 0U),
        .local_host = udp_bind_host_,
        .local_port = udp_bind_port_,
        .remote_host = tcp_peer_host_,
        .remote_port = tcp_peer_port_,
    };
    if (ec)
    {
        event.error_code = static_cast<int32_t>(ec.value());
        event.error_message = ec.message();
    }
    trace_store::instance().record_event(std::move(event));
}

boost::asio::awaitable<bool> socks_udp_session::apply_proxy_outbound_connect_result(
    const udp_proxy_outbound_connect_result& connect_result, boost::system::error_code& ec)
{
    if (connect_result.ec || connect_result.outbound == nullptr)
    {
        ec = connect_result.ec ? connect_result.ec : boost::asio::error::not_connected;
        record_proxy_outbound_connect_result(false, ec);
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} target {}:{} connect proxy udp outbound failed {} rep {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 has_last_target_ ? last_target_addr_ : "unknown",
                 has_last_target_ ? last_target_port_ : 0,
                 ec.message(),
                 connect_result.socks_rep);
        co_return false;
    }

    proxy_outbound_ = connect_result.outbound;
    record_proxy_outbound_connect_result(true, {});
    LOG_INFO("{} trace {:016x} conn {} client {}:{} udp bind {}:{} target {}:{} proxy udp outbound ready bind {}:{}",
             log_event::kSocks,
             trace_id_,
             conn_id_,
             current_client_host(),
             current_client_port(),
             udp_bind_host_,
             udp_bind_port_,
             has_last_target_ ? last_target_addr_ : "unknown",
             has_last_target_ ? last_target_port_ : 0,
             proxy_outbound_->bind_host(),
             proxy_outbound_->bind_port());
    co_return true;
}

boost::asio::awaitable<bool> socks_udp_session::start_proxy_outbound_reader(boost::system::error_code& ec)
{
    const auto [send_ec] =
        co_await proxy_outbound_channel_.async_send(boost::system::error_code{}, proxy_outbound_, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (send_ec)
    {
        ec = send_ec;
        LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} target {}:{} start proxy udp reader failed {}",
                 log_event::kSocks,
                 trace_id_,
                 conn_id_,
                 current_client_host(),
                 current_client_port(),
                 udp_bind_host_,
                 udp_bind_port_,
                 has_last_target_ ? last_target_addr_ : "unknown",
                 has_last_target_ ? last_target_port_ : 0,
                 ec.message());
        auto outbound = proxy_outbound_;
        proxy_outbound_.reset();
        proxy_outbound_started_ = false;
        if (outbound != nullptr)
        {
            co_await outbound->close();
        }
        co_return false;
    }
    proxy_outbound_started_ = true;
    co_return true;
}

boost::asio::awaitable<bool> socks_udp_session::ensure_proxy_outbound(boost::system::error_code& ec)
{
    if (proxy_outbound_ == nullptr)
    {
        if (!(co_await connect_proxy_outbound(ec)))
        {
            co_return false;
        }
    }

    if (!proxy_outbound_started_)
    {
        if (!(co_await start_proxy_outbound_reader(ec)))
        {
            co_return false;
        }
    }
    co_return true;
}

void socks_udp_session::clear_proxy_outbound_if_current(const std::shared_ptr<udp_proxy_outbound>& outbound)
{
    if (outbound == nullptr || proxy_outbound_ != outbound)
    {
        return;
    }

    proxy_outbound_.reset();
    proxy_outbound_started_ = false;
}

boost::asio::awaitable<void> socks_udp_session::udp_socket_loop()
{
    std::vector<uint8_t> buf(65535);
    boost::asio::ip::udp::endpoint sender;
    while (true)
    {
        const auto [recv_ec, n] =
            co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (recv_ec)
        {
            if (!stopped_ && !net::is_socket_close_error(recv_ec))
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} receive error {}",
                         log_event::kSocks,
                         trace_id_,
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
            LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} ignore udp packet from unexpected peer {} expected {}",
                     log_event::kSocks,
                     trace_id_,
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
            LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} ignore udp packet from unexpected peer {}:{} expected {}:{}",
                     log_event::kSocks,
                     trace_id_,
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
            LOG_INFO("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} udp peer bound to {}:{}",
                     log_event::kSocks,
                     trace_id_,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     client_addr_.address().to_string(),
                     client_addr_.port());
        }

        socks_udp_header udp_header;
        if (!decode_client_udp_header(buf, n, udp_header, trace_id_, normalized_sender, udp_bind_host_, udp_bind_port_, conn_id_))
        {
            continue;
        }

        last_target_addr_ = udp_header.addr;
        last_target_port_ = udp_header.port;
        has_last_target_ = true;

        const auto decision = co_await decide_udp_route(udp_header);
        proxy_outbound_tag_ = decision.outbound_tag;
        trace_store::instance().record_event(trace_event{
            .trace_id = trace_id_,
            .conn_id = conn_id_,
            .stage = trace_stage::kRouteDecideDone,
            .result = decision.route == route_type::kBlock ? trace_result::kFail : trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "socks",
            .outbound_tag = decision.outbound_tag,
            .outbound_type = decision.outbound_type,
            .target_host = udp_header.addr,
            .target_port = udp_header.port,
            .local_host = udp_bind_host_,
            .local_port = udp_bind_port_,
            .remote_host = tcp_peer_host_,
            .remote_port = tcp_peer_port_,
            .route_type = relay::to_string(decision.route),
            .match_type = decision.match_type,
            .match_value = decision.match_value,
        });
        if (decision.route == route_type::kBlock)
        {
            LOG_INFO("{} trace {:016x} conn {} client {}:{} udp bind {}:{} udp blocked {}:{}",
                     log_event::kRoute,
                     trace_id_,
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
        if (!(co_await process_udp_packet(udp_header, decision, buf.data() + udp_header.header_len, payload_len)))
        {
            break;
        }
    }
}

boost::asio::awaitable<void> socks_udp_session::wait_and_proxy_to_udp_sock()
{
    while (true)
    {
        auto [read_ec, outbound] = co_await proxy_outbound_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (read_ec)
        {
            co_return;
        }
        if (outbound == nullptr)
        {
            continue;
        }

        co_await proxy_to_udp_sock(outbound);
    }
}

boost::asio::awaitable<void> socks_udp_session::proxy_to_udp_sock(std::shared_ptr<udp_proxy_outbound> outbound)
{
    bool send_reply_failed = false;
    proxy_outbound_reply_relay_context relay_context{
        .read_timeout_sec = cfg_.timeout.read,
        .last_activity_time_ms = last_activity_time_ms_,
        .rx_bytes = rx_bytes_,
    };
    co_await relay_proxy_outbound_replies(
        outbound,
        relay_context,
        [this]() { return stopped_; },
        [this, &send_reply_failed](const proxy::udp_datagram& datagram, boost::system::error_code& ec)
            -> boost::asio::awaitable<std::size_t>
        {
            co_return co_await forward_proxy_reply_to_client(datagram, ec, send_reply_failed);
        },
        [this, &outbound, &send_reply_failed](const boost::system::error_code& ec)
        {
            clear_proxy_outbound_if_current(outbound);
            if (send_reply_failed)
            {
                close_impl();
                return;
            }
            if (!stopped_ && !net::is_socket_close_error(ec))
            {
                LOG_WARN("{} trace {:016x} conn {} client {}:{} udp bind {}:{} read proxy udp datagram failed {}",
                         log_event::kSocks,
                         trace_id_,
                         conn_id_,
                         current_client_host(),
                         current_client_port(),
                         udp_bind_host_,
                         udp_bind_port_,
                         ec.message());
            }
        });
    clear_proxy_outbound_if_current(outbound);
    if (!stopped_)
    {
        co_await outbound->close();
    }
}

boost::asio::awaitable<void> socks_udp_session::keep_tcp_alive()
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
                LOG_INFO("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} client {}:{} tcp control channel closed eof",
                         log_event::kConnClose,
                         trace_id_,
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
                LOG_ERROR("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} client {}:{} keep tcp alive error {}",
                          log_event::kSocks,
                          trace_id_,
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
            LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} client {}:{} tcp control channel flooded ignored_bytes {}",
                     log_event::kSocks,
                     trace_id_,
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

boost::asio::awaitable<void> socks_udp_session::idle_watchdog()
{
    datagram_idle_watchdog_context relay_context{
        .timer = idle_timer_,
        .idle_timeout_sec = cfg_.timeout.idle,
        .last_activity_time_ms = last_activity_time_ms_,
    };
    co_await run_datagram_idle_watchdog(
        relay_context,
        [this]()
        {
            LOG_WARN("{} trace {:016x} conn {} tcp peer {}:{} udp bind {}:{} client {}:{} last_target {}:{} udp session idle closing",
                     log_event::kSocks,
                     trace_id_,
                     conn_id_,
                     tcp_peer_host_,
                     tcp_peer_port_,
                     udp_bind_host_,
                     udp_bind_port_,
                     current_client_host(),
                     current_client_port(),
                     has_last_target_ ? last_target_addr_ : "unknown",
                     has_last_target_ ? last_target_port_ : 0);
            close_impl();
        });
}

}    // namespace relay
