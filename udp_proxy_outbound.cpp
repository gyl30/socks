#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "net_utils.h"
#include "constants.h"
#include "proxy_protocol.h"
#include "udp_proxy_outbound.h"
#include "proxy_reality_connection.h"

namespace relay
{

namespace
{

[[nodiscard]] boost::system::error_code map_socks_rep_to_connect_error(const uint8_t rep)
{
    switch (rep)
    {
        case socks::kRepSuccess:
            return {};
        case socks::kRepNotAllowed:
            return boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        case socks::kRepNetUnreach:
            return boost::asio::error::network_unreachable;
        case socks::kRepHostUnreach:
            return boost::asio::error::host_unreachable;
        case socks::kRepConnRefused:
            return boost::asio::error::connection_refused;
        case socks::kRepTtlExpired:
            return boost::asio::error::timed_out;
        case socks::kRepCmdNotSupported:
            return boost::asio::error::operation_not_supported;
        case socks::kRepAddrTypeNotSupported:
            return boost::asio::error::address_family_not_supported;
        default:
            return boost::asio::error::connection_aborted;
    }
}

[[nodiscard]] const config::socks_t* find_socks_outbound_settings(const config& cfg, const std::string& outbound_tag)
{
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr || outbound->type != "socks" || !outbound->socks.has_value())
    {
        return nullptr;
    }
    return &*outbound->socks;
}

boost::asio::awaitable<bool> connect_socks_server(boost::asio::ip::tcp::socket& socket,
                                                  boost::asio::ip::tcp::resolver& resolver,
                                                  const config::socks_t& settings,
                                                  const config& cfg,
                                                  const uint32_t conn_id,
                                                  const std::string& outbound_tag,
                                                  boost::system::error_code& ec)
{
    auto endpoints = co_await net::wait_resolve_with_timeout(resolver, settings.host, std::to_string(settings.port), cfg.timeout.connect, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} out_tag {} stage resolve socks server {}:{} error {}",
                 log_event::kRoute,
                 conn_id,
                 outbound_tag,
                 settings.host,
                 settings.port,
                 ec.message());
        co_return false;
    }

    for (const auto& entry : endpoints)
    {
        if (socket.is_open())
        {
            boost::system::error_code close_ec;
            close_ec = socket.close(close_ec);
        }

        ec = socket.open(entry.endpoint().protocol(), ec);
        if (ec)
        {
            continue;
        }
        const auto connect_mark = resolve_socket_mark(cfg);
        if (connect_mark != 0)
        {
            net::set_socket_mark(socket.native_handle(), connect_mark, ec);
            if (ec)
            {
                continue;
            }
        }

        co_await net::wait_connect_with_timeout(socket, entry.endpoint(), cfg.timeout.connect, ec);
        if (ec)
        {
            continue;
        }
        ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            ec.clear();
        }
        co_return true;
    }
    co_return false;
}

boost::asio::awaitable<bool> do_password_auth(boost::asio::ip::tcp::socket& socket,
                                              const config::socks_t& settings,
                                              const config& cfg,
                                              boost::system::error_code& ec)
{
    if (settings.username.size() > 255 || settings.password.size() > 255)
    {
        ec = boost::asio::error::invalid_argument;
        co_return false;
    }

    std::vector<uint8_t> request;
    request.reserve(3 + settings.username.size() + settings.password.size());
    request.push_back(socks::kAuthVer);
    request.push_back(static_cast<uint8_t>(settings.username.size()));
    request.insert(request.end(), settings.username.begin(), settings.username.end());
    request.push_back(static_cast<uint8_t>(settings.password.size()));
    request.insert(request.end(), settings.password.begin(), settings.password.end());
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(request), cfg.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket, boost::asio::buffer(reply), cfg.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (reply[0] != socks::kAuthVer || reply[1] != 0x00)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> negotiate_method(boost::asio::ip::tcp::socket& socket,
                                              const config::socks_t& settings,
                                              const config& cfg,
                                              boost::system::error_code& ec)
{
    const uint8_t method = settings.auth ? socks::kMethodPassword : socks::kMethodNoAuth;
    const uint8_t request[] = {socks::kVer, 0x01, method};
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(request), cfg.timeout.write, ec);
    if (ec)
    {
        co_return false;
    }

    uint8_t reply[2] = {0};
    co_await net::wait_read_with_timeout(socket, boost::asio::buffer(reply), cfg.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (reply[0] != socks::kVer || reply[1] == socks::kMethodNoAcceptable)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return false;
    }
    if (reply[1] == socks::kMethodPassword)
    {
        co_return co_await do_password_auth(socket, settings, cfg, ec);
    }
    if (reply[1] != socks::kMethodNoAuth)
    {
        ec = boost::asio::error::operation_not_supported;
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> send_udp_associate_request(boost::asio::ip::tcp::socket& socket, const config& cfg, boost::system::error_code& ec)
{
    const uint8_t request[] = {socks::kVer, socks::kCmdUdpAssociate, 0x00, socks::kAtypIpv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    co_await net::wait_write_with_timeout(socket, boost::asio::buffer(request), cfg.timeout.write, ec);
    co_return !ec;
}

boost::asio::awaitable<bool> read_udp_associate_reply(boost::asio::ip::tcp::socket& socket,
                                                      const config& cfg,
                                                      std::string& bind_host,
                                                      uint16_t& bind_port,
                                                      uint8_t& socks_rep,
                                                      boost::system::error_code& ec)
{
    uint8_t header[4] = {0};
    co_await net::wait_read_with_timeout(socket, boost::asio::buffer(header), cfg.timeout.read, ec);
    if (ec)
    {
        co_return false;
    }
    if (header[0] != socks::kVer)
    {
        ec = boost::asio::error::invalid_argument;
        co_return false;
    }

    socks_rep = header[1];
    if (socks_rep != socks::kRepSuccess)
    {
        co_return false;
    }

    std::vector<uint8_t> payload;
    if (header[3] == socks::kAtypIpv4)
    {
        payload.resize(6);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy_n(payload.begin(), 4, bytes.begin());
        bind_host = boost::asio::ip::address_v4(bytes).to_string();
        bind_port = static_cast<uint16_t>((payload[4] << 8) | payload[5]);
        co_return true;
    }

    if (header[3] == socks::kAtypIpv6)
    {
        payload.resize(18);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::copy_n(payload.begin(), 16, bytes.begin());
        bind_host = boost::asio::ip::address_v6(bytes).to_string();
        bind_port = static_cast<uint16_t>((payload[16] << 8) | payload[17]);
        co_return true;
    }

    if (header[3] == socks::kAtypDomain)
    {
        uint8_t length = 0;
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(&length, 1), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        payload.resize(static_cast<std::size_t>(length) + 2U);
        co_await net::wait_read_with_timeout(socket, boost::asio::buffer(payload), cfg.timeout.read, ec);
        if (ec)
        {
            co_return false;
        }
        bind_host.assign(payload.begin(), payload.end() - 2);
        bind_port = static_cast<uint16_t>((payload[payload.size() - 2] << 8) | payload[payload.size() - 1]);
        co_return true;
    }

    ec = boost::asio::error::address_family_not_supported;
    co_return false;
}

boost::asio::awaitable<boost::asio::ip::udp::endpoint> resolve_udp_endpoint(const boost::asio::any_io_executor& executor,
                                                                             std::string host,
                                                                             const uint16_t port,
                                                                             const config& cfg,
                                                                             boost::system::error_code& ec)
{
    boost::asio::ip::udp::resolver resolver(executor);
    auto results = co_await net::wait_resolve_with_timeout(resolver, std::move(host), std::to_string(port), cfg.timeout.connect, ec);
    if (ec || results.begin() == results.end())
    {
        if (!ec)
        {
            ec = boost::asio::error::host_not_found;
        }
        co_return boost::asio::ip::udp::endpoint{};
    }
    co_return results.begin()->endpoint();
}

boost::asio::awaitable<void> send_udp_packet_with_timeout(boost::asio::ip::udp::socket& socket,
                                                          const boost::asio::ip::udp::endpoint& endpoint,
                                                          const std::vector<uint8_t>& packet,
                                                          const uint32_t timeout_sec,
                                                          boost::system::error_code& ec)
{
    co_await net::detail::await_with_timeout(
        timeout_sec,
        [&]() { return socket.async_send_to(boost::asio::buffer(packet), endpoint, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec, bytes_sent] = result;
            (void)bytes_sent;
            ec = op_ec;
        },
        [&](const auto& wait_result)
        {
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
        });
}

boost::asio::awaitable<std::size_t> receive_udp_packet_with_timeout(boost::asio::ip::udp::socket& socket,
                                                                    std::vector<uint8_t>& packet,
                                                                    boost::asio::ip::udp::endpoint& sender,
                                                                    const uint32_t timeout_sec,
                                                                    boost::system::error_code& ec)
{
    std::size_t received = 0;
    co_await net::detail::await_with_timeout(
        timeout_sec,
        [&]() { return socket.async_receive_from(boost::asio::buffer(packet), sender, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec, bytes_recv] = result;
            ec = op_ec;
            received = bytes_recv;
        },
        [&](const auto& wait_result)
        {
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
            received = 0;
        });
    co_return received;
}

}    // namespace

proxy_udp_upstream::proxy_udp_upstream(std::shared_ptr<proxy_reality_connection> connection, const config& cfg)
    : cfg_(cfg), mode_(upstream_mode::kReality), connection_(std::move(connection))
{
}

proxy_udp_upstream::proxy_udp_upstream(std::shared_ptr<boost::asio::ip::tcp::socket> control_socket,
                                       std::shared_ptr<boost::asio::ip::udp::socket> udp_socket,
                                       boost::asio::ip::udp::endpoint udp_server_endpoint,
                                       const config& cfg)
    : cfg_(cfg),
      mode_(upstream_mode::kSocks),
      socks_control_socket_(std::move(control_socket)),
      socks_udp_socket_(std::move(udp_socket)),
      socks_udp_server_endpoint_(std::move(udp_server_endpoint))
{
}

boost::asio::awaitable<proxy_udp_connect_result> proxy_udp_upstream::connect(const boost::asio::any_io_executor& executor,
                                                                             const uint32_t conn_id,
                                                                             const uint64_t trace_id,
                                                                             const config& cfg,
                                                                             const std::string& outbound_tag)
{
    proxy_udp_connect_result result;
    result.socks_rep = socks::kRepSuccess;
    const auto* outbound = find_outbound_entry(cfg, outbound_tag);
    if (outbound == nullptr)
    {
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }

    if (outbound->type == "reality")
    {
        boost::system::error_code ec;
        auto connection = co_await proxy_reality_connection::connect(executor, cfg, outbound_tag, conn_id, ec);
        if (connection == nullptr)
        {
            result.ec = ec ? ec : boost::asio::error::not_connected;
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
            co_return result;
        }

        auto upstream = std::make_shared<proxy_udp_upstream>(connection, cfg);
        proxy::udp_associate_request request;
        request.trace_id = trace_id;
        std::vector<uint8_t> packet;
        if (!proxy::encode_udp_associate_request(request, packet))
        {
            result.ec = boost::asio::error::message_size;
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
            co_return result;
        }
        co_await connection->write_packet(packet, ec);
        if (ec)
        {
            result.ec = ec;
            result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
            co_return result;
        }

        const auto reply_packet = co_await connection->read_packet(upstream->associate_reply_timeout(), ec);
        if (ec)
        {
            result.ec = ec;
            result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
            co_return result;
        }

        proxy::udp_associate_reply reply;
        if (!proxy::decode_udp_associate_reply(reply_packet.data(), reply_packet.size(), reply))
        {
            result.ec = boost::asio::error::invalid_argument;
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
            co_return result;
        }

        result.socks_rep = reply.socks_rep;
        if (reply.socks_rep != socks::kRepSuccess)
        {
            result.ec = map_socks_rep_to_connect_error(reply.socks_rep);
            co_return result;
        }

        boost::system::error_code bind_ec;
        const auto bind_addr = boost::asio::ip::make_address(reply.bind_host, bind_ec);
        if (!bind_ec)
        {
            result.bind_addr = socks_codec::normalize_ip_address(bind_addr);
            result.bind_port = reply.bind_port;
            result.has_bind_endpoint = true;
            upstream->bind_host_ = result.bind_addr.to_string();
            upstream->bind_port_ = result.bind_port;
        }
        result.upstream = std::move(upstream);
        co_return result;
    }

    if (outbound->type != "socks")
    {
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }

    const auto* settings = find_socks_outbound_settings(cfg, outbound_tag);
    if (settings == nullptr)
    {
        result.ec = boost::asio::error::operation_not_supported;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }

    auto control_socket = std::make_shared<boost::asio::ip::tcp::socket>(executor);
    boost::asio::ip::tcp::resolver tcp_resolver(executor);
    boost::system::error_code ec;
    if (!(co_await connect_socks_server(*control_socket, tcp_resolver, *settings, cfg, conn_id, outbound_tag, ec)))
    {
        result.ec = ec ? ec : boost::asio::error::host_unreachable;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (!(co_await negotiate_method(*control_socket, *settings, cfg, ec)))
    {
        result.ec = ec ? ec : boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }
    if (!(co_await send_udp_associate_request(*control_socket, cfg, ec)))
    {
        result.ec = ec ? ec : boost::asio::error::operation_aborted;
        result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        co_return result;
    }

    std::string bind_host;
    uint16_t bind_port = 0;
    uint8_t socks_rep = socks::kRepSuccess;
    if (!(co_await read_udp_associate_reply(*control_socket, cfg, bind_host, bind_port, socks_rep, ec)))
    {
        result.socks_rep = socks_rep;
        result.ec = socks_rep != socks::kRepSuccess ? map_socks_rep_to_connect_error(socks_rep)
                                                    : (ec ? ec : boost::asio::error::operation_aborted);
        if (result.socks_rep == socks::kRepSuccess)
        {
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        }
        co_return result;
    }

    std::string udp_host = bind_host;
    boost::system::error_code remote_ec;
    const auto remote_endpoint = control_socket->remote_endpoint(remote_ec);
    if (udp_host.empty() || udp_host == "0.0.0.0" || udp_host == "::")
    {
        if (!remote_ec)
        {
            udp_host = remote_endpoint.address().to_string();
        }
    }
    auto udp_server_endpoint = co_await resolve_udp_endpoint(executor, udp_host, bind_port, cfg, ec);
    if (ec)
    {
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        co_return result;
    }

    auto udp_socket = std::make_shared<boost::asio::ip::udp::socket>(executor);
    ec = udp_socket->open(udp_server_endpoint.protocol(), ec);
    if (ec)
    {
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        co_return result;
    }
    const auto connect_mark = resolve_socket_mark(cfg);
    if (connect_mark != 0)
    {
        net::set_socket_mark(udp_socket->native_handle(), connect_mark, ec);
        if (ec)
        {
            result.ec = ec;
            result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
            co_return result;
        }
    }
    udp_socket->bind(boost::asio::ip::udp::endpoint(udp_server_endpoint.protocol(), 0), ec);
    if (ec)
    {
        result.ec = ec;
        result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
        co_return result;
    }

    auto upstream = std::make_shared<proxy_udp_upstream>(control_socket, udp_socket, udp_server_endpoint, cfg);
    upstream->bind_host_ = bind_host;
    upstream->bind_port_ = bind_port;
    boost::system::error_code bind_ec;
    const auto bind_addr = boost::asio::ip::make_address(bind_host, bind_ec);
    if (!bind_ec)
    {
        result.bind_addr = socks_codec::normalize_ip_address(bind_addr);
        result.bind_port = bind_port;
        result.has_bind_endpoint = true;
    }
    result.upstream = std::move(upstream);
    co_return result;
}

uint32_t proxy_udp_upstream::associate_reply_timeout() const
{
    if (cfg_.timeout.connect == 0)
    {
        return cfg_.timeout.read;
    }
    return std::max(cfg_.timeout.read, cfg_.timeout.connect + 1);
}

boost::asio::awaitable<void> proxy_udp_upstream::close()
{
    if (connection_ != nullptr)
    {
        boost::system::error_code ec;
        connection_->close(ec);
    }
    connection_.reset();

    if (socks_control_socket_ != nullptr)
    {
        boost::system::error_code ec;
        ec = socks_control_socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        ec = socks_control_socket_->close(ec);
    }
    socks_control_socket_.reset();

    if (socks_udp_socket_ != nullptr)
    {
        boost::system::error_code ec;
        ec = socks_udp_socket_->close(ec);
    }
    socks_udp_socket_.reset();
    co_return;
}

boost::asio::awaitable<void> proxy_udp_upstream::send_datagram(
    const std::string& host, const uint16_t port, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec)
{
    if (mode_ == upstream_mode::kReality)
    {
        if (connection_ == nullptr)
        {
            ec = boost::asio::error::not_connected;
            co_return;
        }

        proxy::udp_datagram datagram;
        datagram.target_host = host;
        datagram.target_port = port;
        datagram.payload.assign(payload, payload + static_cast<std::ptrdiff_t>(payload_len));

        std::vector<uint8_t> packet;
        if (!proxy::encode_udp_datagram(datagram, packet))
        {
            ec = boost::asio::error::message_size;
            co_return;
        }

        co_await connection_->write_packet(packet, ec);
        co_return;
    }

    if (socks_udp_socket_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return;
    }

    socks_udp_header header;
    header.frag = 0x00;
    header.addr = host;
    header.port = port;
    auto packet = socks_codec::encode_udp_header(header);
    if (packet.empty())
    {
        ec = boost::asio::error::invalid_argument;
        co_return;
    }
    packet.insert(packet.end(), payload, payload + static_cast<std::ptrdiff_t>(payload_len));
    co_await send_udp_packet_with_timeout(*socks_udp_socket_, socks_udp_server_endpoint_, packet, cfg_.timeout.write, ec);
}

boost::asio::awaitable<proxy::udp_datagram> proxy_udp_upstream::receive_datagram(const uint32_t timeout_sec, boost::system::error_code& ec)
{
    if (mode_ == upstream_mode::kReality)
    {
        if (connection_ == nullptr)
        {
            ec = boost::asio::error::not_connected;
            co_return proxy::udp_datagram{};
        }

        const auto packet = co_await connection_->read_packet(timeout_sec, ec);
        if (ec)
        {
            co_return proxy::udp_datagram{};
        }

        proxy::udp_datagram datagram;
        if (!proxy::decode_udp_datagram(packet.data(), packet.size(), datagram))
        {
            ec = boost::asio::error::invalid_argument;
            co_return proxy::udp_datagram{};
        }
        co_return datagram;
    }

    if (socks_udp_socket_ == nullptr)
    {
        ec = boost::asio::error::not_connected;
        co_return proxy::udp_datagram{};
    }

    std::vector<uint8_t> packet(constants::udp::kMaxPacketSize);
    boost::asio::ip::udp::endpoint sender;
    const auto packet_len = co_await receive_udp_packet_with_timeout(*socks_udp_socket_, packet, sender, timeout_sec, ec);
    if (ec)
    {
        co_return proxy::udp_datagram{};
    }

    socks_udp_header header;
    if (!socks_codec::decode_udp_header(packet.data(), packet_len, header) || header.header_len > packet_len)
    {
        ec = boost::asio::error::invalid_argument;
        co_return proxy::udp_datagram{};
    }

    proxy::udp_datagram datagram;
    datagram.target_host = header.addr;
    datagram.target_port = header.port;
    datagram.payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(header.header_len),
                            packet.begin() + static_cast<std::ptrdiff_t>(packet_len));
    co_return datagram;
}

}    // namespace relay
