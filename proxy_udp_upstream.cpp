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
#include "constants.h"
#include "proxy_protocol.h"
#include "proxy_udp_upstream.h"
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

}    // namespace

proxy_udp_upstream::proxy_udp_upstream(std::shared_ptr<proxy_reality_connection> connection, const config& cfg)
    : cfg_(cfg), connection_(std::move(connection))
{
}

boost::asio::awaitable<proxy_udp_connect_result> proxy_udp_upstream::connect(const boost::asio::any_io_executor& executor,
                                                                             const uint32_t conn_id,
                                                                             const uint64_t trace_id,
                                                                             const config& cfg)
{
    proxy_udp_connect_result result;
    result.socks_rep = socks::kRepSuccess;

    boost::system::error_code ec;
    auto connection = co_await proxy_reality_connection::connect(executor, cfg, conn_id, ec);
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
    co_return;
}

boost::asio::awaitable<void> proxy_udp_upstream::send_datagram(
    const std::string& host, const uint16_t port, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec)
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
}

boost::asio::awaitable<proxy::udp_datagram> proxy_udp_upstream::receive_datagram(const uint32_t timeout_sec, boost::system::error_code& ec)
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

}    // namespace relay
