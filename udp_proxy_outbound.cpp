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
#include "config_type_facts.h"
#include "protocol.h"
#include "net_utils.h"
#include "constants.h"
#include "proxy_protocol.h"
#include "udp_proxy_outbound.h"
#include "proxy_reality_connection.h"
#include "socks_client_flow.h"

namespace relay
{

namespace
{

struct socks_udp_associate_result
{
    boost::system::error_code ec;
    std::shared_ptr<boost::asio::ip::tcp::socket> control_socket;
    std::string bind_host;
    uint16_t bind_port = 0;
    uint8_t socks_rep = socks::kRepSuccess;
    bool success = false;
};

void set_connect_failure(udp_proxy_outbound_connect_result& result, const boost::system::error_code& ec)
{
    result.ec = ec;
    result.socks_rep = socks::map_connect_error_to_socks_rep(ec);
}

boost::asio::awaitable<bool> connect_socks_server(boost::asio::ip::tcp::socket& socket,
                                                  boost::asio::ip::tcp::resolver& resolver,
                                                  const config::socks_t& settings,
                                                  const config& cfg,
                                                  const uint32_t conn_id,
                                                  const std::string& outbound_tag,
                                                  const uint32_t connect_mark,
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

    co_return co_await socks_client::read_reply_address(socket, header[3], cfg, bind_host, bind_port, ec);
}

socks_udp_associate_result make_socks_udp_associate_failure(boost::system::error_code ec, const uint8_t socks_rep)
{
    socks_udp_associate_result result;
    result.ec = ec;
    result.socks_rep = socks_rep;
    return result;
}

boost::asio::awaitable<socks_udp_associate_result> open_socks_udp_associate(const boost::asio::any_io_executor& executor,
                                                                            const config::socks_t& settings,
                                                                            const config& cfg,
                                                                            const uint32_t conn_id,
                                                                            const std::string& outbound_tag,
                                                                            const uint32_t connect_mark)
{
    auto control_socket = std::make_shared<boost::asio::ip::tcp::socket>(executor);
    boost::asio::ip::tcp::resolver tcp_resolver(executor);
    boost::system::error_code ec;
    if (!(co_await connect_socks_server(*control_socket, tcp_resolver, settings, cfg, conn_id, outbound_tag, connect_mark, ec)))
    {
        co_return make_socks_udp_associate_failure(ec ? ec : boost::asio::error::host_unreachable, socks::kRepSuccess);
    }
    if (!(co_await socks_client::negotiate_method(*control_socket, settings, cfg, ec)))
    {
        co_return make_socks_udp_associate_failure(
            ec ? ec : boost::system::errc::make_error_code(boost::system::errc::permission_denied), socks::kRepSuccess);
    }
    if (!(co_await send_udp_associate_request(*control_socket, cfg, ec)))
    {
        co_return make_socks_udp_associate_failure(ec ? ec : boost::asio::error::operation_aborted, socks::kRepSuccess);
    }

    socks_udp_associate_result result;
    result.control_socket = std::move(control_socket);
    if (!(co_await read_udp_associate_reply(*result.control_socket, cfg, result.bind_host, result.bind_port, result.socks_rep, ec)))
    {
        result.ec = result.socks_rep != socks::kRepSuccess ? socks::map_socks_rep_to_connect_error(result.socks_rep)
                                                           : (ec ? ec : boost::asio::error::operation_aborted);
        co_return result;
    }

    result.success = true;
    co_return result;
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

std::string select_socks_udp_host(const std::string& bind_host, boost::asio::ip::tcp::socket& control_socket)
{
    if (!bind_host.empty() && bind_host != "0.0.0.0" && bind_host != "::")
    {
        return bind_host;
    }

    boost::system::error_code remote_ec;
    const auto remote_endpoint = control_socket.remote_endpoint(remote_ec);
    if (remote_ec)
    {
        return bind_host;
    }
    return remote_endpoint.address().to_string();
}

void apply_bind_endpoint_result(udp_proxy_outbound_connect_result& result, const std::string& bind_host, const uint16_t bind_port)
{
    boost::system::error_code bind_ec;
    const auto bind_addr = boost::asio::ip::make_address(bind_host, bind_ec);
    if (bind_ec)
    {
        return;
    }

    result.bind_addr = socks_codec::normalize_ip_address(bind_addr);
    result.bind_port = bind_port;
    result.has_bind_endpoint = true;
}

boost::asio::awaitable<std::shared_ptr<boost::asio::ip::udp::socket>> open_socks_udp_socket(
    const boost::asio::any_io_executor& executor,
    const boost::asio::ip::udp::endpoint& udp_server_endpoint,
    const uint32_t connect_mark,
    boost::system::error_code& ec)
{
    auto udp_socket = std::make_shared<boost::asio::ip::udp::socket>(executor);
    ec = udp_socket->open(udp_server_endpoint.protocol(), ec);
    if (ec)
    {
        co_return nullptr;
    }

    if (connect_mark != 0)
    {
        net::set_socket_mark(udp_socket->native_handle(), connect_mark, ec);
        if (ec)
        {
            co_return nullptr;
        }
    }

    udp_socket->bind(boost::asio::ip::udp::endpoint(udp_server_endpoint.protocol(), 0), ec);
    if (ec)
    {
        co_return nullptr;
    }

    co_return udp_socket;
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

class reality_udp_proxy_outbound final : public udp_proxy_outbound
{
   public:
    reality_udp_proxy_outbound(std::shared_ptr<proxy_reality_connection> connection, const config& cfg)
        : udp_proxy_outbound(cfg), connection_(std::move(connection))
    {
    }

    boost::asio::awaitable<void> close() override
    {
        if (connection_ != nullptr)
        {
            boost::system::error_code ec;
            connection_->close(ec);
        }
        connection_.reset();
        co_return;
    }

    boost::asio::awaitable<void> send_datagram(
        const std::string& host, const uint16_t port, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec) override
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

    [[nodiscard]] boost::asio::awaitable<proxy::udp_datagram> receive_datagram(const uint32_t timeout_sec,
                                                                                boost::system::error_code& ec) override
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

   private:
    std::shared_ptr<proxy_reality_connection> connection_;
};

class socks_udp_proxy_outbound final : public udp_proxy_outbound
{
   public:
    socks_udp_proxy_outbound(std::shared_ptr<boost::asio::ip::tcp::socket> control_socket,
                             std::shared_ptr<boost::asio::ip::udp::socket> udp_socket,
                             boost::asio::ip::udp::endpoint udp_server_endpoint,
                             const config& cfg)
        : udp_proxy_outbound(cfg),
          control_socket_(std::move(control_socket)),
          udp_socket_(std::move(udp_socket)),
          udp_server_endpoint_(std::move(udp_server_endpoint))
    {
    }

    boost::asio::awaitable<void> close() override
    {
        if (control_socket_ != nullptr)
        {
            boost::system::error_code ec;
            ec = control_socket_->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            ec = control_socket_->close(ec);
        }
        control_socket_.reset();

        if (udp_socket_ != nullptr)
        {
            boost::system::error_code ec;
            ec = udp_socket_->close(ec);
        }
        udp_socket_.reset();
        co_return;
    }

    boost::asio::awaitable<void> send_datagram(
        const std::string& host, const uint16_t port, const uint8_t* payload, const std::size_t payload_len, boost::system::error_code& ec) override
    {
        if (udp_socket_ == nullptr)
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
        co_await send_udp_packet_with_timeout(*udp_socket_, udp_server_endpoint_, packet, cfg().timeout.write, ec);
    }

    [[nodiscard]] boost::asio::awaitable<proxy::udp_datagram> receive_datagram(const uint32_t timeout_sec,
                                                                                boost::system::error_code& ec) override
    {
        if (udp_socket_ == nullptr)
        {
            ec = boost::asio::error::not_connected;
            co_return proxy::udp_datagram{};
        }

        std::vector<uint8_t> packet(constants::udp::kMaxPacketSize);
        const auto normalized_server = net::normalize_endpoint(udp_server_endpoint_);
        for (;;)
        {
            boost::asio::ip::udp::endpoint sender;
            const auto packet_len = co_await receive_udp_packet_with_timeout(*udp_socket_, packet, sender, timeout_sec, ec);
            if (ec)
            {
                co_return proxy::udp_datagram{};
            }

            const auto normalized_sender = net::normalize_endpoint(sender);
            if (normalized_sender != normalized_server)
            {
                LOG_WARN("{} stage receive_udp_datagram ignore unexpected sender {}:{} expected {}:{}",
                         log_event::kRoute,
                         normalized_sender.address().to_string(),
                         normalized_sender.port(),
                         normalized_server.address().to_string(),
                         normalized_server.port());
                continue;
            }

            socks_udp_header header;
            if (!socks_codec::decode_udp_header(packet.data(), packet_len, header) || header.header_len > packet_len)
            {
                LOG_WARN("{} stage receive_udp_datagram invalid socks udp header sender {}:{} packet_size {}",
                         log_event::kRoute,
                         normalized_sender.address().to_string(),
                         normalized_sender.port(),
                         packet_len);
                ec = boost::asio::error::invalid_argument;
                co_return proxy::udp_datagram{};
            }
            if (header.frag != 0x00)
            {
                LOG_WARN("{} stage receive_udp_datagram ignore fragmented packet sender {}:{} frag {}",
                         log_event::kRoute,
                         normalized_sender.address().to_string(),
                         normalized_sender.port(),
                         header.frag);
                continue;
            }

            proxy::udp_datagram datagram;
            datagram.target_host = header.addr;
            datagram.target_port = header.port;
            datagram.payload.assign(packet.begin() + static_cast<std::ptrdiff_t>(header.header_len),
                                    packet.begin() + static_cast<std::ptrdiff_t>(packet_len));
            co_return datagram;
        }
    }

   private:
    std::shared_ptr<boost::asio::ip::tcp::socket> control_socket_;
    std::shared_ptr<boost::asio::ip::udp::socket> udp_socket_;
    boost::asio::ip::udp::endpoint udp_server_endpoint_;
};

}    // namespace

boost::asio::awaitable<udp_proxy_outbound_connect_result> udp_proxy_outbound::connect_reality_outbound(
    const boost::asio::any_io_executor& executor,
    const uint32_t conn_id,
    const uint64_t trace_id,
    const config& cfg,
    const config::outbound_entry_t& outbound,
    const uint32_t connect_mark)
{
    udp_proxy_outbound_connect_result result;
    result.socks_rep = socks::kRepSuccess;

    boost::system::error_code ec;
    auto connection = co_await proxy_reality_connection::connect(executor, cfg, outbound.tag, connect_mark, conn_id, ec);
    if (connection == nullptr)
    {
        set_connect_failure(result, ec ? ec : boost::asio::error::not_connected);
        co_return result;
    }

    auto upstream = std::make_shared<reality_udp_proxy_outbound>(connection, cfg);
    proxy::udp_associate_request request;
    request.trace_id = trace_id;
    std::vector<uint8_t> packet;
    if (!proxy::encode_udp_associate_request(request, packet))
    {
        set_connect_failure(result, boost::asio::error::message_size);
        co_return result;
    }
    co_await connection->write_packet(packet, ec);
    if (ec)
    {
        set_connect_failure(result, ec);
        co_return result;
    }

    const auto reply_packet = co_await connection->read_packet(upstream->associate_reply_timeout(), ec);
    if (ec)
    {
        set_connect_failure(result, ec);
        co_return result;
    }

    proxy::udp_associate_reply reply;
    if (!proxy::decode_udp_associate_reply(reply_packet.data(), reply_packet.size(), reply))
    {
        set_connect_failure(result, boost::asio::error::invalid_argument);
        co_return result;
    }

    result.socks_rep = reply.socks_rep;
    if (reply.socks_rep != socks::kRepSuccess)
    {
        set_connect_failure(result, socks::map_socks_rep_to_connect_error(reply.socks_rep));
        co_return result;
    }

    apply_bind_endpoint_result(result, reply.bind_host, reply.bind_port);
    if (result.has_bind_endpoint)
    {
        upstream->set_bind_endpoint(result.bind_addr.to_string(), result.bind_port);
    }
    result.outbound = std::move(upstream);
    co_return result;
}

boost::asio::awaitable<udp_proxy_outbound_connect_result> udp_proxy_outbound::connect_socks_outbound(
    const boost::asio::any_io_executor& executor,
    const uint32_t conn_id,
    const uint64_t trace_id,
    const config& cfg,
    const config::outbound_entry_t& outbound,
    const uint32_t connect_mark)
{
    (void)trace_id;
    udp_proxy_outbound_connect_result result;
    result.socks_rep = socks::kRepSuccess;

    if (!outbound.socks.has_value())
    {
        set_connect_failure(result, boost::asio::error::operation_not_supported);
        co_return result;
    }

    auto associate = co_await open_socks_udp_associate(executor, *outbound.socks, cfg, conn_id, outbound.tag, connect_mark);
    if (!associate.success)
    {
        result.socks_rep = associate.socks_rep;
        result.ec = associate.ec;
        if (result.socks_rep == socks::kRepSuccess)
        {
            result.socks_rep = socks::map_connect_error_to_socks_rep(result.ec);
        }
        co_return result;
    }

    boost::system::error_code ec;
    const auto udp_host = select_socks_udp_host(associate.bind_host, *associate.control_socket);
    auto udp_server_endpoint = co_await resolve_udp_endpoint(executor, udp_host, associate.bind_port, cfg, ec);
    if (ec)
    {
        set_connect_failure(result, ec);
        co_return result;
    }

    auto udp_socket = co_await open_socks_udp_socket(executor, udp_server_endpoint, connect_mark, ec);
    if (udp_socket == nullptr)
    {
        set_connect_failure(result, ec);
        co_return result;
    }

    auto upstream = std::make_shared<socks_udp_proxy_outbound>(associate.control_socket, udp_socket, udp_server_endpoint, cfg);
    upstream->set_bind_endpoint(associate.bind_host, associate.bind_port);
    apply_bind_endpoint_result(result, associate.bind_host, associate.bind_port);
    result.outbound = std::move(upstream);
    co_return result;
}

boost::asio::awaitable<udp_proxy_outbound_connect_result> udp_proxy_outbound::connect(const boost::asio::any_io_executor& executor,
                                                                                       const uint32_t conn_id,
                                                                                       const uint64_t trace_id,
                                                                                       const config& cfg,
                                                                                       const config::outbound_entry_t& outbound,
                                                                                       const uint32_t connect_mark)
{
    udp_proxy_outbound_connect_result result;
    result.socks_rep = socks::kRepSuccess;

    const auto outbound_kind = config_type::classify_proxy_outbound_type(outbound.type);
    if (outbound_kind == config_type::proxy_outbound_kind::kReality)
    {
        co_return co_await connect_reality_outbound(executor, conn_id, trace_id, cfg, outbound, connect_mark);
    }

    if (outbound_kind != config_type::proxy_outbound_kind::kSocks)
    {
        set_connect_failure(result, boost::asio::error::operation_not_supported);
        co_return result;
    }

    co_return co_await connect_socks_outbound(executor, conn_id, trace_id, cfg, outbound, connect_mark);
}

uint32_t udp_proxy_outbound::associate_reply_timeout() const
{
    if (cfg_.timeout.connect == 0)
    {
        return cfg_.timeout.read;
    }
    return std::max(cfg_.timeout.read, cfg_.timeout.connect + 1);
}

void udp_proxy_outbound::set_bind_endpoint(std::string host, const uint16_t port)
{
    bind_host_ = std::move(host);
    bind_port_ = port;
}

}    // namespace relay
