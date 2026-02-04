#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/as_tuple.hpp>
#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

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

udp_socks_session::udp_socks_session(asio::ip::tcp::socket socket,
                                     std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager,
                                     const uint32_t sid)
    : timer_(socket.get_executor()),
      socket_(std::move(socket)),
      udp_socket_(socket_.get_executor()),
      tunnel_manager_(std::move(tunnel_manager)),
      recv_channel_(socket_.get_executor(), 128)
{
    ctx_.new_trace_id();
    ctx_.conn_id(sid);
}

void udp_socks_session::start(const std::string& host, const uint16_t port)
{
    const auto self = shared_from_this();
    asio::co_spawn(socket_.get_executor(), [self, host, port]() -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
}

void udp_socks_session::on_data(std::vector<uint8_t> data) { recv_channel_.try_send(std::error_code(), std::move(data)); }

void udp_socks_session::on_close()
{
    recv_channel_.close();
    std::error_code ignore;
    ignore = udp_socket_.close(ignore);
    if (ignore)
    {
        LOG_CTX_WARN(ctx_, "{} close udp socket failed {}", log_event::SOCKS, ignore.message());
    }
}

void udp_socks_session::on_reset() { on_close(); }

asio::awaitable<void> udp_socks_session::run(const std::string& host, const uint16_t port)
{
    std::error_code ec;
    const auto tcp_local_ep = socket_.local_endpoint(ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} failed to get local endpoint {}", log_event::SOCKS, ec.message());
        co_return;
    }

    const auto local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
    const auto udp_protocol = local_addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4();

    ec = udp_socket_.open(udp_protocol, ec);
    if (!ec)
    {
        if (local_addr.is_v6())
        {
            ec = udp_socket_.set_option(asio::ip::v6_only(false), ec);
        }
        ec = udp_socket_.bind(asio::ip::udp::endpoint(local_addr, 0), ec);
    }

    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} bind failed {}", log_event::SOCKS, ec.message());
        uint8_t err[] = {socks::VER, socks::REP_GEN_FAIL, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
        co_return;
    }

    const auto udp_local_ep = udp_socket_.local_endpoint(ec);
    const uint16_t udp_bind_port = udp_local_ep.port();
    LOG_CTX_INFO(ctx_, "{} started bound at {} {}", log_event::SOCKS, local_addr.to_string(), udp_bind_port);

    const auto stream = tunnel_manager_->create_stream();
    if (stream == nullptr)
    {
        LOG_CTX_ERROR(ctx_, "{} failed to create stream", log_event::SOCKS);
        co_return;
    }

    const syn_payload syn{.socks_cmd = socks::CMD_UDP_ASSOCIATE, .addr = "0.0.0.0", .port = 0};
    std::vector<uint8_t> syn_data;
    mux_codec::encode_syn(syn, syn_data);
    ec = co_await tunnel_manager_->connection()->send_async(stream->id(), CMD_SYN, std::move(syn_data));
    if (ec)
    {
        LOG_CTX_WARN(ctx_, "{} syn failed {}", log_event::SOCKS, ec.message());
        co_await stream->close();
        co_return;
    }

    auto [ack_ec, ack_data] = co_await stream->async_read_some();
    if (ack_ec)
    {
        LOG_CTX_WARN(ctx_, "{} ack failed {}", log_event::SOCKS, ack_ec.message());
        co_await stream->close();
        co_return;
    }

    std::vector<uint8_t> final_rep;
    final_rep.reserve(22);
    final_rep.push_back(socks::VER);
    final_rep.push_back(socks::REP_SUCCESS);
    final_rep.push_back(0x00);

    if (local_addr.is_v4())
    {
        final_rep.push_back(socks::ATYP_IPV4);
        const auto bytes = local_addr.to_v4().to_bytes();
        final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
    }
    else
    {
        final_rep.push_back(socks::ATYP_IPV6);
        const auto bytes = local_addr.to_v6().to_bytes();
        final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
    }

    final_rep.push_back(static_cast<uint8_t>((udp_bind_port >> 8) & 0xFF));
    final_rep.push_back(static_cast<uint8_t>(udp_bind_port & 0xFF));

    const auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(final_rep), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        LOG_CTX_WARN(ctx_, "{} write failed {}", log_event::SOCKS, we.message());
        co_await stream->close();
        co_return;
    }

    const auto client_ep_ptr = std::make_shared<asio::ip::udp::endpoint>();

    tunnel_manager_->register_stream(stream->id(), shared_from_this());

    using asio::experimental::awaitable_operators::operator||;
    co_await (udp_sock_to_stream(stream, client_ep_ptr) || stream_to_udp_sock(stream, client_ep_ptr) || keep_tcp_alive());

    tunnel_manager_->remove_stream(stream->id());
    co_await stream->close();
    LOG_CTX_INFO(ctx_, "{} finished", log_event::SOCKS);
}

asio::awaitable<void> udp_socks_session::udp_sock_to_stream(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
{
    std::vector<uint8_t> buf(65535);
    asio::ip::udp::endpoint sender;
    for (;;)
    {
        const auto [recv_ec, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != asio::error::operation_aborted)
            {
                LOG_CTX_WARN(ctx_, "{} receive error {}", log_event::SOCKS, recv_ec.message());
            }
            break;
        }
        *client_ep = sender;

        socks_udp_header h;
        if (!socks_codec::decode_udp_header(buf.data(), n, h))
        {
            LOG_CTX_WARN(ctx_, "{} received invalid udp packet from {}", log_event::SOCKS, sender.address().to_string());
            continue;
        }

        if (h.frag != 0x00)
        {
            LOG_CTX_WARN(ctx_, "{} received a fragmented packet ignore it", log_event::SOCKS);
            continue;
        }

        if (const auto write_ec = co_await stream->async_write_some(buf.data(), n))
        {
            LOG_CTX_ERROR(ctx_, "{} write to stream failed {}", log_event::SOCKS, write_ec.message());
            break;
        }
    }
}

asio::awaitable<void> udp_socks_session::stream_to_udp_sock(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
{
    for (;;)
    {
        const auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
        if (ec || data.empty())
        {
            LOG_CTX_ERROR(ctx_, "{} recv error {}", log_event::SOCKS, ec.message());
            break;
        }

        if (client_ep->port() == 0)
        {
            LOG_CTX_WARN(ctx_, "{} client ep port is 0 ignore it", log_event::SOCKS);
            continue;
        }

        const auto [se, sn] = co_await udp_socket_.async_send_to(asio::buffer(data), *client_ep, asio::as_tuple(asio::use_awaitable));
        if (se)
        {
            LOG_CTX_ERROR(ctx_, "{} send error {}", log_event::SOCKS, se.message());
        }
    }
}

asio::awaitable<void> udp_socks_session::keep_tcp_alive()
{
    char b[1];
    const auto [ec, n] = co_await socket_.async_read_some(asio::buffer(b), asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_CTX_ERROR(ctx_, "{} keep tcp alive error {}", log_event::SOCKS, ec.message());
    }
}

}    // namespace mux