#ifndef UDP_SOCKS_SESSION_H
#define UDP_SOCKS_SESSION_H

#include <memory>
#include <vector>
#include <asio.hpp>
#include "log.h"
#include "protocol.h"
#include "mux_tunnel.h"

namespace mux
{

class udp_socks_session : public mux_stream_interface, public std::enable_shared_from_this<udp_socks_session>
{
   public:
    udp_socks_session(asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager, uint32_t sid)
        : sid_(sid),
          timer_(socket.get_executor()),
          socket_(std::move(socket)),
          udp_socket_(socket_.get_executor()),
          tunnel_manager_(std::move(tunnel_manager)),
          recv_channel_(socket_.get_executor(), 128)
    {
    }

    void start(const std::string& host, uint16_t port)
    {
        auto self = shared_from_this();
        asio::co_spawn(
            socket_.get_executor(), [self, host, port]() mutable -> asio::awaitable<void> { co_await self->run(host, port); }, asio::detached);
    }

   private:
    asio::awaitable<void> run(std::string host, uint16_t port)
    {
        std::error_code ec;
        auto tcp_local_ep = socket_.local_endpoint(ec);
        if (ec)
        {
            LOG_ERROR("{} failed to get local endpoint {}", sid_, ec.message());
            co_return;
        }

        auto local_addr = socks_codec::normalize_ip_address(tcp_local_ep.address());
        auto udp_protocol = local_addr.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4();

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
            LOG_ERROR("{} bind failed {}", sid_, ec.message());
            uint8_t err[] = {socks::VER, socks::REP_GEN_FAIL, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(socket_, asio::buffer(err), asio::as_tuple(asio::use_awaitable));
            co_return;
        }

        auto udp_local_ep = udp_socket_.local_endpoint(ec);
        uint16_t udp_bind_port = udp_local_ep.port();
        LOG_INFO("{} started bound at {}:{}", sid_, local_addr.to_string(), udp_bind_port);

        auto stream = tunnel_manager_->create_stream();
        if (!stream)
        {
            LOG_ERROR("{} failed to create stream", sid_);
            co_return;
        }

        const syn_payload syn{.socks_cmd = socks::CMD_UDP_ASSOCIATE, .addr = "0.0.0.0", .port = 0};
        ec = co_await tunnel_manager_->connection()->send_async(stream->id(), CMD_SYN, mux_codec::encode_syn(syn));
        if (ec)
        {
            LOG_ERROR("{} syn failed {}", sid_, ec.message());
            co_await stream->close();
            co_return;
        }

        auto [ack_ec, ack_data] = co_await stream->async_read_some();
        if (ack_ec)
        {
            LOG_ERROR("{} ack failed {}", sid_, ack_ec.message());
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
            auto bytes = local_addr.to_v4().to_bytes();
            final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
        }
        else
        {
            final_rep.push_back(socks::ATYP_IPV6);
            auto bytes = local_addr.to_v6().to_bytes();
            final_rep.insert(final_rep.end(), bytes.begin(), bytes.end());
        }

        final_rep.push_back(static_cast<uint8_t>((udp_bind_port >> 8) & 0xFF));
        final_rep.push_back(static_cast<uint8_t>(udp_bind_port & 0xFF));

        auto [we, wn] = co_await asio::async_write(socket_, asio::buffer(final_rep), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            LOG_ERROR("{} write failed {}", sid_, we.message());
            co_await stream->close();
            co_return;
        }

        auto client_ep_ptr = std::make_shared<asio::ip::udp::endpoint>();

        tunnel_manager_->register_stream(stream->id(), shared_from_this());

        using asio::experimental::awaitable_operators::operator||;
        co_await (udp_sock_to_stream(stream, client_ep_ptr) || stream_to_udp_sock(stream, client_ep_ptr) || keep_tcp_alive());

        tunnel_manager_->remove_stream(stream->id());
        co_await stream->close();
        LOG_INFO("{} finished", sid_);
    }

   public:
    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(std::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        std::error_code ignore;
        ignore = udp_socket_.close(ignore);
        if (ignore)
        {
            LOG_WARN("{} close udp socket failed {}", sid_, ignore.message());
        }
    }
    void on_reset() override { on_close(); }

   private:
    asio::awaitable<void> udp_sock_to_stream(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
    {
        std::vector<uint8_t> buf(65535);
        asio::ip::udp::endpoint sender;
        for (;;)
        {
            auto [ec, n] = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, asio::as_tuple(asio::use_awaitable));
            if (ec)
            {
                if (ec != asio::error::operation_aborted)
                {
                    LOG_WARN("{} receive error {}", sid_, ec.message());
                }
                break;
            }
            *client_ep = sender;

            socks_udp_header h;
            if (h.frag != 0x00)
            {
                LOG_WARN("{} received a fragmented packet, ignore it", sid_);
                continue;
            }

            ec = co_await stream->async_write_some(buf.data(), n);
            if (ec)
            {
                LOG_ERROR("{} write to stream failed {}", sid_, ec.message());
                break;
            }
        }
    }

    asio::awaitable<void> stream_to_udp_sock(std::shared_ptr<mux_stream> stream, std::shared_ptr<asio::ip::udp::endpoint> client_ep)
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec || data.empty())
            {
                LOG_ERROR("{} recv error {}", sid_, ec.message());
                break;
            }

            if (client_ep->port() == 0)
            {
                LOG_WARN("{} client ep port is 0, ignore it", sid_);
                continue;
            }

            auto [se, sn] = co_await udp_socket_.async_send_to(asio::buffer(data), *client_ep, asio::as_tuple(asio::use_awaitable));
            if (se)
            {
                LOG_ERROR("{} send error {}", sid_, se.message());
            }
        }
    }

    asio::awaitable<void> keep_tcp_alive()
    {
        char b[1];
        auto [ec, n] = co_await socket_.async_read_some(asio::buffer(b), asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("{} keep tcp alive error {}", sid_, ec.message());
        }
    }

   private:
    uint32_t sid_;
    asio::steady_timer timer_;
    asio::ip::tcp::socket socket_;
    asio::ip::udp::socket udp_socket_;
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel_manager_;
    asio::experimental::concurrent_channel<void(std::error_code, std::vector<uint8_t>)> recv_channel_;
};

}    // namespace mux

#endif
