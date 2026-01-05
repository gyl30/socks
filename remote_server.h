#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/as_tuple.hpp>
#include <memory>
#include <vector>
#include "mux_tunnel.h"
#include "mux_protocol.h"
#include "context_pool.h"
#include "log.h"

namespace mux
{

class RemoteSession : public std::enable_shared_from_this<RemoteSession>
{
   public:
    RemoteSession(std::shared_ptr<MuxTunnel> tunnel, std::uint32_t stream_id, boost::asio::any_io_executor ex)
        : tunnel_(tunnel), stream_id_(stream_id), executor_(ex), resolver_(ex)
    {
    }

    boost::asio::awaitable<void> start(std::vector<std::uint8_t> syn_data)
    {
        auto self = shared_from_this();
        syn_payload req;
        if (!syn_payload::decode(syn_data.data(), syn_data.size(), req))
        {
            LOG_WARN("RemoteSession decode syn payload failed");
            co_return;
        }

        LOG_INFO("session {} req: cmd={} target={}:{}", stream_id_, req.socks_cmd, req.addr, req.port);

        stream_ = tunnel_->accept_stream(stream_id_);
        if (!stream_)
        {
            LOG_WARN("RemoteSession accept_stream failed or tunnel closed");
            co_return;
        }

        if (req.socks_cmd == 0x01)
            co_await do_connect(req.addr, req.port);
        else if (req.socks_cmd == 0x03)
            co_await do_udp_associate(req.addr, req.port);
        else
        {
            LOG_WARN("RemoteSession unknown cmd {}", req.socks_cmd);
            co_await send_ack(0x07, "0.0.0.0", 0);
            co_await stream_->close();
        }
    }

   private:
    boost::asio::awaitable<void> do_connect(const std::string& host, std::uint16_t port)
    {
        auto tcp_socket = std::make_shared<boost::asio::ip::tcp::socket>(executor_);
        bool connected = false;
        std::string error_msg;

        auto [ec, eps] = co_await resolver_.async_resolve(host, std::to_string(port), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec)
        {
            auto [ec2, ep] = co_await boost::asio::async_connect(*tcp_socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec2)
            {
                boost::system::error_code ec_opt;
                tcp_socket->set_option(boost::asio::ip::tcp::no_delay(true), ec_opt);
                connected = true;
            }
            else
            {
                error_msg = ec2.message();
            }
        }
        else
        {
            error_msg = ec.message();
        }

        if (!connected)
        {
            LOG_WARN("session {} connect failed: {}", stream_id_, error_msg);
            co_await send_ack(0x04, "0.0.0.0", 0);
            co_await stream_->close();
            co_return;
        }

        auto local_ep = tcp_socket->local_endpoint();
        co_await send_ack(0x00, local_ep.address().to_string(), local_ep.port());

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer_tcp_to_stream(tcp_socket) || transfer_stream_to_tcp(tcp_socket));

        tcp_socket->close();
        co_await stream_->close();
    }

    boost::asio::awaitable<void> send_ack(std::uint8_t rep, std::string addr, std::uint16_t port)
    {
        ack_payload ack{rep, addr, port};
        auto buf = ack.encode();
        frame_header h{stream_id_, (uint16_t)buf.size(), CMD_ACK};
        auto ec = co_await tunnel_->send_frame(h, std::move(buf));
        if (ec)
            LOG_WARN("send_ack failed: {}", ec.message());
    }

    boost::asio::awaitable<void> transfer_tcp_to_stream(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    {
        std::vector<std::uint8_t> data(16384);
        while (true)
        {
            auto [ec, n] = co_await sock->async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted)
                    LOG_WARN("transfer_tcp_to_stream read error: {}", ec.message());
                break;
            }

            data.resize(n);
            if (auto e = co_await stream_->send_data(std::move(data)))
            {
                LOG_WARN("transfer_tcp_to_stream send error: {}", e.message());
                break;
            }

            data.resize(16384);
        }
    }

    boost::asio::awaitable<void> transfer_stream_to_tcp(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    {
        while (true)
        {
            auto [ec, data] = co_await stream_->async_read_some();
            if (ec)
            {
                if (ec != boost::asio::experimental::error::channel_closed)
                    LOG_WARN("transfer_stream_to_tcp read error: {}", ec.message());
                break;
            }
            if (data.empty())
                break;

            auto [e2, n] = co_await boost::asio::async_write(*sock, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
            {
                LOG_WARN("transfer_stream_to_tcp write error: {}", e2.message());
                break;
            }
        }
    }

    boost::asio::awaitable<void> do_udp_associate(const std::string&, std::uint16_t)
    {
        auto udp_socket = std::make_shared<boost::asio::ip::udp::socket>(executor_, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0));
        co_await send_ack(0x00, "0.0.0.0", udp_socket->local_endpoint().port());

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer_udp_to_stream(udp_socket) || transfer_stream_to_udp(udp_socket));

        udp_socket->close();
        co_await stream_->close();
    }

    boost::asio::awaitable<void> transfer_stream_to_udp(std::shared_ptr<boost::asio::ip::udp::socket> udp_sock)
    {
        while (true)
        {
            auto [ec, data] = co_await stream_->async_read_some();
            if (ec)
            {
                if (ec != boost::asio::experimental::error::channel_closed)
                    LOG_WARN("transfer_stream_to_udp read error: {}", ec.message());
                break;
            }
            if (data.empty())
                break;

            if (data.size() < 10 || data[2] != 0x00)
                continue;

            std::size_t header_len = 0;
            boost::asio::ip::udp::endpoint target;
            std::uint8_t atyp = data[3];

            if (atyp == 0x01)
            {
                boost::asio::ip::address_v4::bytes_type b;
                std::memcpy(b.data(), &data[4], 4);
                std::uint16_t p;
                std::memcpy(&p, &data[8], 2);
                target = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(b), ntohs(p));
                header_len = 10;
            }
            else
            {
                LOG_WARN("transfer_stream_to_udp unsupported atyp: {}", atyp);
                continue;
            }

            auto [e2, n] = co_await udp_sock->async_send_to(
                boost::asio::buffer(data.data() + header_len, data.size() - header_len), target, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
            {
                LOG_WARN("transfer_stream_to_udp send error: {}", e2.message());
                break;
            }
        }
    }

    boost::asio::awaitable<void> transfer_udp_to_stream(std::shared_ptr<boost::asio::ip::udp::socket> udp_sock)
    {
        std::vector<std::uint8_t> buf(65536);
        boost::asio::ip::udp::endpoint sender;
        while (true)
        {
            auto [ec, len] =
                co_await udp_sock->async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                    LOG_WARN("transfer_udp_to_stream recv error: {}", ec.message());
                break;
            }

            std::vector<std::uint8_t> packet;
            packet.reserve(len + 10);
            packet.push_back(0);
            packet.push_back(0);
            packet.push_back(0);
            packet.push_back(0x01);
            auto b = sender.address().to_v4().to_bytes();
            packet.insert(packet.end(), b.begin(), b.end());
            std::uint16_t p = htons(sender.port());
            const std::uint8_t* pp = reinterpret_cast<const std::uint8_t*>(&p);
            packet.push_back(pp[0]);
            packet.push_back(pp[1]);
            packet.insert(packet.end(), buf.begin(), buf.begin() + len);

            if (auto e = co_await stream_->send_data(std::move(packet)))
            {
                LOG_WARN("transfer_udp_to_stream send error: {}", e.message());
                break;
            }
        }
    }

    std::shared_ptr<MuxTunnel> tunnel_;
    std::shared_ptr<MuxStream> stream_;
    std::uint32_t stream_id_;
    boost::asio::any_io_executor executor_;
    boost::asio::ip::tcp::resolver resolver_;
};

class RemoteServer
{
   public:
    RemoteServer(io_context_pool& pool, std::uint16_t port)
        : pool_(pool), acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port))
    {
    }

    void start()
    {
        boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached);
        LOG_INFO("remote server listening on port {}", acceptor_.local_endpoint().port());
    }

   private:
    boost::asio::awaitable<void> accept_loop()
    {
        while (true)
        {
            boost::asio::ip::tcp::socket socket(acceptor_.get_executor());

            auto [ec] = co_await acceptor_.async_accept(socket, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_WARN("server accept failed: {}", ec.message());
                continue;
            }

            auto tunnel = std::make_shared<MuxTunnel>(std::move(socket));
            tunnel->set_syn_handler(
                [this, tunnel](std::uint32_t stream_id, std::vector<std::uint8_t> payload) -> boost::asio::awaitable<void>
                {
                    auto& session_ctx = pool_.get_io_context();
                    auto session = std::make_shared<RemoteSession>(tunnel, stream_id, session_ctx.get_executor());
                    boost::asio::co_spawn(
                        session_ctx, [session, p = std::move(payload)]() mutable { return session->start(std::move(p)); }, boost::asio::detached);
                    co_return;
                });
            boost::asio::co_spawn(acceptor_.get_executor(), tunnel->run(), boost::asio::detached);
        }
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
};

}    // namespace mux

#endif
