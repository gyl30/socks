#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/as_tuple.hpp>
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include "mux_tunnel.h"
#include "mux_protocol.h"
#include "protocol.h"
#include "log.h"
#include "context_pool.h"

namespace mux
{

class local_session : public std::enable_shared_from_this<local_session>
{
   public:
    local_session(boost::asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel> tunnel)
        : socket_(std::move(socket)), tunnel_(tunnel), udp_socket_(socket_.get_executor())
    {
        boost::system::error_code ec;
        socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("local_session set nodelay error {}", ec.message());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> start()
    {
        auto self = shared_from_this();

        if (!co_await handshake())
        {
            co_return;
        }

        auto [ec, cmd, addr, port] = co_await read_request();
        if (ec)
        {
            LOG_WARN("read_request failed {}", ec.message());
            co_return;
        }

        if (cmd == socks::CMD_CONNECT)
        {
            co_await connect_remote(cmd, addr, port);
        }
        else if (cmd == socks::CMD_UDP_ASSOCIATE)
        {
            co_await setup_udp_associate(addr, port);
        }
        else
        {
            LOG_WARN("unsupported command {}", cmd);
            co_await reply_browser(socks::REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0);
        }
    }

   private:
    [[nodiscard]] boost::asio::awaitable<bool> handshake()
    {
        std::uint8_t version = 0;
        auto [ec1, n1] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec1)
        {
            LOG_WARN("handshake read ver error {}", ec1.message());
            co_return false;
        }
        if (version != socks::VER)
        {
            LOG_WARN("handshake invalid ver {}", version);
            co_return false;
        }

        std::uint8_t nmethods = 0;
        auto [ec2, n2] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
        {
            LOG_WARN("handshake read nmethods error {}", ec2.message());
            co_return false;
        }

        std::vector<std::uint8_t> methods(nmethods);
        auto [ec3, n3] = co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
        {
            LOG_WARN("handshake read methods error {}", ec3.message());
            co_return false;
        }

        const std::uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [ec4, n4] = co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec4)
        {
            LOG_WARN("handshake write response error {}", ec4.message());
            co_return false;
        }
        co_return true;
    }

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::uint8_t, std::string, std::uint16_t>> read_request()
    {
        std::uint8_t head[4];
        auto [ec1, n1] = co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec1)
        {
            co_return std::make_tuple(ec1, 0, "", 0);
        }

        const std::uint8_t cmd = head[1];
        const std::uint8_t atyp = head[3];
        std::string host;
        std::uint16_t port = 0;

        if (atyp == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                co_return std::make_tuple(ec, 0, "", 0);
            }
            host = boost::asio::ip::address_v4(bytes).to_string();
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            std::uint8_t len = 0;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                co_return std::make_tuple(ec, 0, "", 0);
            }
            host.resize(len);
            auto [ec2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
            {
                co_return std::make_tuple(ec2, 0, "", 0);
            }
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                co_return std::make_tuple(ec, 0, "", 0);
            }
            host = boost::asio::ip::address_v6(bytes).to_string();
        }
        else
        {
            LOG_WARN("read_request unsupported atyp {}", atyp);
            co_return std::make_tuple(boost::asio::error::invalid_argument, 0, "", 0);
        }

        auto [ec_p, n_p] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&port, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_p)
        {
            co_return std::make_tuple(ec_p, 0, "", 0);
        }
        port = ntohs(port);

        co_return std::make_tuple(boost::system::error_code(), cmd, host, port);
    }

    [[nodiscard]] boost::asio::awaitable<void> connect_remote(std::uint8_t cmd, const std::string& host, std::uint16_t port)
    {
        auto stream = tunnel_->create_stream();
        LOG_INFO("creating stream {} for target {}:{}", stream->id(), host, port);

        SynPayload syn;
        syn.socks_cmd = cmd;
        syn.addr = host;
        syn.port = port;
        auto syn_buf = syn.encode();

        {
            FrameHeader h;
            h.stream_id = stream->id();
            h.length = static_cast<std::uint16_t>(syn_buf.size());
            h.command = mux::CMD_SYN;
            auto ec = co_await tunnel_->send_frame(h, std::move(syn_buf));
            if (ec)
            {
                LOG_WARN("connect_remote send syn failed {}", ec.message());
                co_return;
            }
        }

        auto [ec_read, ack_buf] = co_await stream->async_read_some();
        if (ec_read || ack_buf.empty())
        {
            LOG_WARN("connect_remote read ack failed/empty {}", ec_read.message());
            co_return;
        }

        AckPayload ack;
        if (!AckPayload::decode(ack_buf.data(), ack_buf.size(), ack))
        {
            LOG_WARN("connect_remote decode ack failed");
            co_return;
        }

        if (ack.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("remote refused stream {} rep {}", stream->id(), ack.socks_rep);
            co_await reply_browser(ack.socks_rep, "0.0.0.0", 0);
            co_return;
        }

        co_await reply_browser(socks::REP_SUCCESS, "0.0.0.0", 0);

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer_socket_to_stream(stream) || transfer_stream_to_socket(stream));

        socket_.close();
        co_await stream->close();
    }

    [[nodiscard]] boost::asio::awaitable<void> setup_udp_associate(const std::string& client_host, std::uint16_t client_port)
    {
        boost::system::error_code ec;
        udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
        {
            LOG_WARN("udp open failed {}", ec.message());
            co_return;
        }
        udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        if (ec)
        {
            LOG_WARN("udp bind failed {}", ec.message());
            co_return;
        }

        auto stream = tunnel_->create_stream();

        SynPayload syn;
        syn.socks_cmd = socks::CMD_UDP_ASSOCIATE;
        syn.addr = client_host;
        syn.port = client_port;
        auto syn_buf = syn.encode();

        {
            FrameHeader h;
            h.stream_id = stream->id();
            h.length = static_cast<std::uint16_t>(syn_buf.size());
            h.command = mux::CMD_SYN;
            if (auto e = co_await tunnel_->send_frame(h, std::move(syn_buf)))
            {
                LOG_WARN("udp setup send syn failed {}", e.message());
                co_return;
            }
        }

        auto [ec_ack, ack_buf] = co_await stream->async_read_some();
        if (ec_ack || ack_buf.empty())
        {
            LOG_WARN("udp setup read ack failed {}", ec_ack.message());
            co_return;
        }

        AckPayload ack;
        if (!AckPayload::decode(ack_buf.data(), ack_buf.size(), ack))
        {
            LOG_WARN("udp setup decode ack failed");
            co_return;
        }

        if (ack.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("udp remote refused {}", ack.socks_rep);
            co_await reply_browser(ack.socks_rep, "0.0.0.0", 0);
            co_return;
        }

        std::string local_ip = "0.0.0.0";
        if (socket_.local_endpoint().address().is_v4())
        {
            local_ip = socket_.local_endpoint().address().to_string();
        }

        co_await reply_browser(socks::REP_SUCCESS, local_ip, udp_socket_.local_endpoint().port());

        using boost::asio::experimental::awaitable_operators::operator||;

        co_await (transfer_udp_to_stream(stream) || transfer_stream_to_udp(stream) || tcp_keepalive());

        udp_socket_.close();
        socket_.close();
        co_await stream->close();
    }

    [[nodiscard]] boost::asio::awaitable<void> tcp_keepalive()
    {
        char buf[1];
        while (true)
        {
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                break;
            }
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_udp_to_stream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<std::uint8_t> buf(65536);
        boost::asio::ip::udp::endpoint sender;
        while (true)
        {
            auto [ec, n] =
                co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("transfer_udp_to_stream recv failed {}", ec.message());
                }
                break;
            }

            if (client_ep_ != sender)
            {
                client_ep_ = sender;
            }

            std::vector<std::uint8_t> payload(buf.begin(), buf.begin() + n);
            if (auto e = co_await stream->send_data(std::move(payload)))
            {
                LOG_WARN("transfer_udp_to_stream send failed {}", e.message());
                break;
            }
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_udp(std::shared_ptr<mux_stream> stream)
    {
        while (true)
        {
            auto [ec, payload] = co_await stream->async_read_some();
            if (ec)
            {
                if (ec != boost::asio::experimental::error::channel_closed)
                {
                    LOG_WARN("transfer_stream_to_udp read failed {}", ec.message());
                }
                break;
            }
            if (payload.empty())
            {
                break;
            }

            if (client_ep_.port() != 0)
            {
                auto [e, n] =
                    co_await udp_socket_.async_send_to(boost::asio::buffer(payload), client_ep_, boost::asio::as_tuple(boost::asio::use_awaitable));
                if (e)
                {
                    LOG_WARN("transfer_stream_to_udp send failed {}", e.message());
                    break;
                }
            }
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> reply_browser(std::uint8_t rep, std::string bound_ip, std::uint16_t bound_port)
    {
        std::vector<std::uint8_t> resp = {socks::VER, rep, 0x00, socks::ATYP_IPV4};
        boost::system::error_code ec;
        auto addr = boost::asio::ip::make_address_v4(bound_ip, ec);
        if (ec)
        {
            addr = boost::asio::ip::address_v4::any();
        }

        auto bytes = addr.to_bytes();
        resp.insert(resp.end(), bytes.begin(), bytes.end());

        const std::uint16_t p = htons(bound_port);
        const auto* pp = reinterpret_cast<const std::uint8_t*>(&p);
        resp.push_back(pp[0]);
        resp.push_back(pp[1]);
        auto [we, n] = co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            LOG_WARN("reply_browser failed {}", we.message());
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_socket_to_stream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<std::uint8_t> data(16384);
        while (true)
        {
            auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("transfer_socket_to_stream read failed {}", ec.message());
                }
                break;
            }

            data.resize(n);
            if (auto e = co_await stream->send_data(std::move(data)))
            {
                LOG_WARN("transfer_socket_to_stream send failed {}", e.message());
                break;
            }

            data.resize(16384);
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_socket(std::shared_ptr<mux_stream> stream)
    {
        while (true)
        {
            auto [ec, payload] = co_await stream->async_read_some();
            if (ec)
            {
                if (ec != boost::asio::experimental::error::channel_closed)
                {
                    LOG_WARN("transfer_stream_to_socket read failed {}", ec.message());
                }
                break;
            }
            if (payload.empty())
            {
                break;
            }

            auto [e2, n] =
                co_await boost::asio::async_write(socket_, boost::asio::buffer(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
            {
                LOG_WARN("transfer_stream_to_socket write failed {}", e2.message());
                break;
            }
        }
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel> tunnel_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::endpoint client_ep_;
};

class local_client
{
   public:
    local_client(io_context_pool& pool, const std::string& remote_host, const std::string& remote_port, std::uint16_t local_port)
        : pool_(pool),
          remote_host_(remote_host),
          remote_port_(remote_port),
          local_port_(local_port),
          acceptor_(pool_.get_io_context()),
          ssl_context_(boost::asio::ssl::context::tlsv13_client)
    {
        ssl_context_.set_verify_mode(boost::asio::ssl::verify_none);
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), run(), boost::asio::detached); }

   private:
    [[nodiscard]] boost::asio::awaitable<void> run()
    {
        boost::asio::ip::tcp::resolver resolver(acceptor_.get_executor());
        auto [ec, endpoints] = co_await resolver.async_resolve(remote_host_, remote_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("resolve remote failed {}", ec.message());
            co_return;
        }

        boost::asio::ip::tcp::socket socket(acceptor_.get_executor());
        auto [ec2, ep] = co_await boost::asio::async_connect(socket, endpoints, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
        {
            LOG_ERROR("connect remote failed {}", ec2.message());
            co_return;
        }

        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_stream(std::move(socket), ssl_context_);

        if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(), "apple.com"))
        {
            LOG_ERROR("failed to set sni");
            co_return;
        }

        auto [ec3] = co_await ssl_stream.async_handshake(boost::asio::ssl::stream_base::client, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
        {
            LOG_ERROR("ssl handshake failed {}", ec3.message());
            co_return;
        }

        tunnel_ = std::make_shared<mux_tunnel>(std::move(ssl_stream));
        boost::asio::co_spawn(acceptor_.get_executor(), tunnel_->run(), boost::asio::detached);

        boost::asio::ip::tcp::endpoint local_ep(boost::asio::ip::tcp::v4(), local_port_);
        boost::system::error_code be;
        acceptor_.open(local_ep.protocol(), be);
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), be);
        acceptor_.bind(local_ep, be);
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, be);

        if (be)
        {
            LOG_ERROR("acceptor bind/listen failed {}", be.message());
            co_return;
        }

        LOG_INFO("local client listening on {}", local_port_);

        while (true)
        {
            auto& client_ctx = pool_.get_io_context();
            boost::asio::ip::tcp::socket peer(client_ctx);
            auto [ec_acc] = co_await acceptor_.async_accept(peer, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_acc)
            {
                LOG_WARN("accept failed {}", ec_acc.message());
                continue;
            }

            auto session = std::make_shared<local_session>(std::move(peer), tunnel_);
            boost::asio::co_spawn(
                client_ctx, [session]() { return session->start(); }, boost::asio::detached);
        }
    }

    io_context_pool& pool_;
    std::string remote_host_;
    std::string remote_port_;
    std::uint16_t local_port_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_context_;
    std::shared_ptr<mux_tunnel> tunnel_;
};

}    // namespace mux

#endif
