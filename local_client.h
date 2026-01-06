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
#include <chrono>
#include <cstdlib>
#include <openssl/ssl.h>
#include "mux_tunnel.h"
#include "mux_protocol.h"
#include "protocol.h"
#include "log.h"
#include "context_pool.h"
#include "reality_core.h"

namespace mux
{

std::vector<uint8_t> hex_to_bytes(const std::string& hex)
{
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

template <typename NextLayer>
class SessionIdPatcherStream
{
   public:
    using executor_type = typename NextLayer::executor_type;
    using lowest_layer_type = typename NextLayer::lowest_layer_type;

    SessionIdPatcherStream(NextLayer next, std::vector<uint8_t> target_id) : next_layer_(std::move(next)), target_id_(std::move(target_id)) {}

    executor_type get_executor() { return next_layer_.get_executor(); }
    lowest_layer_type& lowest_layer() { return next_layer_.lowest_layer(); }

    template <typename ConstBufferSequence, typename WriteToken>
    auto async_write_some(const ConstBufferSequence& buffers, WriteToken&& token)
    {
        return boost::asio::async_initiate<WriteToken, void(boost::system::error_code, size_t)>(
            [this](auto handler, const ConstBufferSequence& buffers)
            {
                if (!patched_)
                {
                    std::vector<uint8_t> data;
                    size_t total_size = boost::asio::buffer_size(buffers);
                    data.resize(total_size);
                    boost::asio::buffer_copy(boost::asio::buffer(data), buffers);

                    if (data.size() > 44 && data[0] == 0x16 && data[5] == 0x01)
                    {
                        uint8_t sid_len = data[43];

                        if (sid_len != 32)
                        {
                            LOG_WARN("ClientHello generated with SessionID len: {} (Needs 32 to patch)", sid_len);
                        }
                        else
                        {
                            LOG_INFO("Patching ClientHello SessionID with REALITY payload");
                            std::memcpy(&data[44], target_id_.data(), 32);

                            auto data_ptr = std::make_shared<std::vector<uint8_t>>(std::move(data));
                            next_layer_.async_write_some(boost::asio::buffer(*data_ptr),
                                                         [handler = std::move(handler), data_ptr](boost::system::error_code ec, size_t n) mutable
                                                         { handler(ec, n); });
                            patched_ = true;
                            return;
                        }
                    }
                    patched_ = true;
                }

                next_layer_.async_write_some(buffers, std::move(handler));
            },
            token,
            buffers);
    }

    template <typename MutableBufferSequence, typename ReadToken>
    auto async_read_some(const MutableBufferSequence& buffers, ReadToken&& token)
    {
        return next_layer_.async_read_some(buffers, std::forward<ReadToken>(token));
    }

   private:
    NextLayer next_layer_;
    std::vector<uint8_t> target_id_;
    bool patched_ = false;
};

class local_session : public std::enable_shared_from_this<local_session>
{
   public:
    local_session(boost::asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_interface> tunnel)
        : socket_(std::move(socket)), tunnel_(tunnel), udp_socket_(socket_.get_executor())
    {
        boost::system::error_code ec;
        socket_.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    }

    [[nodiscard]] boost::asio::awaitable<void> start()
    {
        if (!co_await handshake())
            co_return;
        auto [ec, cmd, addr, port] = co_await read_request();
        if (ec)
            co_return;

        if (cmd == socks::CMD_CONNECT)
            co_await connect_remote(cmd, addr, port);
        else if (cmd == socks::CMD_UDP_ASSOCIATE)
            co_await setup_udp_associate(addr, port);
        else
            co_await reply_browser(socks::REP_CMD_NOT_SUPPORTED, "0.0.0.0", 0);
    }

   private:
    [[nodiscard]] boost::asio::awaitable<bool> handshake()
    {
        std::uint8_t version = 0;
        auto [ec1, n1] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec1 || version != socks::VER)
            co_return false;

        std::uint8_t nmethods = 0;
        auto [ec2, n2] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
            co_return false;

        std::vector<std::uint8_t> methods(nmethods);
        auto [ec3, n3] = co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
            co_return false;

        const std::uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [ec4, n4] = co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec4)
            co_return false;
        co_return true;
    }

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::uint8_t, std::string, std::uint16_t>> read_request()
    {
        std::uint8_t head[4];
        auto [ec1, n1] = co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec1)
            co_return std::make_tuple(ec1, 0, "", 0);

        const std::uint8_t cmd = head[1];
        const std::uint8_t atyp = head[3];
        std::string host;
        std::uint16_t port = 0;

        if (atyp == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                co_return std::make_tuple(ec, 0, "", 0);
            host = boost::asio::ip::address_v4(bytes).to_string();
        }
        else if (atyp == socks::ATYP_DOMAIN)
        {
            std::uint8_t len = 0;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                co_return std::make_tuple(ec, 0, "", 0);
            host.resize(len);
            auto [ec2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
                co_return std::make_tuple(ec2, 0, "", 0);
        }
        else if (atyp == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                co_return std::make_tuple(ec, 0, "", 0);
            host = boost::asio::ip::address_v6(bytes).to_string();
        }
        else
        {
            co_return std::make_tuple(boost::asio::error::invalid_argument, 0, "", 0);
        }

        auto [ec_p, n_p] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&port, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_p)
            co_return std::make_tuple(ec_p, 0, "", 0);
        port = ntohs(port);

        co_return std::make_tuple(boost::system::error_code(), cmd, host, port);
    }

    [[nodiscard]] boost::asio::awaitable<void> connect_remote(std::uint8_t cmd, const std::string& host, std::uint16_t port)
    {
        auto stream = tunnel_->create_stream();
        SynPayload syn;
        syn.socks_cmd = cmd;
        syn.addr = host;
        syn.port = port;
        auto syn_buf = syn.encode();

        {
            FrameHeader h{stream->id(), static_cast<std::uint16_t>(syn_buf.size()), mux::CMD_SYN};
            if (auto ec = co_await tunnel_->send_frame(h, std::move(syn_buf)))
                co_return;
        }

        auto [ec_read, ack_buf] = co_await stream->async_read_some();
        if (ec_read || ack_buf.empty())
            co_return;

        AckPayload ack;
        if (!AckPayload::decode(ack_buf.data(), ack_buf.size(), ack))
            co_return;

        if (ack.socks_rep != socks::REP_SUCCESS)
        {
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
            co_return;
        udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        if (ec)
            co_return;

        auto stream = tunnel_->create_stream();
        SynPayload syn;
        syn.socks_cmd = socks::CMD_UDP_ASSOCIATE;
        syn.addr = client_host;
        syn.port = client_port;
        auto syn_buf = syn.encode();

        {
            FrameHeader h{stream->id(), static_cast<std::uint16_t>(syn_buf.size()), mux::CMD_SYN};
            if (auto e = co_await tunnel_->send_frame(h, std::move(syn_buf)))
                co_return;
        }

        auto [ec_ack, ack_buf] = co_await stream->async_read_some();
        if (ec_ack || ack_buf.empty())
            co_return;

        AckPayload ack;
        if (!AckPayload::decode(ack_buf.data(), ack_buf.size(), ack))
            co_return;

        if (ack.socks_rep != socks::REP_SUCCESS)
        {
            co_await reply_browser(ack.socks_rep, "0.0.0.0", 0);
            co_return;
        }

        std::string local_ip = socket_.local_endpoint().address().to_string();
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
                break;
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
                break;
            if (client_ep_ != sender)
                client_ep_ = sender;
            std::vector<std::uint8_t> payload(buf.begin(), buf.begin() + n);
            if (auto e = co_await stream->send_data(std::move(payload)))
                break;
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_udp(std::shared_ptr<mux_stream> stream)
    {
        while (true)
        {
            auto [ec, payload] = co_await stream->async_read_some();
            if (ec || payload.empty())
                break;
            if (client_ep_.port() != 0)
            {
                auto [e, n] =
                    co_await udp_socket_.async_send_to(boost::asio::buffer(payload), client_ep_, boost::asio::as_tuple(boost::asio::use_awaitable));
                if (e)
                    break;
            }
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> reply_browser(std::uint8_t rep, std::string bound_ip, std::uint16_t bound_port)
    {
        std::vector<std::uint8_t> resp = {socks::VER, rep, 0x00, socks::ATYP_IPV4};
        boost::system::error_code ec;
        auto addr = boost::asio::ip::make_address_v4(bound_ip, ec);
        if (ec)
            addr = boost::asio::ip::address_v4::any();
        auto bytes = addr.to_bytes();
        resp.insert(resp.end(), bytes.begin(), bytes.end());
        const std::uint16_t p = htons(bound_port);
        const auto* pp = reinterpret_cast<const std::uint8_t*>(&p);
        resp.push_back(pp[0]);
        resp.push_back(pp[1]);
        co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_socket_to_stream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<std::uint8_t> data(16384);
        while (true)
        {
            auto [ec, n] = co_await socket_.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                break;
            data.resize(n);
            if (auto e = co_await stream->send_data(std::move(data)))
                break;
            data.resize(16384);
        }
    }

    [[nodiscard]] boost::asio::awaitable<void> transfer_stream_to_socket(std::shared_ptr<mux_stream> stream)
    {
        while (true)
        {
            auto [ec, payload] = co_await stream->async_read_some();
            if (ec || payload.empty())
                break;
            auto [e2, n] =
                co_await boost::asio::async_write(socket_, boost::asio::buffer(payload), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
                break;
        }
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::endpoint client_ep_;
};

class local_client
{
   public:
    local_client(
        io_context_pool& pool, const std::string& remote_host, const std::string& remote_port, uint16_t local_port, const std::string& auth_key_hex)
        : pool_(pool),
          remote_host_(remote_host),
          remote_port_(remote_port),
          local_port_(local_port),
          acceptor_(pool_.get_io_context()),
          ssl_context_(boost::asio::ssl::context::tlsv13_client)
    {
        ssl_context_.set_verify_mode(boost::asio::ssl::verify_none);

        SSL_CTX_set_options(ssl_context_.native_handle(), SSL_OP_NO_TICKET);
        auth_key_ = hex_to_bytes(auth_key_hex);
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), run(), boost::asio::detached); }

   private:
    [[nodiscard]] boost::asio::awaitable<void> run()
    {
        boost::asio::ip::tcp::resolver resolver(acceptor_.get_executor());
        auto [ec, endpoints] = co_await resolver.async_resolve(remote_host_, remote_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("resolve failed: {}", ec.message());
            co_return;
        }

        boost::asio::ip::tcp::socket socket(acceptor_.get_executor());
        auto [ec2, ep] = co_await boost::asio::async_connect(socket, endpoints, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
        {
            LOG_ERROR("connect failed: {}", ec2.message());
            co_return;
        }

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        uint64_t ts_net = __builtin_bswap64(now);
        std::vector<uint8_t> plaintext(32);
        std::memcpy(plaintext.data(), &ts_net, 8);
        for (int i = 8; i < 32; ++i) plaintext[i] = rand() % 255;
        std::vector<uint8_t> session_id = reality::CryptoUtil::aes_cfb_encrypt(auth_key_, plaintext);

        SessionIdPatcherStream<boost::asio::ip::tcp::socket> patcher(std::move(socket), std::move(session_id));

        auto ssl_stream =
            std::make_shared<boost::asio::ssl::stream<SessionIdPatcherStream<boost::asio::ip::tcp::socket>>>(std::move(patcher), ssl_context_);

        SSL_set_tlsext_host_name(ssl_stream->native_handle(), "apple.com");

        SSL_SESSION* sess = SSL_SESSION_new();
        SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION);

        std::vector<uint8_t> dummy_id(32, 0xEE);
        SSL_SESSION_set1_id(sess, dummy_id.data(), dummy_id.size());

        std::vector<uint8_t> dummy_key(48, 0xAA);
        SSL_SESSION_set1_master_key(sess, dummy_key.data(), dummy_key.size());

        STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl_stream->native_handle());
        if (ciphers && sk_SSL_CIPHER_num(ciphers) > 0)
        {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, 0);
            SSL_SESSION_set_cipher(sess, cipher);
        }

        SSL_set_session(ssl_stream->native_handle(), sess);
        SSL_SESSION_free(sess);

        auto [ec3] = co_await ssl_stream->async_handshake(boost::asio::ssl::stream_base::client, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
        {
            LOG_ERROR("handshake failed {}", ec3.message());
            co_return;
        }

        tunnel_ = std::make_shared<mux_tunnel_impl<SessionIdPatcherStream<boost::asio::ip::tcp::socket>>>(std::move(*ssl_stream));
        boost::asio::co_spawn(acceptor_.get_executor(), tunnel_->run(), boost::asio::detached);

        boost::asio::ip::tcp::endpoint local_ep(boost::asio::ip::tcp::v4(), local_port_);
        acceptor_.open(local_ep.protocol());
        acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(local_ep);
        acceptor_.listen();

        LOG_INFO("local client listening on {}", local_port_);

        while (true)
        {
            auto& client_ctx = pool_.get_io_context();
            boost::asio::ip::tcp::socket peer(client_ctx);
            auto [ec_acc] = co_await acceptor_.async_accept(peer, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_acc)
                continue;

            auto session = std::make_shared<local_session>(std::move(peer), tunnel_);
            boost::asio::co_spawn(
                client_ctx, [session]() { return session->start(); }, boost::asio::detached);
        }
    }

    std::vector<uint8_t> hex_to_bytes(const std::string& hex)
    {
        std::vector<uint8_t> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    io_context_pool& pool_;
    std::string remote_host_;
    std::string remote_port_;
    std::uint16_t local_port_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_context_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
    std::vector<uint8_t> auth_key_;
};

}    // namespace mux

#endif
