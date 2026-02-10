#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <functional>
#include <system_error>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

#include "config.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "local_client.h"
#include "remote_server.h"

class scoped_pool
{
   public:
    explicit scoped_pool(mux::io_context_pool& pool) : pool_(pool), thread_([&pool]() { pool.run(); }) {}
    ~scoped_pool()
    {
        pool_.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

   private:
    mux::io_context_pool& pool_;
    std::thread thread_;
};

class IntegrationTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32];
        std::uint8_t priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        client_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        short_id_ = "0102030405060708";
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& client_pub_key() const { return client_pub_key_; }
    [[nodiscard]] const std::string& short_id() const { return short_id_; }

   private:
    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string short_id_;
};

TEST_F(IntegrationTest, FullHandshakeAndMux)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);

    const std::uint16_t server_port = 18844;
    const std::uint16_t local_socks_port = 11081;
    const std::string sni = "www.google.com";

    mux::config::timeout_t timeouts;
    timeouts.read = 5;
    timeouts.write = 5;

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout = timeouts;
    const auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = local_socks_port;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.timeout = timeouts;
    const auto client = std::make_shared<mux::local_client>(pool, client_cfg);

    scoped_pool sp(pool);

    server->start();
    client->start();

    std::this_thread::sleep_for(std::chrono::seconds(2));

    asio::io_context proxy_ctx;
    asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    if (!ec)
    {
        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_socket, asio::buffer(handshake), ec);
        EXPECT_FALSE(ec);

        std::uint8_t response[2];
        asio::read(proxy_socket, asio::buffer(response), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(response[0], 0x05);
        EXPECT_EQ(response[1], 0x00);
    }

    client->stop();
    server->stop();
}

TEST_F(IntegrationTest, FullDataTransfer)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);

    auto echo_acceptor = std::make_shared<asio::ip::tcp::acceptor>(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const std::uint16_t echo_port = echo_acceptor->local_endpoint().port();

    struct echo_session : std::enable_shared_from_this<echo_session>
    {
        asio::ip::tcp::socket socket;
        std::vector<uint8_t> data;
        echo_session(asio::ip::tcp::socket s) : socket(std::move(s)), data(1024) {}
        void start()
        {
            auto self = shared_from_this();
            socket.async_read_some(asio::buffer(data),
                                   [self](std::error_code ec, std::size_t n)
                                   {
                                       if (!ec)
                                       {
                                           asio::async_write(self->socket,
                                                             asio::buffer(self->data, n),
                                                             [self](std::error_code ec, std::size_t)
                                                             {
                                                                 if (!ec)
                                                                 {
                                                                     self->start();
                                                                 }
                                                             });
                                       }
                                   });
        }
    };

    auto acceptor_handler = std::make_shared<std::function<void()>>();
    *acceptor_handler = [echo_acceptor, acceptor_handler]()
    {
        echo_acceptor->async_accept(
            [echo_acceptor, acceptor_handler](std::error_code ec, asio::ip::tcp::socket socket)
            {
                if (!ec)
                {
                    std::make_shared<echo_session>(std::move(socket))->start();
                }
                if (!ec || ec != asio::error::operation_aborted)
                {
                    (*acceptor_handler)();
                }
            });
    };
    (*acceptor_handler)();

    const std::uint16_t server_port = 18845;
    const std::uint16_t local_socks_port = 11082;
    const std::string sni = "www.google.com";

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout = timeouts;
    const auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = local_socks_port;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.timeout = timeouts;
    const auto client = std::make_shared<mux::local_client>(pool, client_cfg);
    client->start();

    scoped_pool sp(pool);

    std::this_thread::sleep_for(std::chrono::seconds(2));

    {
        asio::io_context proxy_ctx;
        asio::ip::tcp::socket proxy_socket(proxy_ctx);
        proxy_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
        ASSERT_FALSE(ec);

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_socket, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_socket, asio::buffer(resp));
        EXPECT_EQ(resp[0], 0x05);
        EXPECT_EQ(resp[1], 0x00);

        std::vector<uint8_t> conn_req = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
        conn_req.push_back(static_cast<uint8_t>((echo_port >> 8) & 0xFF));
        conn_req.push_back(static_cast<uint8_t>(echo_port & 0xFF));
        asio::write(proxy_socket, asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        asio::read(proxy_socket, asio::buffer(conn_resp));
        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x00);

        std::string test_data = "hello raii proxy echo server\n";
        asio::write(proxy_socket, asio::buffer(test_data));

        std::vector<char> echo_buf(test_data.size());
        asio::read(proxy_socket, asio::buffer(echo_buf));
        EXPECT_EQ(std::string(echo_buf.begin(), echo_buf.end()), test_data);
    }

    client->stop();
    server->stop();
    echo_acceptor->close();
}
