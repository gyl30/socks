// NOLINTBEGIN(google-explicit-constructor, misc-non-private-member-variables-in-classes)
// NOLINTBEGIN(bugprone-unused-return-value, misc-include-cleaner)
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <functional>
#include <system_error>

#include <boost/asio/read.hpp>
#include <gtest/gtest.h>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "config.h"
#include "protocol.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"
#include "test_util.h"

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
    struct stack_handles
    {
        std::shared_ptr<mux::remote_server> server;
        std::shared_ptr<mux::socks_client> client;
    };

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
    [[nodiscard]] stack_handles make_stack(mux::io_context_pool& pool,
                                           const std::uint16_t local_socks_port,
                                           const std::uint16_t timeout_s = 10) const
    {
        const std::string sni = "www.google.com";
        mux::config::timeout_t timeouts;
        timeouts.read = timeout_s;
        timeouts.write = timeout_s;
        timeouts.idle = timeout_s;

        mux::config server_cfg;
        server_cfg.inbound.host = "127.0.0.1";
        server_cfg.inbound.port = 0;
        server_cfg.reality.private_key = server_priv_key();
        server_cfg.reality.short_id = short_id();
        server_cfg.timeout = timeouts;

        const auto server = std::make_shared<mux::remote_server>(pool, server_cfg);
        reality::server_fingerprint fp;
        fp.cipher_suite = 0x1301;
        fp.alpn = "h2";
        server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);
        const auto server_port = server->listen_port();

        mux::config client_cfg;
        client_cfg.outbound.host = "127.0.0.1";
        client_cfg.outbound.port = server_port;
        client_cfg.socks.port = local_socks_port;
        client_cfg.reality.public_key = client_pub_key();
        client_cfg.reality.sni = sni;
        client_cfg.reality.short_id = short_id();
        client_cfg.reality.strict_cert_verify = false;
        client_cfg.timeout = timeouts;
        const auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

        return stack_handles{.server = server, .client = client};
    }

   private:
    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string short_id_;
};

namespace
{

std::shared_ptr<boost::asio::ip::tcp::acceptor> create_ephemeral_acceptor(
    boost::asio::io_context& io_context,
    const std::uint32_t max_attempts = 120,
    const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    auto acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(io_context);
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor->is_open())
        {
            acceptor->close(ec);
        }
        ec = acceptor->open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            ec = acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
        }
        if (!ec)
        {
            return acceptor;
        }
        std::this_thread::sleep_for(backoff);
    }
    return nullptr;
}

bool wait_for_socks_listen(const std::uint16_t socks_port, const int attempts = 60)
{
    for (int i = 0; i < attempts; ++i)
    {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::system::error_code ec;
        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), socks_port), ec);
        if (!ec)
        {
            boost::system::error_code ignore;
            socket.close(ignore);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

bool wait_for_socks_listen(const std::shared_ptr<mux::socks_client>& client,
                           std::uint16_t& socks_port,
                           const int attempts = 60)
{
    for (int i = 0; i < attempts; ++i)
    {
        const auto port = client->listen_port();
        if (port != 0 && wait_for_socks_listen(port, 1))
        {
            socks_port = port;
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

}    // namespace

TEST_F(IntegrationTest, FullHandshakeAndMux)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(2);

    const std::string sni = "www.google.com";

    mux::config::timeout_t timeouts;
    timeouts.read = 5;
    timeouts.write = 5;

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = 0;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout = timeouts;
    const auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout = timeouts;
    const auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

    scoped_pool const sp(pool);

    server->start();
    client->start();

    std::uint16_t local_socks_port = 0;
    ASSERT_TRUE(wait_for_socks_listen(client, local_socks_port));

    boost::asio::io_context proxy_ctx;
    boost::asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    if (!ec)
    {
        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_socket, boost::asio::buffer(handshake), ec);
        EXPECT_FALSE(ec);

        std::uint8_t response[2];
        boost::asio::read(proxy_socket, boost::asio::buffer(response), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(response[0], 0x05);
        EXPECT_EQ(response[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

TEST_F(IntegrationTest, FullDataTransfer)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(2);

    auto echo_acceptor = create_ephemeral_acceptor(pool.get_io_context());
    ASSERT_NE(echo_acceptor, nullptr);
    const std::uint16_t echo_port = echo_acceptor->local_endpoint().port();

    struct echo_session : std::enable_shared_from_this<echo_session>
    {
        boost::asio::ip::tcp::socket socket;
        std::vector<uint8_t> data;
        echo_session(boost::asio::ip::tcp::socket s) : socket(std::move(s)), data(1024) {}
        void start()
        {
            auto self = shared_from_this();
            socket.async_read_some(boost::asio::buffer(data),
                                   [self](boost::system::error_code ec, std::size_t n)
                                   {
                                       if (!ec)
                                       {
                                           boost::asio::async_write(self->socket,
                                                             boost::asio::buffer(self->data, n),
                                                             [self](boost::system::error_code ec, std::size_t)
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
    std::weak_ptr<std::function<void()>> const weak_handler = acceptor_handler;
    *acceptor_handler = [echo_acceptor, weak_handler]()
    {
        echo_acceptor->async_accept(
            [echo_acceptor, weak_handler](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
            {
                if (!ec)
                {
                    std::make_shared<echo_session>(std::move(socket))->start();
                }
                if (auto handler = weak_handler.lock())
                {
                    if (!ec || ec != boost::asio::error::operation_aborted)
                    {
                        (*handler)();
                    }
                }
            });
    };
    (*acceptor_handler)();

    const std::string sni = "www.google.com";

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = 0;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout = timeouts;
    const auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout = timeouts;
    const auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

    scoped_pool const sp(pool);
    server->start();
    client->start();
    std::uint16_t local_socks_port = 0;
    ASSERT_TRUE(wait_for_socks_listen(client, local_socks_port));

    {
        boost::asio::io_context proxy_ctx;
        boost::asio::ip::tcp::socket proxy_socket(proxy_ctx);
        proxy_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
        ASSERT_FALSE(ec);

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_socket, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_socket, boost::asio::buffer(resp));
        EXPECT_EQ(resp[0], 0x05);
        EXPECT_EQ(resp[1], 0x00);

        std::vector<uint8_t> conn_req = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
        conn_req.push_back(static_cast<uint8_t>((echo_port >> 8) & 0xFF));
        conn_req.push_back(static_cast<uint8_t>(echo_port & 0xFF));
        boost::asio::write(proxy_socket, boost::asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        boost::asio::read(proxy_socket, boost::asio::buffer(conn_resp));
        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x00);

        std::string test_data = "hello raii proxy echo server\n";
        boost::asio::write(proxy_socket, boost::asio::buffer(test_data));

        std::vector<char> echo_buf(test_data.size());
        boost::asio::read(proxy_socket, boost::asio::buffer(echo_buf));
        EXPECT_EQ(std::string(echo_buf.begin(), echo_buf.end()), test_data);
    }

    client->stop();
    server->stop();
    echo_acceptor->close();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(IntegrationTest, SocksRejectsUnsupportedMethod)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(2);

    auto stack = make_stack(pool, 0, 5);
    ASSERT_NE(stack.server->listen_port(), 0);

    scoped_pool const sp(pool);
    stack.server->start();
    stack.client->start();

    std::uint16_t local_socks_port = 0;
    ASSERT_TRUE(wait_for_socks_listen(stack.client, local_socks_port));

    boost::asio::io_context proxy_ctx;
    boost::asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    ASSERT_FALSE(ec);

    std::uint8_t handshake[] = {socks::kVer, 0x01, socks::kMethodPassword};
    boost::asio::write(proxy_socket, boost::asio::buffer(handshake), ec);
    ASSERT_FALSE(ec);

    std::uint8_t response[2] = {0};
    boost::asio::read(proxy_socket, boost::asio::buffer(response), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(response[0], socks::kVer);
    EXPECT_EQ(response[1], socks::kMethodNoAcceptable);

    stack.client->stop();
    stack.server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

TEST_F(IntegrationTest, SocksUnsupportedCommandReturnsCmdNotSupported)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(2);

    auto stack = make_stack(pool, 0, 5);
    ASSERT_NE(stack.server->listen_port(), 0);

    scoped_pool const sp(pool);
    stack.server->start();
    stack.client->start();

    std::uint16_t local_socks_port = 0;
    ASSERT_TRUE(wait_for_socks_listen(stack.client, local_socks_port));

    boost::asio::io_context proxy_ctx;
    boost::asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    ASSERT_FALSE(ec);

    std::uint8_t handshake[] = {socks::kVer, 0x01, socks::kMethodNoAuth};
    boost::asio::write(proxy_socket, boost::asio::buffer(handshake), ec);
    ASSERT_FALSE(ec);

    std::uint8_t handshake_response[2] = {0};
    boost::asio::read(proxy_socket, boost::asio::buffer(handshake_response), ec);
    ASSERT_FALSE(ec);
    ASSERT_EQ(handshake_response[0], socks::kVer);
    ASSERT_EQ(handshake_response[1], socks::kMethodNoAuth);

    std::vector<std::uint8_t> bind_req = {socks::kVer, socks::kCmdBind, 0x00, socks::kAtypIpv4, 127, 0, 0, 1, 0, 80};
    boost::asio::write(proxy_socket, boost::asio::buffer(bind_req), ec);
    ASSERT_FALSE(ec);

    std::uint8_t bind_resp[10] = {0};
    boost::asio::read(proxy_socket, boost::asio::buffer(bind_resp), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(bind_resp[0], socks::kVer);
    EXPECT_EQ(bind_resp[1], socks::kRepCmdNotSupported);

    stack.client->stop();
    stack.server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}

TEST_F(IntegrationTest, SocksConnectClosedPortReturnsFailure)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(2);

    auto stack = make_stack(pool, 0, 5);
    ASSERT_NE(stack.server->listen_port(), 0);

    boost::asio::io_context closed_target_context;
    boost::asio::ip::tcp::socket closed_target_socket(closed_target_context);
    closed_target_socket.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(mux::test::bind_ephemeral_tcp_socket(closed_target_socket));
    const auto closed_target_port = closed_target_socket.local_endpoint().port();

    scoped_pool const sp(pool);
    stack.server->start();
    stack.client->start();

    std::uint16_t local_socks_port = 0;
    ASSERT_TRUE(wait_for_socks_listen(stack.client, local_socks_port));

    boost::asio::io_context proxy_ctx;
    boost::asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    ASSERT_FALSE(ec);

    std::uint8_t handshake[] = {socks::kVer, 0x01, socks::kMethodNoAuth};
    boost::asio::write(proxy_socket, boost::asio::buffer(handshake), ec);
    ASSERT_FALSE(ec);

    std::uint8_t handshake_response[2] = {0};
    boost::asio::read(proxy_socket, boost::asio::buffer(handshake_response), ec);
    ASSERT_FALSE(ec);
    ASSERT_EQ(handshake_response[0], socks::kVer);
    ASSERT_EQ(handshake_response[1], socks::kMethodNoAuth);

    std::vector<std::uint8_t> conn_req = {socks::kVer, socks::kCmdConnect, 0x00, socks::kAtypIpv4, 127, 0, 0, 1};
    conn_req.push_back(static_cast<std::uint8_t>((closed_target_port >> 8) & 0xFF));
    conn_req.push_back(static_cast<std::uint8_t>(closed_target_port & 0xFF));
    boost::asio::write(proxy_socket, boost::asio::buffer(conn_req), ec);
    ASSERT_FALSE(ec);

    std::uint8_t conn_resp[10] = {0};
    boost::asio::read(proxy_socket, boost::asio::buffer(conn_resp), ec);
    ASSERT_FALSE(ec);
    EXPECT_EQ(conn_resp[0], socks::kVer);
    EXPECT_NE(conn_resp[1], socks::kRepSuccess);

    closed_target_socket.close(ec);
    ASSERT_FALSE(ec);
    stack.client->stop();
    stack.server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
}
// NOLINTEND(bugprone-unused-return-value, misc-include-cleaner)
// NOLINTEND(google-explicit-constructor, misc-non-private-member-variables-in-classes)
