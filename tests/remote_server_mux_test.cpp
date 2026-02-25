
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "log.h"
#include "protocol.h"
#include "ch_parser.h"
#include "mux_codec.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "mux_protocol.h"
#include "reality_auth.h"
#include "socks_client.h"
#include "remote_server.h"
#include "reality_messages.h"

using namespace mux;

class scoped_pool
{
   public:
    explicit scoped_pool(mux::io_context_pool& pool) : pool_(pool), thread_([this]() { pool_.run(); }) {}
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

class remote_server_mux_test_fixture : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        short_id_ = "0102030405060708";
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& server_pub_key() const { return server_pub_key_; }
    [[nodiscard]] const std::string& short_id() const { return short_id_; }

    mux::config make_server_cfg(std::uint16_t port) const
    {
        mux::config cfg;
        cfg.inbound.host = "127.0.0.1";
        cfg.inbound.port = port;
        cfg.reality.private_key = server_priv_key();
        cfg.reality.short_id = short_id();
        return cfg;
    }

    mux::config make_client_cfg(std::uint16_t server_port, const std::string& sni, const mux::config::timeout_t& timeouts) const
    {
        mux::config cfg;
        cfg.outbound.host = "127.0.0.1";
        cfg.outbound.port = server_port;
        cfg.socks.port = 0;
        cfg.reality.public_key = server_pub_key();
        cfg.reality.sni = sni;
        cfg.reality.short_id = short_id();
        cfg.reality.strict_cert_verify = false;
        cfg.timeout = timeouts;
        return cfg;
    }

   private:
    std::string server_priv_key_;
    std::string server_pub_key_;
    std::string short_id_;
};

static std::uint16_t wait_for_socks_listen_port(const std::shared_ptr<mux::socks_client>& client, const int attempts = 80)
{
    for (int i = 0; i < attempts; ++i)
    {
        const auto listen_port = client->listen_port();
        if (listen_port != 0)
        {
            return listen_port;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}

static bool connect_proxy_with_retry(boost::asio::ip::tcp::socket& socket, const std::uint16_t port, const int attempts = 40)
{
    const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port);
    for (int i = 0; i < attempts; ++i)
    {
        boost::system::error_code ec;
        socket.connect(endpoint, ec);
        if (!ec)
        {
            return true;
        }
        boost::system::error_code close_ec;
        socket.close(close_ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

TEST_F(remote_server_mux_test_fixture, ProcessTcpConnectRequest)
{
    mux::io_context_pool pool(2);
    scoped_pool const sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", timeouts));
    client->start();

    const std::uint16_t local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    {
        boost::asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        ASSERT_TRUE(connect_proxy_with_retry(proxy_sock, local_socks_port));

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_sock, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_sock, boost::asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {
            0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(server_port >> 8), static_cast<uint8_t>(server_port & 0xFF)};
        boost::asio::write(proxy_sock, boost::asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        boost::asio::read(proxy_sock, boost::asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test_fixture, ProcessUdpAssociateRequest)
{
    mux::io_context_pool pool(2);
    scoped_pool const sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", timeouts));
    client->start();

    const std::uint16_t local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    {
        boost::asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        ASSERT_TRUE(connect_proxy_with_retry(proxy_sock, local_socks_port));

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_sock, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_sock, boost::asio::buffer(resp, 2));

        std::uint8_t udp_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        boost::asio::write(proxy_sock, boost::asio::buffer(udp_req));

        std::uint8_t udp_resp[10];
        boost::asio::read(proxy_sock, boost::asio::buffer(udp_resp, 10));
        EXPECT_EQ(udp_resp[0], 0x05);
        EXPECT_EQ(udp_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test_fixture, TargetConnectFail)
{
    mux::io_context_pool pool(2);
    scoped_pool const sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", mux::config::timeout_t{}));
    client->start();

    const std::uint16_t local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    {
        boost::asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        ASSERT_TRUE(connect_proxy_with_retry(proxy_sock, local_socks_port));

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_sock, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_sock, boost::asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1};
        boost::asio::write(proxy_sock, boost::asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        boost::asio::read(proxy_sock, boost::asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_NE(conn_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test_fixture, TargetConnectTimeoutUsesConfiguredConnectTimeoutAndReturnsHostUnreach)
{
    mux::io_context_pool pool(2);
    scoped_pool const sp(pool);

    auto server_cfg = make_server_cfg(0);
    server_cfg.timeout.connect = 1;
    server_cfg.timeout.read = 10;
    auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config::timeout_t client_timeouts;
    client_timeouts.read = 10;
    client_timeouts.write = 10;
    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", client_timeouts));
    client->start();

    const std::uint16_t local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor saturated_acceptor(pool.get_io_context());
    saturated_acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    saturated_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    saturated_acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    saturated_acceptor.listen(1, ec);
    ASSERT_FALSE(ec);

    const auto target_port = saturated_acceptor.local_endpoint().port();
    boost::asio::ip::tcp::socket queued_client_a(pool.get_io_context());
    queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(pool.get_io_context());
    queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);

    {
        boost::asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        ASSERT_TRUE(connect_proxy_with_retry(proxy_sock, local_socks_port));

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_sock, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_sock, boost::asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {0x05,
                                   0x01,
                                   0x00,
                                   0x01,
                                   127,
                                   0,
                                   0,
                                   1,
                                   static_cast<std::uint8_t>(target_port >> 8),
                                   static_cast<std::uint8_t>(target_port & 0xFF)};

        const auto start = std::chrono::steady_clock::now();
        boost::asio::write(proxy_sock, boost::asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        boost::asio::read(proxy_sock, boost::asio::buffer(conn_resp, 10));
        const auto elapsed = std::chrono::steady_clock::now() - start;

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], socks::kRepHostUnreach);
        EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);
    }

    boost::system::error_code close_ec;
    queued_client_a.close(close_ec);
    queued_client_b.close(close_ec);
    saturated_acceptor.close(close_ec);
    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test_fixture, TargetResolveFail)
{
    mux::io_context_pool pool(2);
    scoped_pool const sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", mux::config::timeout_t{}));
    client->start();

    const std::uint16_t local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    {
        boost::asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        ASSERT_TRUE(connect_proxy_with_retry(proxy_sock, local_socks_port));

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        boost::asio::write(proxy_sock, boost::asio::buffer(handshake));
        std::uint8_t resp[2];
        boost::asio::read(proxy_sock, boost::asio::buffer(resp, 2));

        const std::string domain = "invalid.domain.totally.fake";
        std::vector<uint8_t> conn_req = {0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(domain.size())};
        conn_req.insert(conn_req.end(), domain.begin(), domain.end());
        conn_req.push_back(0);
        conn_req.push_back(80);

        boost::asio::write(proxy_sock, boost::asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        boost::asio::read(proxy_sock, boost::asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x04);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}
