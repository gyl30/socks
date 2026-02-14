#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

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

class remote_server_mux_test : public ::testing::Test
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

TEST_F(remote_server_mux_test, ProcessTcpConnectRequest)
{
    mux::io_context_pool pool(2);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", timeouts));
    client->start();

    std::uint16_t local_socks_port = 0;
    for (int i = 0; i < 50; ++i)
    {
        local_socks_port = client->listen_port();
        if (local_socks_port != 0)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_NE(local_socks_port, 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {
            0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, static_cast<uint8_t>(server_port >> 8), static_cast<uint8_t>(server_port & 0xFF)};
        asio::write(proxy_sock, asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        asio::read(proxy_sock, asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test, ProcessUdpAssociateRequest)
{
    mux::io_context_pool pool(2);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", timeouts));
    client->start();

    std::uint16_t local_socks_port = 0;
    for (int i = 0; i < 50; ++i)
    {
        local_socks_port = client->listen_port();
        if (local_socks_port != 0)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_NE(local_socks_port, 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        std::uint8_t udp_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        asio::write(proxy_sock, asio::buffer(udp_req));

        std::uint8_t udp_resp[10];
        asio::read(proxy_sock, asio::buffer(udp_resp, 10));
        EXPECT_EQ(udp_resp[0], 0x05);
        EXPECT_EQ(udp_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test, TargetConnectFail)
{
    mux::io_context_pool pool(2);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", mux::config::timeout_t{}));
    client->start();

    std::uint16_t local_socks_port = 0;
    for (int i = 0; i < 50; ++i)
    {
        local_socks_port = client->listen_port();
        if (local_socks_port != 0)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_NE(local_socks_port, 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1};
        asio::write(proxy_sock, asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        asio::read(proxy_sock, asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_NE(conn_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

TEST_F(remote_server_mux_test, TargetResolveFail)
{
    mux::io_context_pool pool(2);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(0));

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    auto client = std::make_shared<mux::socks_client>(pool, make_client_cfg(server_port, "www.google.com", mux::config::timeout_t{}));
    client->start();

    std::uint16_t local_socks_port = 0;
    for (int i = 0; i < 50; ++i)
    {
        local_socks_port = client->listen_port();
        if (local_socks_port != 0)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ASSERT_NE(local_socks_port, 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        const std::string domain = "invalid.domain.totally.fake";
        std::vector<uint8_t> conn_req = {0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(domain.size())};
        conn_req.insert(conn_req.end(), domain.begin(), domain.end());
        conn_req.push_back(0);
        conn_req.push_back(80);

        asio::write(proxy_sock, asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        asio::read(proxy_sock, asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
        EXPECT_EQ(conn_resp[1], 0x04);
    }

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}
