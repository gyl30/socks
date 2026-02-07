#include <chrono>
#include <memory>
#include <vector>
#include <thread>
#include <string>
#include <cstdint>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

#include "log.h"
#include "protocol.h"
#include "mux_codec.h"
#include "ch_parser.h"
#include "crypto_util.h"
#include "local_client.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "mux_protocol.h"
#include "remote_server.h"
#include "reality_messages.h"

using namespace mux;

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

class RemoteServerMuxTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        short_id = "0102030405060708";
    }
    std::string server_priv_key;
    std::string server_pub_key;
    std::string short_id;
};

TEST_F(RemoteServerMuxTest, ProcessTcpConnectRequest)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(
        pool, 0, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        0,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        timeouts);
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
}

TEST_F(RemoteServerMuxTest, ProcessUdpAssociateRequest)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(
        pool, 0, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;
    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        0,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        timeouts);
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
}

TEST_F(RemoteServerMuxTest, TargetConnectFail)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(
        pool, 0, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        0,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        mux::config::timeout_t{});
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
}

TEST_F(RemoteServerMuxTest, TargetResolveFail)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool sp(pool);

    auto server = std::make_shared<mux::remote_server>(
        pool, 0, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});

    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->cert_manager().set_certificate("www.google.com", reality::construct_certificate({0x01, 0x02, 0x03}), fp);

    server->start();
    const std::uint16_t server_port = server->listen_port();

    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        0,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        mux::config::timeout_t{});
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
}
