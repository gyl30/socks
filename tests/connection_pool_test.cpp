#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>
#include <asio/io_context.hpp>

#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "reality_messages.h"
#include "remote_server.h"

namespace
{

class ConnectionPoolTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(priv, priv + 32));

        client_pub_key = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(pub, pub + 32));
    }
    std::string server_priv_key;
    std::string client_pub_key;
};

TEST_F(ConnectionPoolTest, TunnelReuse)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);

    uint16_t server_port = 31081;
    uint16_t local_socks_port = 31082;
    std::string sni = "www.google.com";

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_priv_key;
    server_cfg.reality.short_id = "0102030405060708";
    auto server = std::make_shared<mux::remote_server>(pool, server_cfg);
    reality::server_fingerprint fp;
    server->cert_manager().set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fp);
    server->start();

    mux::config::limits_t limits;
    limits.max_connections = 1;

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = local_socks_port;
    client_cfg.reality.public_key = client_pub_key;
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = "0102030405060708";
    client_cfg.limits = limits;
    auto client = std::make_shared<mux::socks_client>(pool, client_cfg);
    client->start();

    std::thread t([&pool] { pool.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    asio::io_context client_ctx;
    asio::ip::tcp::socket s1(client_ctx);
    s1.connect({asio::ip::make_address("127.0.0.1"), local_socks_port}, ec);
    ASSERT_FALSE(ec);

    asio::ip::tcp::socket s2(client_ctx);
    s2.connect({asio::ip::make_address("127.0.0.1"), local_socks_port}, ec);
    ASSERT_FALSE(ec);

    client->stop();
    server->stop();
    pool.stop();
    t.join();
}

}    // namespace
