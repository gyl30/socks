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
#include "local_client.h"
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
        std::error_code ec;
        auto verify_pub = reality::crypto_util::extract_ed25519_public_key(std::vector<uint8_t>(priv, priv + 32), ec);
        verify_pub_key = reality::crypto_util::bytes_to_hex(verify_pub);
    }
    std::string server_priv_key;
    std::string client_pub_key;
    std::string verify_pub_key;
};

TEST_F(ConnectionPoolTest, TunnelReuse)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);

    uint16_t server_port = 31081;
    uint16_t local_socks_port = 31082;
    std::string sni = "www.google.com";

    auto server =
        std::make_shared<mux::remote_server>(pool, server_port, std::vector<mux::config::fallback_entry>{}, server_priv_key, "0102030405060708");
    reality::server_fingerprint fp;
    server->cert_manager().set_certificate(sni, {0x01, 0x02}, fp);
    server->start();

    mux::config::limits_t limits;
    limits.max_connections = 1;

    auto client = std::make_shared<mux::local_client>(pool,
                                                      "127.0.0.1",
                                                      std::to_string(server_port),
                                                      local_socks_port,
                                                      client_pub_key,
                                                      sni,
                                                      "0102030405060708",
                                                      verify_pub_key,
                                                      mux::config::timeout_t{},
                                                      mux::config::socks_t{},
                                                      limits);
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
