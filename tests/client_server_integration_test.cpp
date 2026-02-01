#include <gtest/gtest.h>
#include "local_client.h"
#include "remote_server.h"
#include "context_pool.h"
#include "crypto_util.h"
#include <thread>

using namespace mux;

class IntegrationTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(priv, priv + 32));
        client_pub_key = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(pub, pub + 32));
    }

    std::string server_priv_key;
    std::string client_pub_key;
};

TEST_F(IntegrationTest, FullHandshakeAndMux)
{
    std::error_code ec;
    io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);

    uint16_t server_port = 18844;
    uint16_t local_socks_port = 11080;
    std::string sni = "www.google.com";

    auto server = std::make_shared<remote_server>(pool, server_port, std::vector<config::fallback_entry>{}, server_priv_key);
    server->start();

    auto client = std::make_shared<local_client>(pool, "127.0.0.1", std::to_string(server_port), local_socks_port, client_pub_key, sni);
    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    client->stop();
    server->stop();
    pool.stop();
}
