#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <cstdint>
#include <memory>
#include <system_error>

#include <gtest/gtest.h>

#include "config.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "local_client.h"
#include "remote_server.h"

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
        std::error_code ec;
        const auto verify_pub = reality::crypto_util::extract_ed25519_public_key(std::vector<std::uint8_t>(priv, priv + 32), ec);
        ASSERT_FALSE(ec);
        verify_pub_key_ = reality::crypto_util::bytes_to_hex(verify_pub);
        short_id_ = "0102030405060708";
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& client_pub_key() const { return client_pub_key_; }
    [[nodiscard]] const std::string& verify_pub_key() const { return verify_pub_key_; }
    [[nodiscard]] const std::string& short_id() const { return short_id_; }

   private:
    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string verify_pub_key_;
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

    const auto server =
        std::make_shared<mux::remote_server>(pool, server_port, std::vector<mux::config::fallback_entry>{}, server_priv_key(), short_id(), timeouts);
    server->start();

    const auto client = std::make_shared<mux::local_client>(
        pool, "127.0.0.1", std::to_string(server_port), local_socks_port, client_pub_key(), sni, short_id(), verify_pub_key(), timeouts);

    std::thread pool_thread([&pool]() { pool.run(); });

    server->start();
    client->start();

    std::this_thread::sleep_for(std::chrono::seconds(5));

    asio::io_context proxy_ctx;
    asio::ip::tcp::socket proxy_socket(proxy_ctx);
    proxy_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    EXPECT_FALSE(ec) << "Connect failed: " << ec.message();
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
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}
