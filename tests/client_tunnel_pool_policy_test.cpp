#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>

#include "config.h"
#include "crypto_util.h"
#include "remote_server.h"
#include "context_pool.h"
#include "mux_tunnel.h"
#include "reality_messages.h"
#include "client_tunnel_pool.h"

namespace
{

class scoped_pool_runner
{
   public:
    explicit scoped_pool_runner(mux::io_context_pool& pool) : pool_(pool), thread_([&pool]() { pool.run(); }) {}

    ~scoped_pool_runner()
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

[[nodiscard]] std::uint16_t pick_free_port()
{
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

[[nodiscard]] bool wait_for_tunnel(const std::shared_ptr<mux::client_tunnel_pool>& tunnel_pool, const std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        const auto tunnel = tunnel_pool->select_tunnel();
        if (tunnel != nullptr)
        {
            const auto connection = tunnel->connection();
            if (connection != nullptr && connection->is_open())
            {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

class client_tunnel_pool_policy_test : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t public_key[32];
        std::uint8_t private_key[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(public_key, private_key));
        server_private_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(private_key, private_key + 32));
        client_public_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32));
    }

    [[nodiscard]] const std::string& server_private_key() const { return server_private_key_; }
    [[nodiscard]] const std::string& client_public_key() const { return client_public_key_; }

   private:
    std::string server_private_key_;
    std::string client_public_key_;
};

TEST_F(client_tunnel_pool_policy_test, DummyCertificateAllowedWhenStrictVerifyDisabled)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool_runner runner(pool);

    const std::uint16_t server_port = pick_free_port();
    const std::string sni = "www.google.com";
    const std::string short_id = "0102030405060708";

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_private_key();
    server_cfg.reality.short_id = short_id;
    auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint);
    server->start();

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.reality.public_key = client_public_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id;
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.limits.max_connections = 1;
    client_cfg.timeout.read = 5;
    client_cfg.timeout.write = 5;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, client_cfg, 0);
    ASSERT_TRUE(tunnel_pool->valid());
    tunnel_pool->start();

    EXPECT_TRUE(wait_for_tunnel(tunnel_pool, std::chrono::seconds(6)));

    tunnel_pool->stop();
    server->stop();
}

TEST_F(client_tunnel_pool_policy_test, DummyCertificateRejectedWhenStrictVerifyEnabled)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    scoped_pool_runner runner(pool);

    const std::uint16_t server_port = pick_free_port();
    const std::string sni = "www.google.com";
    const std::string short_id = "0102030405060708";

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_private_key();
    server_cfg.reality.short_id = short_id;
    auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint);
    server->start();

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.reality.public_key = client_public_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id;
    client_cfg.reality.strict_cert_verify = true;
    client_cfg.limits.max_connections = 1;
    client_cfg.timeout.read = 5;
    client_cfg.timeout.write = 5;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, client_cfg, 0);
    ASSERT_TRUE(tunnel_pool->valid());
    tunnel_pool->start();

    EXPECT_FALSE(wait_for_tunnel(tunnel_pool, std::chrono::seconds(4)));

    tunnel_pool->stop();
    server->stop();
}

}    // namespace
