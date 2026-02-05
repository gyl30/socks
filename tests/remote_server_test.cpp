#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

#include "remote_server.h"
#include "context_pool.h"
#include "crypto_util.h"
#include "reality_messages.h"

class RemoteServerTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        (void)reality::crypto_util::generate_x25519_keypair(pub, priv);
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
    }
    std::string server_priv_key;
    std::string server_pub_key;
};

TEST_F(RemoteServerTest, AuthFailureTriggersFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29911;
    std::uint16_t fallback_port = 29912;
    std::string sni = "www.google.com";

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    bool fallback_triggered = false;
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    mux::config::fallback_entry fb;
    fb.sni = sni;
    fb.host = "127.0.0.1";
    fb.port = std::to_string(fallback_port);

    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{fb}, server_priv_key, "", mux::config::timeout_t{}, mux::config::limits_t{});
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
        std::vector<std::uint8_t> session_id(32, 0x01);
        std::vector<std::uint8_t> random(32, 0x02);
        std::vector<std::uint8_t> x25519_pubkey(32, 0x03);

        auto ch_msg = reality::ClientHelloBuilder::build(spec, session_id, random, x25519_pubkey, sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(ch_msg.size()));
        record.insert(record.end(), ch_msg.begin(), ch_msg.end());

        asio::write(sock, asio::buffer(record));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_TRUE(fallback_triggered);
}

TEST_F(RemoteServerTest, SNIMismatchTriggersFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29913;
    std::uint16_t default_fallback_port = 29914;
    std::string config_sni = "www.google.com";
    std::string client_sni = "www.bing.com";

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), default_fallback_port));
    bool fallback_triggered = false;
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    mux::config::fallback_entry fb;
    fb.sni = "";
    fb.host = "127.0.0.1";
    fb.port = std::to_string(default_fallback_port);

    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{fb}, server_priv_key, "", mux::config::timeout_t{}, mux::config::limits_t{});
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
        auto ch_msg = reality::ClientHelloBuilder::build(
            spec, std::vector<std::uint8_t>(32, 0), std::vector<std::uint8_t>(32, 0), std::vector<std::uint8_t>(32, 0), client_sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(ch_msg.size()));
        record.insert(record.end(), ch_msg.begin(), ch_msg.end());

        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered);
}

TEST_F(RemoteServerTest, InvalidHandshakeTriggersFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29915;
    std::uint16_t default_fallback_port = 29916;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), default_fallback_port));
    bool fallback_triggered = false;
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    mux::config::fallback_entry fb;
    fb.sni = "";
    fb.host = "127.0.0.1";
    fb.port = std::to_string(default_fallback_port);

    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{fb}, server_priv_key, "", mux::config::timeout_t{}, mux::config::limits_t{});
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered);
}
