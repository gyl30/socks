#include <vector>
#include <string>
#include <thread>
#include <memory>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

#include "config.h"
#include "crypto_util.h"
#include "local_client.h"
#include "context_pool.h"
#include "reality_core.h"
#include "remote_server.h"

class LimitsTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        uint8_t pub[32];
        uint8_t priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(priv, priv + 32));
        client_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(pub, pub + 32));
        std::error_code ec;
        const auto verify_pub = reality::crypto_util::extract_ed25519_public_key(std::vector<uint8_t>(priv, priv + 32), ec);
        ASSERT_FALSE(ec);
        verify_pub_key_ = reality::crypto_util::bytes_to_hex(verify_pub);
        short_id_ = "0102030405060708";
    }

    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string verify_pub_key_;
    std::string short_id_;
};

TEST_F(LimitsTest, ContextPoolInvalidSize)
{
    std::error_code ec;
    const mux::io_context_pool pool(0, ec);
    EXPECT_EQ(ec, std::errc::invalid_argument);
}

TEST_F(LimitsTest, ConnectionPoolCapacity)
{
    std::error_code ec;

    mux::io_context_pool pool(4, ec);
    ASSERT_FALSE(ec);

    std::thread pool_thread([&pool] { pool.run(); });

    const uint16_t server_port = 28844;
    const uint16_t local_socks_port = 21080;
    const std::string sni = "www.google.com";

    mux::config::limits_t limits;
    limits.max_connections = 2;

    mux::config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;

    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{}, server_priv_key_, short_id_, timeouts, limits);

    const std::vector<uint8_t> dummy_cert = {0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    const reality::server_fingerprint dummy_fp{};
    server->cert_manager().set_certificate(sni, dummy_cert, dummy_fp);

    server->start();

    const uint16_t target_port = 30080;
    asio::ip::tcp::acceptor target_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), target_port));
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> target_sockets;

    std::function<void()> accept_target = [&]()
    {
        auto sock = std::make_shared<asio::ip::tcp::socket>(pool.get_io_context());
        target_acceptor.async_accept(*sock,
                                     [&, sock](const std::error_code ec_accept)
                                     {
                                         if (!ec_accept)
                                         {
                                             target_sockets.push_back(sock);
                                             accept_target();
                                         }
                                     });
    };
    accept_target();

    auto client = std::make_shared<mux::local_client>(pool,
                                                      "127.0.0.1",
                                                      std::to_string(server_port),
                                                      local_socks_port,
                                                      client_pub_key_,
                                                      sni,
                                                      short_id_,
                                                      verify_pub_key_,
                                                      timeouts,
                                                      mux::config::socks_t{},
                                                      limits);
    client->start();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto connect_socks = [&]([[maybe_unused]] int id) -> bool
    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        const asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), local_socks_port);
        std::error_code cec;
        sock.connect(ep, cec);
        if (cec)
        {
            return false;
        }

        const uint8_t ver_method[] = {0x05, 0x01, 0x00};
        (void)asio::write(sock, asio::buffer(ver_method), cec);
        if (cec)
        {
            return false;
        }

        uint8_t resp[2];
        (void)asio::read(sock, asio::buffer(resp), cec);
        if (cec || resp[1] != 0x00)
        {
            return false;
        }

        const uint16_t port_n = htons(target_port);
        uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
        std::memcpy(req + 8, &port_n, 2);

        (void)asio::write(sock, asio::buffer(req, 10), cec);
        if (cec)
        {
            return false;
        }

        uint8_t reply[10];
        (void)asio::read(sock, asio::buffer(reply), cec);

        if (!cec && reply[1] == 0x00)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            return true;
        }
        return false;
    };

    std::thread t1([&] { EXPECT_TRUE(connect_socks(1)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread t2([&] { EXPECT_TRUE(connect_socks(2)); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread t3([&] { EXPECT_TRUE(connect_socks(3)); });

    t1.join();
    t2.join();
    t3.join();

    client->stop();
    server->stop();
    pool.stop();

    target_acceptor.close();
    pool_thread.join();
}
