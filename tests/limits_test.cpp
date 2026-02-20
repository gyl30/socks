// NOLINTBEGIN(bugprone-unused-return-value, misc-include-cleaner)
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <cstring>
#include <functional>
#include <system_error>

#include <boost/asio/read.hpp>
#include <gtest/gtest.h>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "config.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "reality_core.h"
#include "socks_client.h"
#include "remote_server.h"
#include "reality_messages.h"

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
        short_id_ = "0102030405060708";
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& client_pub_key() const { return client_pub_key_; }
    [[nodiscard]] const std::string& short_id() const { return short_id_; }

   private:
    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string short_id_;
};

TEST_F(LimitsTest, ContextPoolInvalidSize)
{
    const mux::io_context_pool pool(0);
    // Should remain usable with fallback worker count
}

TEST_F(LimitsTest, ConnectionPoolCapacity)
{
    boost::system::error_code const ec;

    mux::io_context_pool pool(4);
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

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = server_port;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout = timeouts;
    server_cfg.limits = limits;
    auto server = std::make_shared<mux::remote_server>(pool, server_cfg);

    const auto dummy_cert = reality::construct_certificate({0x01, 0x02, 0x03});
    const reality::server_fingerprint dummy_fp{};
    server->set_certificate(sni, dummy_cert, dummy_fp);

    server->start();

    const uint16_t target_port = 30080;
    boost::asio::ip::tcp::acceptor target_acceptor(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), target_port));
    std::vector<std::shared_ptr<boost::asio::ip::tcp::socket>> target_sockets;

    std::function<void()> accept_target = [&]()
    {
        auto sock = std::make_shared<boost::asio::ip::tcp::socket>(pool.get_io_context());
        target_acceptor.async_accept(*sock,
                                     [&, sock](const boost::system::error_code ec_accept)
                                     {
                                         if (!ec_accept)
                                         {
                                             target_sockets.push_back(sock);
                                             accept_target();
                                         }
                                     });
    };
    accept_target();

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = local_socks_port;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout = timeouts;
    client_cfg.limits = limits;
    auto client = std::make_shared<mux::socks_client>(pool, client_cfg);
    client->start();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto connect_socks = [&]([[maybe_unused]] int id) -> bool
    {
        boost::asio::ip::tcp::socket sock(pool.get_io_context());
        const boost::asio::ip::tcp::endpoint ep(boost::asio::ip::make_address("127.0.0.1"), local_socks_port);
        boost::system::error_code cec;
        sock.connect(ep, cec);
        if (cec)
        {
            return false;
        }

        const uint8_t ver_method[] = {0x05, 0x01, 0x00};
        (void)boost::asio::write(sock, boost::asio::buffer(ver_method), cec);
        if (cec)
        {
            return false;
        }

        uint8_t resp[2];
        (void)boost::asio::read(sock, boost::asio::buffer(resp), cec);
        if (cec || resp[1] != 0x00)
        {
            return false;
        }

        const uint16_t port_n = htons(target_port);
        uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
        std::memcpy(req + 8, &port_n, 2);

        (void)boost::asio::write(sock, boost::asio::buffer(req, 10), cec);
        if (cec)
        {
            return false;
        }

        uint8_t reply[10];
        (void)boost::asio::read(sock, boost::asio::buffer(reply), cec);

        if (!cec && reply[1] == 0x00)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            return true;
        }
        return false;
    };

    bool ok1 = false;
    bool ok2 = false;
    bool ok3 = false;
    std::thread t1([&] { ok1 = connect_socks(1); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread t2([&] { ok2 = connect_socks(2); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    std::thread t3([&] { ok3 = connect_socks(3); });

    t1.join();
    t2.join();
    t3.join();

    EXPECT_TRUE(ok1);
    EXPECT_TRUE(ok2);
    EXPECT_TRUE(ok3);

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    pool.stop();

    target_acceptor.close();
    pool_thread.join();
}
// NOLINTEND(bugprone-unused-return-value, misc-include-cleaner)
