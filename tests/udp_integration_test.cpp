#include <gtest/gtest.h>
#include <asio.hpp>
#include "local_client.h"
#include "remote_server.h"
#include "context_pool.h"
#include "crypto_util.h"
#include "mux_codec.h"
#include <thread>
#include <atomic>

using namespace mux;

class UdpIntegrationTest : public ::testing::Test
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

asio::awaitable<void> run_udp_echo_server(asio::ip::udp::socket& socket, uint16_t port)
{
    std::error_code ec;
    socket.open(asio::ip::udp::v4(), ec);
    if (ec)
    {
        LOG_ERROR("echo server open failed: {}", ec.message());
        co_return;
    }
    socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port), ec);
    if (ec)
    {
        LOG_ERROR("echo server bind failed on port {}: {}", port, ec.message());
        co_return;
    }

    char data[4096];
    asio::ip::udp::endpoint sender_ep;

    for (;;)
    {
        auto [receive_ec, n] = co_await socket.async_receive_from(asio::buffer(data), sender_ep, asio::as_tuple(asio::use_awaitable));
        if (receive_ec)
        {
            if (receive_ec != asio::error::operation_aborted)
                LOG_ERROR("echo server receive error: {}", receive_ec.message());
            break;
        }

        auto [send_ec, sn] = co_await socket.async_send_to(asio::buffer(data, n), sender_ep, asio::as_tuple(asio::use_awaitable));
        if (send_ec)
        {
            LOG_ERROR("echo server send error: {}", send_ec.message());
            break;
        }
    }
}

TEST_F(UdpIntegrationTest, UdpAssociateAndEcho)
{
    std::error_code ec;
    io_context_pool pool(4, ec);
    ASSERT_FALSE(ec);

    uint16_t server_port = 0;
    uint16_t local_socks_port = 0;
    uint16_t echo_server_port = 0;
    std::string sni = "www.google.com";

    asio::ip::tcp::acceptor server_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    server_port = server_acceptor.local_endpoint().port();
    server_acceptor.close();

    asio::ip::tcp::acceptor local_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    local_socks_port = local_acceptor.local_endpoint().port();
    local_acceptor.close();

    config::timeout_t timeouts;
    timeouts.read = 10;
    timeouts.write = 10;

    auto server = std::make_shared<remote_server>(pool, server_port, std::vector<config::fallback_entry>{}, server_priv_key, timeouts);
    server->start();

    auto client = std::make_shared<local_client>(pool, "127.0.0.1", std::to_string(server_port), local_socks_port, client_pub_key, sni, timeouts);
    client->start();

    asio::ip::udp::socket echo_socket(pool.get_io_context());

    echo_socket.open(asio::ip::udp::v4(), ec);
    echo_socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    echo_server_port = echo_socket.local_endpoint().port();
    echo_socket.close();

    asio::co_spawn(pool.get_io_context(), run_udp_echo_server(echo_socket, echo_server_port), asio::detached);

    std::thread pool_thread([&pool]() { pool.run(); });

    bool tunnel_ready = false;
    for (int i = 0; i < 20; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::atomic<bool> test_passed{false};
    std::atomic<bool> test_failed{false};
    auto client_tcp = std::make_shared<asio::ip::tcp::socket>(pool.get_io_context());
    auto client_udp = std::make_shared<asio::ip::udp::socket>(pool.get_io_context());

    asio::co_spawn(
        pool.get_io_context(),
        [&]() -> asio::awaitable<void>
        {
            std::error_code ecc;

            co_await client_tcp->async_connect({asio::ip::make_address("127.0.0.1"), local_socks_port}, asio::use_awaitable);

            uint8_t method_req[] = {0x05, 0x01, 0x00};
            co_await asio::async_write(*client_tcp, asio::buffer(method_req), asio::use_awaitable);

            uint8_t method_res[2];
            co_await asio::async_read(*client_tcp, asio::buffer(method_res), asio::use_awaitable);
            if (method_res[0] != 0x05 || method_res[1] != 0x00)
            {
                test_failed = true;
                co_return;
            }

            uint8_t associate_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            co_await asio::async_write(*client_tcp, asio::buffer(associate_req), asio::use_awaitable);

            uint8_t associate_res[10];
            co_await asio::async_read(*client_tcp, asio::buffer(associate_res), asio::use_awaitable);
            if (associate_res[1] != 0x00)
            {
                test_failed = true;
                co_return;
            }

            uint16_t proxy_bind_port = (associate_res[8] << 8) | associate_res[9];

            client_udp->open(asio::ip::udp::v4());

            std::string payload_data = "Hello UDP Multi-Stage Handshake";
            std::vector<uint8_t> packet;
            packet.push_back(0x00);
            packet.push_back(0x00);
            packet.push_back(0x00);
            packet.push_back(0x01);
            packet.push_back(127);
            packet.push_back(0);
            packet.push_back(0);
            packet.push_back(1);
            packet.push_back((echo_server_port >> 8) & 0xFF);
            packet.push_back(echo_server_port & 0xFF);
            packet.insert(packet.end(), payload_data.begin(), payload_data.end());

            asio::ip::udp::endpoint proxy_ep(asio::ip::make_address("127.0.0.1"), proxy_bind_port);
            co_await client_udp->async_send_to(asio::buffer(packet), proxy_ep, asio::use_awaitable);

            std::vector<uint8_t> recv_buf(4096);
            asio::ip::udp::endpoint sender_ep;
            auto [re, n] = co_await client_udp->async_receive_from(asio::buffer(recv_buf), sender_ep, asio::as_tuple(asio::use_awaitable));

            if (!re && n > 10)
            {
                std::string recv_payload(recv_buf.begin() + 10, recv_buf.begin() + n);
                if (recv_payload == payload_data)
                {
                    test_passed = true;
                }
                else
                {
                    test_failed = true;
                }
            }
            else
            {
                test_failed = true;
            }
        },
        asio::detached);

    for (int i = 0; i < 100; ++i)
    {
        if (test_passed || test_failed)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    client->stop();
    server->stop();

    std::error_code ignore;
    client_tcp->close(ignore);
    client_udp->close(ignore);
    echo_socket.close(ignore);

    pool.stop();
    if (pool_thread.joinable())
        pool_thread.join();

    EXPECT_TRUE(test_passed.load());
    EXPECT_FALSE(test_failed.load());
}
