#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/this_coro.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"

using asio::ip::tcp;

TEST(LocalClientMockTest, HandshakeFailurePaths)
{
    mux::config::timeout_t timeouts;
    timeouts.read = 1;
    timeouts.write = 1;

    std::uint8_t pub[32], priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
    std::string server_pub_hex = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));

    mux::config::limits_t limits;
    limits.max_connections = 1;

    auto run_mock_server_and_test = [&](std::vector<std::uint8_t> data_to_send)
    {
        std::error_code ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);

        asio::io_context server_ctx;
        tcp::acceptor acceptor(server_ctx, tcp::endpoint(tcp::v4(), 0));
        std::uint16_t port = acceptor.local_endpoint().port();

        std::thread server_thread(
            [&]()
            {
                std::error_code accept_ec;
                tcp::socket socket(server_ctx);
                acceptor.accept(socket, accept_ec);
                if (!accept_ec)
                {
                    std::error_code write_ec;
                    (void)asio::write(socket, asio::buffer(data_to_send), write_ec);

                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            });

        mux::config client_cfg;
        client_cfg.outbound.host = "127.0.0.1";
        client_cfg.outbound.port = port;
        client_cfg.socks.port = 0;
        client_cfg.reality.public_key = server_pub_hex;
        client_cfg.reality.sni = "example.com";
        client_cfg.timeout = timeouts;
        client_cfg.limits = limits;
        auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

        std::thread pool_thread([&pool]() { pool.run(); });

        client->start();

        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        client->stop();
        pool.stop();
        if (pool_thread.joinable())
        {
            pool_thread.join();
        }
        if (server_thread.joinable())
        {
            server_thread.join();
        }
    };

    {
        std::vector<std::uint8_t> short_sh = {0x16, 0x03, 0x03, 0x00, 0x01};
        run_mock_server_and_test(short_sh);
    }

    {
        std::vector<uint8_t> short_sid_sh = {0x16, 0x03, 0x03, 0x00, 0x26, 0x02, 0x00, 0x00, 0x22, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        run_mock_server_and_test(short_sid_sh);
    }
}
