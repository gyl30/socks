#include <vector>
#include <string>
#include <thread>
#include <memory>
#include <chrono>
#include <cstdint>
#include <utility>
#include <system_error>

#include <gtest/gtest.h>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include "crypto_util.h"
#include "local_client.h"
#include "context_pool.h"

namespace
{

using asio::ip::tcp;

class LocalClientHandshakeTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_pub_hex_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        verify_key_hex_ = std::string(64, 'b');
    }

    std::string server_pub_hex_;
    std::string verify_key_hex_;
};

asio::awaitable<void> mock_server_silent(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return;

    // Read Client Hello but do nothing
    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));

    // Just wait until the test is over or client disconnects
    asio::steady_timer timer(socket.get_executor());
    timer.expires_after(std::chrono::seconds(2));
    co_await timer.async_wait(asio::as_tuple(asio::use_awaitable));
}

TEST_F(LocalClientHandshakeTest, HandshakeTimeout)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t port = acceptor.local_endpoint().port();

    asio::co_spawn(pool.get_io_context(), mock_server_silent(acceptor), asio::detached);

    mux::config::timeout_t timeouts;
    timeouts.read = 1;
    timeouts.write = 1;

    mux::config::limits_t limits;
    limits.max_connections = 1;

    auto client = std::make_shared<mux::local_client>(
        pool, "127.0.0.1", std::to_string(port), 0, server_pub_hex_, "example.com", "", verify_key_hex_, timeouts, mux::config::socks_t{}, limits);

    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();

    // The client should encounter timeout and retry.
    // We wait enough time for at least one timeout to occur.
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    client->stop();
    pool.stop();
    if (pool_thread.joinable())
        pool_thread.join();
}

asio::awaitable<void> mock_server_invalid_sh(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
    if (ec)
        co_return;

    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));

    // Send invalid Server Hello (garbage)
    std::vector<uint8_t> garbage = {0x16, 0x03, 0x03, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    co_await asio::async_write(socket, asio::buffer(garbage), asio::as_tuple(asio::use_awaitable));
}

TEST_F(LocalClientHandshakeTest, InvalidServerHello)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t port = acceptor.local_endpoint().port();

    asio::co_spawn(pool.get_io_context(), mock_server_invalid_sh(acceptor), asio::detached);

    auto client =
        std::make_shared<mux::local_client>(pool, "127.0.0.1", std::to_string(port), 0, server_pub_hex_, "example.com", "", verify_key_hex_);

    std::thread pool_thread([&pool]() { pool.run(); });
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
        pool_thread.join();
}

}    // namespace
