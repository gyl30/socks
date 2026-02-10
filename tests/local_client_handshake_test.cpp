#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/read.hpp>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include "crypto_util.h"
#include "context_pool.h"
#include "local_client.h"
#include "reality_messages.h"
#include "tls_record_layer.h"

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
    }

    std::string server_pub_hex_;
};

asio::awaitable<void> mock_server_silent(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));

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

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex_;
    client_cfg.reality.sni = "example.com";
    client_cfg.timeout = timeouts;
    client_cfg.limits = limits;
    auto client = std::make_shared<mux::local_client>(pool, client_cfg);

    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

asio::awaitable<void> mock_server_invalid_sh(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));

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

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex_;
    client_cfg.reality.sni = "example.com";
    auto client = std::make_shared<mux::local_client>(pool, client_cfg);

    std::thread pool_thread([&pool]() { pool.run(); });
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

asio::awaitable<void> mock_server_unsupported_scheme(tcp::acceptor& acceptor, const std::string& server_priv_hex)
{
    auto [ec, socket] = co_await acceptor.async_accept(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> ch_buf(2048);
    auto [re1, n1] = co_await socket.async_read_some(asio::buffer(ch_buf), asio::as_tuple(asio::use_awaitable));
    if (re1)
    {
        co_return;
    }

    std::vector<uint8_t> srand(32, 0x55);
    std::vector<uint8_t> sid(32, 0);
    auto sh = reality::construct_server_hello(srand, sid, 0x1301, reality::tls_consts::group::kX25519, std::vector<uint8_t>(32, 0x66));
    auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(sh.size()));
    sh_rec.insert(sh_rec.end(), sh.begin(), sh.end());
    co_await asio::async_write(socket, asio::buffer(sh_rec), asio::as_tuple(asio::use_awaitable));

    std::vector<uint8_t> enc_ext = reality::construct_encrypted_extensions("");
    std::vector<uint8_t> cert = reality::construct_certificate({0x01, 0x02, 0x03});

    std::vector<uint8_t> cv = {0x0f, 0x00, 0x00, 0x08, 0x08, 0x08, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};

    std::vector<uint8_t> plain;
    plain.insert(plain.end(), enc_ext.begin(), enc_ext.end());
    plain.insert(plain.end(), cert.begin(), cert.end());
    plain.insert(plain.end(), cv.begin(), cv.end());

    std::error_code enc_ec;
    auto enc = reality::tls_record_layer::encrypt_record(
        EVP_aes_128_gcm(), std::vector<uint8_t>(16, 0), std::vector<uint8_t>(12, 0), 0, plain, reality::kContentTypeHandshake, enc_ec);

    co_await asio::async_write(socket, asio::buffer(enc), asio::as_tuple(asio::use_awaitable));
}

TEST_F(LocalClientHandshakeTest, UnsupportedVerifyScheme)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t port = acceptor.local_endpoint().port();

    asio::co_spawn(pool.get_io_context(), mock_server_unsupported_scheme(acceptor, server_pub_hex_), asio::detached);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex_;
    client_cfg.reality.sni = "example.com";
    auto client = std::make_shared<mux::local_client>(pool, client_cfg);

    std::thread pool_thread([&pool]() { pool.run(); });
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

}    // namespace
