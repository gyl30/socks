
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <utility>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "reality_messages.h"
#include "tls_record_layer.h"

namespace
{

using boost::asio::ip::tcp;

class local_client_handshake_test_fixture : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_pub_hex_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
    }

    [[nodiscard]] const std::string& server_pub_hex() const { return server_pub_hex_; }

   private:
    std::string server_pub_hex_;
};

boost::asio::awaitable<void> mock_server_silent(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));

    boost::asio::steady_timer timer(socket.get_executor());
    timer.expires_after(std::chrono::seconds(2));
    co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
}

TEST_F(local_client_handshake_test_fixture, HandshakeTimeout)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t const port = acceptor.local_endpoint().port();

    boost::asio::co_spawn(pool.get_io_context(), mock_server_silent(acceptor), boost::asio::detached);

    mux::config::timeout_t timeouts;
    timeouts.read = 1;
    timeouts.write = 1;

    mux::config::limits_t limits;
    limits.max_connections = 1;

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex();
    client_cfg.reality.sni = "example.com";
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout = timeouts;
    client_cfg.limits = limits;
    auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

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

boost::asio::awaitable<void> mock_server_invalid_sh(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> buf(1024);
    co_await socket.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));

    std::vector<uint8_t> garbage = {0x16, 0x03, 0x03, 0x00, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    co_await boost::asio::async_write(socket, boost::asio::buffer(garbage), boost::asio::as_tuple(boost::asio::use_awaitable));
}

TEST_F(local_client_handshake_test_fixture, InvalidServerHello)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t const port = acceptor.local_endpoint().port();

    boost::asio::co_spawn(pool.get_io_context(), mock_server_invalid_sh(acceptor), boost::asio::detached);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex();
    client_cfg.reality.sni = "example.com";
    client_cfg.reality.strict_cert_verify = false;
    auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

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

boost::asio::awaitable<void> mock_server_unsupported_scheme(tcp::acceptor& acceptor)
{
    auto [ec, socket] = co_await acceptor.async_accept(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        co_return;
    }

    std::vector<uint8_t> ch_buf(2048);
    auto [re1, n1] = co_await socket.async_read_some(boost::asio::buffer(ch_buf), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (re1)
    {
        co_return;
    }

    std::vector<uint8_t> const srand(32, 0x55);
    std::vector<uint8_t> const sid(32, 0);
    auto sh = reality::construct_server_hello(srand, sid, 0x1301, reality::tls_consts::group::kX25519, std::vector<uint8_t>(32, 0x66));
    auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(sh.size()));
    sh_rec.insert(sh_rec.end(), sh.begin(), sh.end());
    co_await boost::asio::async_write(socket, boost::asio::buffer(sh_rec), boost::asio::as_tuple(boost::asio::use_awaitable));

    std::vector<uint8_t> enc_ext = reality::construct_encrypted_extensions("");
    std::vector<uint8_t> cert = reality::construct_certificate({0x01, 0x02, 0x03});

    std::vector<uint8_t> cv = {0x0f, 0x00, 0x00, 0x08, 0x08, 0x08, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd};

    std::vector<uint8_t> plain;
    plain.insert(plain.end(), enc_ext.begin(), enc_ext.end());
    plain.insert(plain.end(), cert.begin(), cert.end());
    plain.insert(plain.end(), cv.begin(), cv.end());

    auto enc = reality::tls_record_layer::encrypt_record(
        EVP_aes_128_gcm(), std::vector<uint8_t>(16, 0), std::vector<uint8_t>(12, 0), 0, plain, reality::kContentTypeHandshake);

    co_await boost::asio::async_write(socket, boost::asio::buffer(*enc), boost::asio::as_tuple(boost::asio::use_awaitable));
}

TEST_F(local_client_handshake_test_fixture, UnsupportedVerifyScheme)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    tcp::acceptor acceptor(pool.get_io_context(), tcp::endpoint(tcp::v4(), 0));
    std::uint16_t const port = acceptor.local_endpoint().port();

    boost::asio::co_spawn(pool.get_io_context(), mock_server_unsupported_scheme(acceptor), boost::asio::detached);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = server_pub_hex();
    client_cfg.reality.sni = "example.com";
    client_cfg.reality.strict_cert_verify = false;
    auto client = std::make_shared<mux::socks_client>(pool, client_cfg);

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
