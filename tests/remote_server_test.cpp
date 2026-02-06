#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/buffer.hpp>

#include "ch_parser.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "remote_server.h"
#include "reality_messages.h"

class RemoteServerTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
    }
    std::string server_priv_key;
    std::string server_pub_key;

    std::vector<uint8_t> build_valid_sid_ch(const std::string& sni,
                                            const std::string& short_id_hex,
                                            uint32_t timestamp,
                                            std::vector<uint8_t>& out_sid)
    {
        std::uint8_t c_pub[32], c_priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(c_pub, c_priv));
        std::error_code ec;
        auto shared =
            reality::crypto_util::x25519_derive(reality::crypto_util::hex_to_bytes(server_priv_key), std::vector<uint8_t>(c_pub, c_pub + 32), ec);
        auto salt = std::vector<uint8_t>(info_random.begin(), info_random.begin() + 20);
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, reality::crypto_util::hex_to_bytes("5245414c495459"), 16, EVP_sha256(), ec);

        std::array<uint8_t, 16> payload;
        (void)reality::build_auth_payload(reality::crypto_util::hex_to_bytes(short_id_hex), timestamp, payload);

        auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
        auto ch_body =
            reality::ClientHelloBuilder::build(spec, std::vector<uint8_t>(32, 0), info_random, std::vector<uint8_t>(c_pub, c_pub + 32), sni);

        auto record_tmp = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record_tmp.insert(record_tmp.end(), ch_body.begin(), ch_body.end());

        auto info = mux::ch_parser::parse(record_tmp);

        std::vector<uint8_t> aad = ch_body;
        uint32_t aad_sid_offset = info.sid_offset - 5;
        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        out_sid = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                     auth_key,
                                                     std::vector<uint8_t>(info_random.begin() + 20, info_random.end()),
                                                     std::vector<uint8_t>(payload.begin(), payload.end()),
                                                     aad,
                                                     ec);

        auto ch_final = reality::ClientHelloBuilder::build(spec, out_sid, info_random, std::vector<uint8_t>(c_pub, c_pub + 32), sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_final.size()));
        record.insert(record.end(), ch_final.begin(), ch_final.end());
        return record;
    }
    std::vector<uint8_t> info_random = std::vector<uint8_t>(32, 0x42);
};

TEST_F(RemoteServerTest, AuthFailureTriggersFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29911;
    std::uint16_t fallback_port = 29912;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    auto server = std::make_shared<mux::remote_server>(pool,
                                                       server_port,
                                                       std::vector<mux::config::fallback_entry>{{"", "127.0.0.1", std::to_string(fallback_port)}},
                                                       server_priv_key,
                                                       "",
                                                       mux::config::timeout_t{},
                                                       mux::config::limits_t{});
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}

TEST_F(RemoteServerTest, AuthFailShortIdMismatch)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29928;
    std::uint16_t fallback_port = 29929;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    auto server = std::make_shared<mux::remote_server>(pool,
                                                       server_port,
                                                       std::vector<mux::config::fallback_entry>{{"", "127.0.0.1", std::to_string(fallback_port)}},
                                                       server_priv_key,
                                                       "0102030405060708",
                                                       mux::config::timeout_t{},
                                                       mux::config::limits_t{});
    server->start();

    std::vector<uint8_t> sid;

    auto record = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<uint32_t>(time(nullptr)), sid);

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}

TEST_F(RemoteServerTest, ClockSkewDetected)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29932;
    std::uint16_t fallback_port = 29933;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    auto server = std::make_shared<mux::remote_server>(pool,
                                                       server_port,
                                                       std::vector<mux::config::fallback_entry>{{"", "127.0.0.1", std::to_string(fallback_port)}},
                                                       server_priv_key,
                                                       "0102030405060708",
                                                       mux::config::timeout_t{},
                                                       mux::config::limits_t{});
    server->start();

    std::vector<uint8_t> sid;

    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<uint32_t>(time(nullptr) - 1000), sid);

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}

TEST_F(RemoteServerTest, InvalidAuthConfigPath)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29943;
    std::uint16_t fallback_port = 29944;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
                fallback_triggered = true;
        });

    auto server = std::make_shared<mux::remote_server>(pool,
                                                       server_port,
                                                       std::vector<mux::config::fallback_entry>{{"", "127.0.0.1", std::to_string(fallback_port)}},
                                                       server_priv_key,
                                                       "abc",
                                                       mux::config::timeout_t{},
                                                       mux::config::limits_t{});
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
        auto ch_msg = reality::ClientHelloBuilder::build(
            spec, std::vector<uint8_t>(32, 0), std::vector<uint8_t>(32, 0), std::vector<uint8_t>(32, 0), "www.google.com");
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_msg.size()));
        record.insert(record.end(), ch_msg.begin(), ch_msg.end());
        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}
