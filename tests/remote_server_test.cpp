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

#include "ch_parser.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "reality_auth.h"
#include "remote_server.h"
#include "reality_messages.h"
#include "statistics.h"

namespace
{

std::uint16_t pick_free_port()
{
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

}    // namespace

class remote_server_test : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& server_pub_key() const { return server_pub_key_; }
    [[nodiscard]] const std::vector<uint8_t>& info_random() const { return info_random_; }
    [[nodiscard]] mux::config make_server_cfg(std::uint16_t port,
                                              const std::vector<mux::config::fallback_entry>& fallbacks,
                                              const std::string& short_id) const
    {
        mux::config cfg;
        cfg.inbound.host = "127.0.0.1";
        cfg.inbound.port = port;
        cfg.fallbacks = fallbacks;
        cfg.reality.private_key = server_priv_key();
        cfg.reality.short_id = short_id;
        return cfg;
    }

    std::vector<uint8_t> build_valid_sid_ch(const std::string& sni,
                                            const std::string& short_id_hex,
                                            uint32_t timestamp,
                                            std::vector<uint8_t>& out_sid)
    {
        std::uint8_t c_pub[32], c_priv[32];
        if (!reality::crypto_util::generate_x25519_keypair(c_pub, c_priv))
        {
            return {};
        }
        std::error_code ec;
        auto shared =
            reality::crypto_util::x25519_derive(reality::crypto_util::hex_to_bytes(server_priv_key()), std::vector<uint8_t>(c_pub, c_pub + 32), ec);
        auto salt = std::vector<uint8_t>(info_random_.begin(), info_random_.begin() + 20);
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, reality::crypto_util::hex_to_bytes("5245414c495459"), 16, EVP_sha256(), ec);

        std::array<uint8_t, 16> payload;
        const std::array<std::uint8_t, 3> ver{1, 0, 0};
        (void)reality::build_auth_payload(reality::crypto_util::hex_to_bytes(short_id_hex), ver, timestamp, payload);

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random_, std::vector<uint8_t>(c_pub, c_pub + 32), sni);

        auto record_tmp = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record_tmp.insert(record_tmp.end(), ch_body.begin(), ch_body.end());

        auto info = mux::ch_parser::parse(record_tmp);

        std::vector<uint8_t> aad = ch_body;
        uint32_t aad_sid_offset = info.sid_offset - 5;
        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        out_sid = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                     auth_key,
                                                     std::vector<uint8_t>(info_random_.begin() + 20, info_random_.end()),
                                                     std::vector<uint8_t>(payload.begin(), payload.end()),
                                                     aad,
                                                     ec);

        auto ch_final = reality::client_hello_builder::build(spec, out_sid, info_random_, std::vector<uint8_t>(c_pub, c_pub + 32), sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_final.size()));
        record.insert(record.end(), ch_final.begin(), ch_final.end());
        return record;
    }

   private:
    std::vector<uint8_t> info_random_ = std::vector<uint8_t>(32, 0x42);
    std::string server_priv_key_;
    std::string server_pub_key_;
};

TEST_F(remote_server_test, AuthFailureTriggersFallback)
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
            {
                fallback_triggered = true;
            }
        });

    mux::config cfg;
    cfg.inbound.host = "127.0.0.1";
    cfg.inbound.port = server_port;
    cfg.fallbacks = {{"", "127.0.0.1", std::to_string(fallback_port)}};
    cfg.reality.private_key = server_priv_key();
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
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

TEST_F(remote_server_test, AuthFailShortIdMismatch)
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
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708"));
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

TEST_F(remote_server_test, ClockSkewDetected)
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
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708"));
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

TEST_F(remote_server_test, AuthFailInvalidTLSHeader)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29951;
    std::uint16_t fallback_port = 29952;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        std::vector<uint8_t> invalid_header = {0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
        asio::write(sock, asio::buffer(invalid_header));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}

TEST_F(remote_server_test, AuthFailBufferTooShort)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29961;
    std::uint16_t fallback_port = 29962;

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        std::vector<uint8_t> short_buf = {0x16, 0x03, 0x03, 0x00};
        asio::write(sock, asio::buffer(short_buf));

        sock.shutdown(asio::ip::tcp::socket::shutdown_send);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
    EXPECT_TRUE(fallback_triggered.load());
}

TEST_F(remote_server_test, FallbackResolveFail)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29971;

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(server_port, {{"", "invalid.hostname.test", "80"}}, "0102030405060708"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("TRIGGER FALLBACK"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, FallbackConnectFail)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29981;

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(server_port, {{"", "127.0.0.1", "1"}}, "0102030405060708"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("TRIGGER FALLBACK"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, InvalidAuthConfigPath)
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
            {
                fallback_triggered = true;
            }
        });

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "abc"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_msg = reality::client_hello_builder::build(
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

TEST_F(remote_server_test, MultiSNIFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 29991;
    std::uint16_t fallback_port_a = 29992;
    std::uint16_t fallback_port_b = 29993;

    asio::ip::tcp::acceptor acceptor_a(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port_a));
    asio::ip::tcp::acceptor acceptor_b(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port_b));

    std::atomic<int> fallback_a_count{0};
    std::atomic<int> fallback_b_count{0};

    acceptor_a.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_a_count++;
            }
        });
    acceptor_b.async_accept(
        [&](std::error_code ec, asio::ip::tcp::socket peer)
        {
            if (!ec)
            {
                fallback_b_count++;
            }
        });

    std::vector<mux::config::fallback_entry> fallbacks = {{"www.a.com", "127.0.0.1", std::to_string(fallback_port_a)},
                                                          {"www.b.com", "127.0.0.1", std::to_string(fallback_port_b)}};

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(server_port, fallbacks, ""));
    server->start();

    auto trigger_fallback = [&](const std::string& sni)
    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body = reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random(), std::vector<uint8_t>(32, 0), sni);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    };

    trigger_fallback("www.a.com");
    trigger_fallback("www.b.com");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_EQ(fallback_a_count.load(), 1);
    EXPECT_EQ(fallback_b_count.load(), 1);
}

TEST_F(remote_server_test, FallbackGuardRateLimitBlocksFallbackDial)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    const std::uint16_t server_port = pick_free_port();
    const std::uint16_t fallback_port = pick_free_port();

    asio::ip::tcp::acceptor fallback_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), fallback_port));
    std::atomic<bool> fallback_triggered{false};
    fallback_acceptor.async_accept(
        [&](std::error_code accept_ec, asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                fallback_triggered = true;
            }
        });

    auto cfg = make_server_cfg(server_port, {{"", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    const auto before = mux::statistics::instance().fallback_rate_limited();
    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        std::error_code connect_ec;
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        ASSERT_FALSE(connect_ec);
        asio::write(sock, asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    std::error_code close_ec;
    fallback_acceptor.cancel(close_ec);
    fallback_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_FALSE(fallback_triggered.load());
    EXPECT_GT(mux::statistics::instance().fallback_rate_limited(), before);
}

TEST_F(remote_server_test, FallbackGuardCircuitBreakerBlocksSubsequentAttempt)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    const std::uint16_t server_port = pick_free_port();
    auto cfg = make_server_cfg(server_port, {{"", "127.0.0.1", "1"}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.circuit_fail_threshold = 1;
    cfg.reality.fallback_guard.circuit_open_sec = 2;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    const auto before = mux::statistics::instance().fallback_rate_limited();

    auto trigger_invalid = [&]()
    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        std::error_code connect_ec;
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port}, connect_ec);
        EXPECT_FALSE(connect_ec);
        if (connect_ec)
        {
            return;
        }
        asio::write(sock, asio::buffer("TRIGGER FALLBACK"));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    };

    trigger_invalid();
    trigger_invalid();

    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_GT(mux::statistics::instance().fallback_rate_limited(), before);
}
