#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>

#include <sys/socket.h>
#include <unistd.h>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "ch_parser.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "mux_codec.h"
#include "mock_mux_connection.h"
#include "reality_auth.h"
#define private public
#include "remote_server.h"
#undef private
#include "reality_messages.h"
#include "statistics.h"

namespace
{

std::atomic<bool> g_fail_socket_once{false};
std::atomic<int> g_fail_socket_errno{EMFILE};
std::atomic<bool> g_fail_reuse_setsockopt_once{false};
std::atomic<int> g_fail_reuse_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_listen_once{false};
std::atomic<int> g_fail_listen_errno{EACCES};
std::atomic<bool> g_fail_shutdown_once{false};
std::atomic<int> g_fail_shutdown_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};
std::atomic<bool> g_fail_rand_bytes_once{false};
std::atomic<bool> g_fail_ed25519_raw_private_key_once{false};
std::atomic<bool> g_fail_pkey_derive_once{false};
std::atomic<int> g_fail_hkdf_add_info_on_call{0};
std::atomic<int> g_hkdf_add_info_call_counter{0};

void fail_next_socket(const int err)
{
    g_fail_socket_errno.store(err, std::memory_order_release);
    g_fail_socket_once.store(true, std::memory_order_release);
}

void fail_next_reuse_setsockopt(const int err)
{
    g_fail_reuse_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_reuse_setsockopt_once.store(true, std::memory_order_release);
}

void fail_next_listen(const int err)
{
    g_fail_listen_errno.store(err, std::memory_order_release);
    g_fail_listen_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

void fail_next_shutdown(const int err)
{
    g_fail_shutdown_errno.store(err, std::memory_order_release);
    g_fail_shutdown_once.store(true, std::memory_order_release);
}

void fail_next_rand_bytes() { g_fail_rand_bytes_once.store(true, std::memory_order_release); }

void fail_next_ed25519_raw_private_key() { g_fail_ed25519_raw_private_key_once.store(true, std::memory_order_release); }

void fail_next_pkey_derive() { g_fail_pkey_derive_once.store(true, std::memory_order_release); }

void fail_hkdf_add_info_on_call(const int call_index)
{
    g_hkdf_add_info_call_counter.store(0, std::memory_order_release);
    g_fail_hkdf_add_info_on_call.store(call_index, std::memory_order_release);
}

extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_listen(int sockfd, int backlog);
extern "C" int __real_shutdown(int sockfd, int how);
extern "C" int __real_close(int fd);
extern "C" int __real_RAND_bytes(unsigned char* buf, int num);
extern "C" EVP_PKEY* __real_EVP_PKEY_new_raw_private_key(int type, ENGINE* e, const unsigned char* key, size_t keylen);
extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);
extern "C" int __real_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_REUSEADDR && g_fail_reuse_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_reuse_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_listen(int sockfd, int backlog)
{
    if (g_fail_listen_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_listen_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_listen(sockfd, backlog);
}

extern "C" int __wrap_shutdown(int sockfd, int how)
{
    if (g_fail_shutdown_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_shutdown_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_shutdown(sockfd, how);
}

extern "C" int __wrap_close(int fd)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);
}

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)
{
    if (g_fail_rand_bytes_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);
}

extern "C" EVP_PKEY* __wrap_EVP_PKEY_new_raw_private_key(int type, ENGINE* e, const unsigned char* key, size_t keylen)
{
    if (type == EVP_PKEY_ED25519 && g_fail_ed25519_raw_private_key_once.exchange(false, std::memory_order_acq_rel))
    {
        return nullptr;
    }
    return __real_EVP_PKEY_new_raw_private_key(type, e, key, keylen);
}

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)
{
    if (g_fail_pkey_derive_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);
}

extern "C" int __wrap_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen)
{
    const int call_no = g_hkdf_add_info_call_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
    const int fail_on = g_fail_hkdf_add_info_on_call.load(std::memory_order_acquire);
    if (fail_on > 0 && call_no == fail_on)
    {
        g_fail_hkdf_add_info_on_call.store(0, std::memory_order_release);
        return 0;
    }
    return __real_EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);
}

std::uint16_t pick_free_port()
{
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

template <typename Predicate>
bool wait_for_condition(Predicate predicate,
                        const std::chrono::milliseconds timeout = std::chrono::milliseconds(1500),
                        const std::chrono::milliseconds interval = std::chrono::milliseconds(10))
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
        {
            return true;
        }
        std::this_thread::sleep_for(interval);
    }
    return predicate();
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
        auto shared =
            reality::crypto_util::x25519_derive(reality::crypto_util::hex_to_bytes(server_priv_key()), std::vector<uint8_t>(c_pub, c_pub + 32));
        if (!shared)
        {
            return {};
        }
        auto salt = std::vector<uint8_t>(info_random_.begin(), info_random_.begin() + 20);
        auto prk = reality::crypto_util::hkdf_extract(salt, *shared, EVP_sha256());
        if (!prk)
        {
            return {};
        }
        auto auth_key = reality::crypto_util::hkdf_expand(*prk, reality::crypto_util::hex_to_bytes("5245414c495459"), 16, EVP_sha256());
        if (!auth_key)
        {
            return {};
        }

        std::array<uint8_t, 16> payload;
        const std::array<std::uint8_t, 3> ver{1, 0, 0};
        if (!reality::build_auth_payload(reality::crypto_util::hex_to_bytes(short_id_hex), ver, timestamp, payload))
        {
            return {};
        }

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random_, std::vector<uint8_t>(c_pub, c_pub + 32), sni);

        auto record_tmp = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record_tmp.insert(record_tmp.end(), ch_body.begin(), ch_body.end());

        auto info = mux::ch_parser::parse(record_tmp);
        if (info.sid_offset < 5)
        {
            return {};
        }

        std::vector<uint8_t> aad = ch_body;
        const std::uint32_t aad_sid_offset = info.sid_offset - 5;
        if (aad_sid_offset + 32 > aad.size())
        {
            return {};
        }
        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        auto sid_res = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                          *auth_key,
                                                          std::vector<uint8_t>(info_random_.begin() + 20, info_random_.end()),
                                                          std::vector<uint8_t>(payload.begin(), payload.end()),
                                                          aad);
        if (!sid_res || sid_res->size() != 32)
        {
            return {};
        }
        out_sid = std::move(*sid_res);

        std::copy(out_sid.begin(), out_sid.end(), ch_body.begin() + static_cast<std::ptrdiff_t>(aad_sid_offset));
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
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
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, AuthFailShortIdMismatch)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, ClockSkewDetected)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, AuthFailInvalidTLSHeader)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, AuthFailBufferTooShort)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, FallbackResolveFail)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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
    mux::io_context_pool pool(1);
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
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, MultiSNIFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    EXPECT_TRUE(wait_for_condition([&fallback_a_count]() { return fallback_a_count.load() == 1; }));
    EXPECT_TRUE(wait_for_condition([&fallback_b_count]() { return fallback_b_count.load() == 1; }));

    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_EQ(fallback_a_count.load(), 1);
    EXPECT_EQ(fallback_b_count.load(), 1);
}

TEST_F(remote_server_test, WildcardStarFallback)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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

    auto server = std::make_shared<mux::remote_server>(
        pool, make_server_cfg(server_port, {{"*", "127.0.0.1", std::to_string(fallback_port)}}, "0102030405060708"));
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&fallback_triggered]() { return fallback_triggered.load(); }));
    std::error_code close_ec;
    fallback_acceptor.cancel(close_ec);
    fallback_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, RealityDestFallbackUsedWhenNoFallbackEntries)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    const std::uint16_t server_port = pick_free_port();
    const std::uint16_t dest_port = pick_free_port();

    asio::ip::tcp::acceptor dest_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), dest_port));
    std::atomic<bool> dest_triggered{false};
    dest_acceptor.async_accept(
        [&](std::error_code accept_ec, asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                dest_triggered = true;
            }
        });

    auto cfg = make_server_cfg(server_port, {}, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});
        asio::write(sock, asio::buffer("INVALID DATA"));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&dest_triggered]() { return dest_triggered.load(); }));
    std::error_code close_ec;
    dest_acceptor.cancel(close_ec);
    dest_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_TRUE(dest_triggered.load());
}

TEST_F(remote_server_test, ExactSniFallbackPreferredOverRealityDest)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    const std::uint16_t server_port = pick_free_port();
    const std::uint16_t exact_port = pick_free_port();
    const std::uint16_t dest_port = pick_free_port();

    asio::ip::tcp::acceptor exact_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), exact_port));
    asio::ip::tcp::acceptor dest_acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), dest_port));
    std::atomic<int> exact_count{0};
    std::atomic<int> dest_count{0};
    exact_acceptor.async_accept(
        [&](std::error_code accept_ec, asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                exact_count++;
            }
        });
    dest_acceptor.async_accept(
        [&](std::error_code accept_ec, asio::ip::tcp::socket peer)
        {
            if (!accept_ec)
            {
                dest_count++;
            }
        });

    std::vector<mux::config::fallback_entry> fallbacks = {{"www.exact.test", "127.0.0.1", std::to_string(exact_port)}};
    auto cfg = make_server_cfg(server_port, fallbacks, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    {
        asio::ip::tcp::socket sock(pool.get_io_context());
        sock.connect({asio::ip::make_address("127.0.0.1"), server_port});

        auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
        auto ch_body =
            reality::client_hello_builder::build(spec, std::vector<uint8_t>(32, 0), info_random(), std::vector<uint8_t>(32, 0), "www.exact.test");
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_body.size()));
        record.insert(record.end(), ch_body.begin(), ch_body.end());
        asio::write(sock, asio::buffer(record));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    EXPECT_TRUE(wait_for_condition([&exact_count]() { return exact_count.load() == 1; }));
    EXPECT_TRUE(wait_for_condition([&dest_count]() { return dest_count.load() == 0; }));
    std::error_code close_ec;
    exact_acceptor.cancel(close_ec);
    exact_acceptor.close(close_ec);
    dest_acceptor.cancel(close_ec);
    dest_acceptor.close(close_ec);
    server->stop();
    pool.stop();
    pool_thread.join();

    EXPECT_EQ(exact_count.load(), 1);
    EXPECT_EQ(dest_count.load(), 0);
}

TEST_F(remote_server_test, FallbackGuardRateLimitBlocksFallbackDial)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
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
    mux::io_context_pool pool(1);
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

TEST_F(remote_server_test, ConstructorHandlesInvalidInboundHostAndUnsupportedFallbackType)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg.inbound.host = "not-a-valid-ip";
    cfg.reality.type = "udp";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_EQ(server->fallback_type_, "udp");
    EXPECT_TRUE(server->auth_config_valid_);
}

TEST_F(remote_server_test, ConstructorRejectsInvalidRealityDest)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg.reality.dest = "invalid-dest-without-port";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_FALSE(server->fallback_dest_valid_);
    EXPECT_FALSE(server->auth_config_valid_);
}

TEST_F(remote_server_test, ConstructorRejectsInvalidPrivateKeyLength)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg.reality.private_key = "0102";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_FALSE(server->auth_config_valid_);
}

TEST_F(remote_server_test, ConstructorReturnsEarlyWhenBindFails)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    asio::ip::tcp::acceptor occupied(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto used_port = occupied.local_endpoint().port();

    auto cfg = make_server_cfg(used_port, {}, "0102030405060708");
    cfg.inbound.host = "127.0.0.1";
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    EXPECT_TRUE(server->private_key_.empty());
}

TEST_F(remote_server_test, FallbackSelectionAndCertificateTargetBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const std::uint16_t exact_port = pick_free_port();
    const std::uint16_t wildcard_port = pick_free_port();
    const std::uint16_t dest_port = pick_free_port();
    std::vector<mux::config::fallback_entry> fallbacks = {
        {"www.exact.test", "127.0.0.1", std::to_string(exact_port)},
        {"*", "127.0.0.1", std::to_string(wildcard_port)},
    };

    auto cfg = make_server_cfg(pick_free_port(), fallbacks, "0102030405060708");
    cfg.reality.dest = std::string("127.0.0.1:") + std::to_string(dest_port);
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    const auto exact = server->find_fallback_target_by_sni("www.exact.test");
    EXPECT_EQ(exact.first, "127.0.0.1");
    EXPECT_EQ(exact.second, std::to_string(exact_port));

    const auto wildcard = server->find_fallback_target_by_sni("other.domain");
    EXPECT_EQ(wildcard.first, "127.0.0.1");
    EXPECT_EQ(wildcard.second, std::to_string(wildcard_port));

    server->fallbacks_.clear();
    const auto dest = server->find_fallback_target_by_sni("none");
    EXPECT_EQ(dest.first, "127.0.0.1");
    EXPECT_EQ(dest.second, std::to_string(dest_port));

    mux::client_hello_info info{};
    info.sni.clear();
    const auto target = server->resolve_certificate_target(info);
    EXPECT_EQ(target.fetch_host, "127.0.0.1");
    EXPECT_EQ(target.fetch_port, static_cast<std::uint16_t>(dest_port));
    EXPECT_EQ(target.cert_sni, "127.0.0.1");
}

TEST_F(remote_server_test, FallbackGuardStateMachineBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 1;
    cfg.reality.fallback_guard.circuit_fail_threshold = 1;
    cfg.reality.fallback_guard.circuit_open_sec = 1;
    cfg.reality.fallback_guard.state_ttl_sec = 1;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    mux::connection_context ctx;
    EXPECT_EQ(server->fallback_guard_key(ctx), "unknown");
    ctx.remote_addr("127.0.0.2");
    EXPECT_EQ(server->fallback_guard_key(ctx), "127.0.0.2");

    EXPECT_TRUE(server->consume_fallback_token(ctx));
    EXPECT_FALSE(server->consume_fallback_token(ctx));

    server->record_fallback_result(ctx, false);
    EXPECT_FALSE(server->consume_fallback_token(ctx));
    server->record_fallback_result(ctx, true);

    {
        std::lock_guard<std::mutex> lock(server->fallback_guard_mu_);
        ASSERT_FALSE(server->fallback_guard_states_.empty());
        const auto future = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        server->cleanup_fallback_guard_state_locked(future);
    }

    {
        std::lock_guard<std::mutex> lock(server->fallback_guard_mu_);
        EXPECT_TRUE(server->fallback_guard_states_.empty());
    }

    mux::connection_context unknown_ctx;
    unknown_ctx.remote_addr("127.0.0.9");
    server->record_fallback_result(unknown_ctx, false);
}

TEST_F(remote_server_test, SetCertificateAsyncPathAfterStart)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    auto server = std::make_shared<mux::remote_server>(pool, cfg);
    server->start();

    reality::server_fingerprint fingerprint;
    fingerprint.cipher_suite = 0x1301;
    fingerprint.alpn = "h2";
    const std::string sni = "post.start.test";
    server->set_certificate(sni, reality::construct_certificate({0x01, 0x02, 0x03}), fingerprint, "trace-1");

    const auto cert_opt = server->cert_manager_.get_certificate(sni);
    EXPECT_TRUE(cert_opt.has_value());

    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(remote_server_test, ConstructorCoversShortIdAndDestParsingBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg_invalid_hex = make_server_cfg(pick_free_port(), {}, "zz");
    auto server_invalid_hex = std::make_shared<mux::remote_server>(pool, cfg_invalid_hex);
    EXPECT_FALSE(server_invalid_hex->auth_config_valid_);

    auto cfg_long_short_id = make_server_cfg(pick_free_port(), {}, "010203040506070809");
    auto server_long_short_id = std::make_shared<mux::remote_server>(pool, cfg_long_short_id);
    EXPECT_FALSE(server_long_short_id->auth_config_valid_);

    auto cfg_ipv6_dest = make_server_cfg(pick_free_port(), {{"www.example.test", "127.0.0.1", "not-a-port"}}, "0102030405060708");
    cfg_ipv6_dest.reality.dest = "[::1]:8443";
    auto server_ipv6_dest = std::make_shared<mux::remote_server>(pool, cfg_ipv6_dest);
    EXPECT_TRUE(server_ipv6_dest->fallback_dest_valid_);
    EXPECT_EQ(server_ipv6_dest->fallback_dest_host_, "::1");
    EXPECT_EQ(server_ipv6_dest->fallback_dest_port_, "8443");

    mux::client_hello_info info{};
    info.sni = "www.example.test";
    const auto target = server_ipv6_dest->resolve_certificate_target(info);
    EXPECT_EQ(target.fetch_host, "127.0.0.1");
    EXPECT_EQ(target.fetch_port, static_cast<std::uint16_t>(443));

    auto cfg_port_suffix = make_server_cfg(pick_free_port(), {{"www.port.test", "127.0.0.1", "443abc"}}, "0102030405060708");
    auto server_port_suffix = std::make_shared<mux::remote_server>(pool, cfg_port_suffix);
    mux::client_hello_info suffix_info{};
    suffix_info.sni = "www.port.test";
    const auto suffix_target = server_port_suffix->resolve_certificate_target(suffix_info);
    EXPECT_EQ(suffix_target.fetch_host, "127.0.0.1");
    EXPECT_EQ(suffix_target.fetch_port, static_cast<std::uint16_t>(443));
}

TEST_F(remote_server_test, ParseClientHelloAndTranscriptGuardBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));

    std::string client_sni = "seed";
    const auto empty_info = mux::remote_server::parse_client_hello({}, client_sni);
    EXPECT_FALSE(empty_info.is_tls13);
    EXPECT_TRUE(client_sni.empty());

    reality::transcript trans;
    mux::connection_context ctx;
    EXPECT_FALSE(server->init_handshake_transcript({0x16, 0x03, 0x03, 0x00, 0x00}, trans, ctx));
    EXPECT_TRUE(server->init_handshake_transcript({0x16, 0x03, 0x03, 0x00, 0x01, 0x01}, trans, ctx));
}

TEST_F(remote_server_test, AuthenticateClientFailureBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    mux::connection_context ctx;

    mux::client_hello_info invalid_tls_info{};
    invalid_tls_info.is_tls13 = false;
    invalid_tls_info.session_id.assign(32, 0x01);
    EXPECT_FALSE(server->authenticate_client(invalid_tls_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    mux::client_hello_info missing_share_info{};
    missing_share_info.is_tls13 = true;
    missing_share_info.session_id.assign(32, 0x02);
    missing_share_info.random.assign(32, 0x03);
    EXPECT_FALSE(server->authenticate_client(missing_share_info, std::vector<std::uint8_t>(64, 0x00), ctx));

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    mux::client_hello_info sid_offset_info{};
    sid_offset_info.is_tls13 = true;
    sid_offset_info.has_x25519_share = true;
    sid_offset_info.x25519_pub.assign(peer_pub, peer_pub + 32);
    sid_offset_info.session_id.assign(32, 0x11);
    sid_offset_info.random.assign(32, 0x22);
    sid_offset_info.sid_offset = 3;
    EXPECT_FALSE(server->authenticate_client(sid_offset_info, std::vector<std::uint8_t>(64, 0x33), ctx));

    mux::client_hello_info aad_mismatch_info = sid_offset_info;
    aad_mismatch_info.sid_offset = 200;
    EXPECT_FALSE(server->authenticate_client(aad_mismatch_info, std::vector<std::uint8_t>(40, 0x44), ctx));
}

TEST_F(remote_server_test, AuthenticateClientShortIdAndTimestampFailureBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    mux::connection_context ctx;

    std::vector<std::uint8_t> sid_mismatch;
    const auto record_mismatch = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<std::uint32_t>(time(nullptr)), sid_mismatch);
    const auto info_mismatch = mux::ch_parser::parse(record_mismatch);
    EXPECT_FALSE(server->authenticate_client(info_mismatch, record_mismatch, ctx));

    std::vector<std::uint8_t> sid_skew;
    const auto record_skew = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr) - 1000), sid_skew);
    const auto info_skew = mux::ch_parser::parse(record_skew);
    EXPECT_FALSE(server->authenticate_client(info_skew, record_skew, ctx));
}

TEST_F(remote_server_test, DeriveShareAndFallbackHelperBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));

    mux::client_hello_info no_share_info{};
    std::array<std::uint8_t, 32> pub_key{};
    std::array<std::uint8_t, 32> priv_key{};
    const auto key_share_res = server->derive_server_key_share(no_share_info, pub_key.data(), priv_key.data(), mux::connection_context{});
    EXPECT_FALSE(key_share_res.has_value());
    EXPECT_EQ(key_share_res.error(), std::errc::invalid_argument);

    mux::remote_server::server_handshake_res bad_handshake{};
    bad_handshake.cipher = EVP_aes_128_gcm();
    bad_handshake.negotiated_md = EVP_sha256();
    bad_handshake.handshake_hash.assign(32, 0x55);
    bad_handshake.hs_keys.master_secret.clear();
    const auto app_keys_res = server->derive_application_traffic_keys(bad_handshake);
    EXPECT_FALSE(app_keys_res.has_value());
    EXPECT_TRUE(app_keys_res.error());

    mux::connection_context ctx;
    server->record_fallback_result(ctx, false);
}

TEST_F(remote_server_test, RejectStreamForLimitSendsAckAndReset)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    auto conn = std::make_shared<mux::mock_mux_connection>(pool.get_io_context());

    mux::connection_context ctx;
    ctx.conn_id(7);
    ctx.trace_id("reject-limit");

    EXPECT_CALL(*conn, mock_send_async(42, mux::kCmdAck, testing::_))
        .WillOnce(
            [](std::uint32_t, std::uint8_t, const std::vector<std::uint8_t>& payload)
            {
                mux::ack_payload ack{};
                EXPECT_TRUE(mux::mux_codec::decode_ack(payload.data(), payload.size(), ack));
                EXPECT_EQ(ack.socks_rep, socks::kRepGenFail);
                return std::error_code{};
            });
    EXPECT_CALL(*conn, mock_send_async(42, mux::kCmdRst, testing::_)).WillOnce(testing::Return(std::error_code{}));

    std::promise<void> done;
    auto done_future = done.get_future();
    asio::co_spawn(pool.get_io_context(),
                   [server, conn, ctx, &done]() mutable -> asio::awaitable<void>
                   {
                       co_await server->reject_stream_for_limit(conn, ctx, 42);
                       done.set_value();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    EXPECT_EQ(done_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    pool.stop();
    runner.join();
}

TEST_F(remote_server_test, FallbackFailedAndGuardDisabledBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = false;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    mux::connection_context guard_ctx;
    guard_ctx.remote_addr("127.0.0.8");
    EXPECT_TRUE(server->consume_fallback_token(guard_ctx));
    server->record_fallback_result(guard_ctx, false);

    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));

    asio::ip::tcp::socket client_socket(io_context);
    client_socket.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    asio::ip::tcp::socket peer_socket(io_context);
    acceptor.accept(peer_socket, ec);
    ASSERT_FALSE(ec);

    auto fallback_socket = std::make_shared<asio::ip::tcp::socket>(std::move(client_socket));

    bool drain_done = false;
    asio::co_spawn(io_context,
                   [fallback_socket, &drain_done]() -> asio::awaitable<void>
                   {
                       co_await mux::remote_server::fallback_failed(fallback_socket);
                       drain_done = true;
                       co_return;
                   },
                   asio::detached);

    const std::string payload = "fallback-data";
    asio::write(peer_socket, asio::buffer(payload), ec);
    ASSERT_FALSE(ec);
    peer_socket.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    peer_socket.close(ec);

    io_context.run();
    EXPECT_TRUE(drain_done);

    io_context.restart();
    bool timer_done = false;
    asio::co_spawn(io_context,
                   [&io_context, &timer_done]() -> asio::awaitable<void>
                   {
                       co_await mux::remote_server::fallback_failed_timer(123, io_context);
                       timer_done = true;
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_TRUE(timer_done);
}

TEST_F(remote_server_test, PerformHandshakeResponseCoversCipherSuiteSelectionBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));

    reality::server_fingerprint invalid_fp;
    invalid_fp.cipher_suite = 0x9999;
    invalid_fp.alpn = "h2";
    server->set_certificate("cipher.invalid", reality::construct_certificate({0x01, 0x02, 0x03}), invalid_fp, "trace-invalid");

    reality::server_fingerprint chacha_fp;
    chacha_fp.cipher_suite = 0x1303;
    chacha_fp.alpn = "h2";
    server->set_certificate("cipher.chacha", reality::construct_certificate({0x01, 0x02, 0x03}), chacha_fp, "trace-chacha");

    auto run_once = [&](const std::string& sni, const std::uint32_t conn_id, const bool expect_ok) -> mux::remote_server::server_handshake_res
    {
        asio::ip::tcp::acceptor acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
        asio::ip::tcp::socket client_socket(pool.get_io_context());
        client_socket.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);

        auto server_socket = std::make_shared<asio::ip::tcp::socket>(pool.get_io_context());
        acceptor.accept(*server_socket, ec);
        EXPECT_FALSE(ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        EXPECT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        mux::client_hello_info info{};
        info.sni = sni;
        info.session_id.assign(32, 0x11);
        info.has_x25519_share = true;
        info.x25519_pub.assign(peer_pub, peer_pub + 32);

        mux::connection_context ctx;
        ctx.conn_id(conn_id);
        ctx.trace_id(sni);

        std::promise<std::pair<mux::remote_server::server_handshake_res, std::error_code>> done;
        auto done_future = done.get_future();
        asio::co_spawn(pool.get_io_context(),
                       [server, server_socket, info, ctx, &done]() mutable -> asio::awaitable<void>
                       {
                           reality::transcript trans;
                           auto res = co_await server->perform_handshake_response(server_socket, info, trans, ctx);
                           done.set_value({std::move(res), res.ec});
                           co_return;
                       },
                       asio::detached);

        EXPECT_EQ(done_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        auto [result, hs_ec] = done_future.get();
        if (expect_ok)
        {
            EXPECT_FALSE(hs_ec);
            EXPECT_TRUE(result.ok);
        }
        else
        {
            EXPECT_TRUE(hs_ec);
            EXPECT_FALSE(result.ok);
        }
        return result;
    };

    const auto invalid_res = run_once("cipher.invalid", 71, true);
    EXPECT_EQ(invalid_res.cipher, EVP_aes_128_gcm());

    (void)run_once("cipher.chacha", 72, false);

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test, ConstructorCoversMalformedBracketDestParseBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg_missing_bracket = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg_missing_bracket.reality.dest = "[::1";
    auto server_missing_bracket = std::make_shared<mux::remote_server>(pool, cfg_missing_bracket);
    EXPECT_FALSE(server_missing_bracket->fallback_dest_valid_);
    EXPECT_FALSE(server_missing_bracket->auth_config_valid_);

    auto cfg_missing_colon = make_server_cfg(pick_free_port(), {}, "0102030405060708");
    cfg_missing_colon.reality.dest = "[::1]8443";
    auto server_missing_colon = std::make_shared<mux::remote_server>(pool, cfg_missing_colon);
    EXPECT_FALSE(server_missing_colon->fallback_dest_valid_);
    EXPECT_FALSE(server_missing_colon->auth_config_valid_);
}

TEST_F(remote_server_test, ConstructorAcceptorSetupFailureBranchesWithWrappers)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto open_fail_port = pick_free_port();
    fail_next_socket(EMFILE);
    auto open_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(open_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(open_fail_server->private_key_.empty());

    const auto reuse_fail_port = pick_free_port();
    fail_next_reuse_setsockopt(EPERM);
    auto reuse_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(reuse_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(reuse_fail_server->private_key_.empty());

    const auto listen_fail_port = pick_free_port();
    fail_next_listen(EACCES);
    auto listen_fail_server = std::make_shared<mux::remote_server>(pool, make_server_cfg(listen_fail_port, {}, "0102030405060708"));
    EXPECT_TRUE(listen_fail_server->private_key_.empty());
}

TEST_F(remote_server_test, AuthenticateClientCoversShortIdClockSkewAndReplayBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    mux::connection_context ctx;

    const auto short_id_before = mux::statistics::instance().auth_short_id_failures();
    const auto skew_before = mux::statistics::instance().auth_clock_skew_failures();
    const auto replay_before = mux::statistics::instance().auth_replay_failures();

    std::vector<std::uint8_t> sid_mismatch;
    const auto record_mismatch = build_valid_sid_ch("www.google.com", "ffffffffffffffff", static_cast<std::uint32_t>(time(nullptr)), sid_mismatch);
    const auto info_mismatch = mux::ch_parser::parse(record_mismatch);
    EXPECT_FALSE(server->authenticate_client(info_mismatch, record_mismatch, ctx));

    std::vector<std::uint8_t> sid_skew;
    const auto record_skew = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr) - 1000), sid_skew);
    const auto info_skew = mux::ch_parser::parse(record_skew);
    EXPECT_FALSE(server->authenticate_client(info_skew, record_skew, ctx));

    std::vector<std::uint8_t> sid_ok;
    const auto record_ok = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid_ok);
    const auto info_ok = mux::ch_parser::parse(record_ok);
    EXPECT_TRUE(server->authenticate_client(info_ok, record_ok, ctx));
    EXPECT_FALSE(server->authenticate_client(info_ok, record_ok, ctx));

    EXPECT_GT(mux::statistics::instance().auth_short_id_failures(), short_id_before);
    EXPECT_GT(mux::statistics::instance().auth_clock_skew_failures(), skew_before);
    EXPECT_GT(mux::statistics::instance().auth_replay_failures(), replay_before);
}

TEST_F(remote_server_test, AuthenticateClientCoversInvalidPayloadAndShortIdLengthBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    mux::connection_context ctx;

    std::vector<std::uint8_t> sid_ok;
    auto record = build_valid_sid_ch("www.google.com", "0102030405060708", static_cast<std::uint32_t>(time(nullptr)), sid_ok);
    auto info = mux::ch_parser::parse(record);
    ASSERT_EQ(info.session_id.size(), 32u);

    auto invalid_payload_info = info;
    invalid_payload_info.session_id[0] ^= 0x01;
    EXPECT_FALSE(server->authenticate_client(invalid_payload_info, record, ctx));

    server->auth_config_valid_ = true;
    server->short_id_bytes_.assign(reality::kShortIdMaxLen + 1, 0x01);
    EXPECT_FALSE(server->authenticate_client(info, record, ctx));
}

TEST_F(remote_server_test, PerformHandshakeResponseCoversRandomAndSignKeyFailureBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    reality::server_fingerprint fp;
    fp.cipher_suite = 0x1301;
    fp.alpn = "h2";
    server->set_certificate("fault.test", reality::construct_certificate({0x01, 0x02, 0x03}), fp, "fault-trace");

    auto run_once = [&](const bool fail_rand, const bool fail_sign_key) -> std::pair<bool, std::error_code>
    {
        asio::ip::tcp::acceptor acceptor(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
        asio::ip::tcp::socket client_socket(pool.get_io_context());
        client_socket.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);

        auto server_socket = std::make_shared<asio::ip::tcp::socket>(pool.get_io_context());
        acceptor.accept(*server_socket, ec);
        EXPECT_FALSE(ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        EXPECT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        mux::client_hello_info info{};
        info.sni = "fault.test";
        info.session_id.assign(32, 0x12);
        info.has_x25519_share = true;
        info.x25519_pub.assign(peer_pub, peer_pub + 32);

        mux::connection_context ctx;
        ctx.conn_id(91);
        ctx.trace_id("fault-branch");

        if (fail_rand)
        {
            fail_next_rand_bytes();
        }
        if (fail_sign_key)
        {
            fail_next_ed25519_raw_private_key();
        }

        std::promise<std::pair<mux::remote_server::server_handshake_res, std::error_code>> done;
        auto done_future = done.get_future();
        asio::co_spawn(pool.get_io_context(),
                       [server, server_socket, info, ctx, &done]() mutable -> asio::awaitable<void>
                       {
                           reality::transcript trans;
                           auto res = co_await server->perform_handshake_response(server_socket, info, trans, ctx);
                           done.set_value({std::move(res), res.ec});
                           co_return;
                       },
                       asio::detached);

        EXPECT_EQ(done_future.wait_for(std::chrono::seconds(2)), std::future_status::ready);
        auto [result, hs_ec] = done_future.get();
        return {result.ok, hs_ec};
    };

    {
        const auto [ok, hs_ec] = run_once(true, false);
        EXPECT_FALSE(ok);
        EXPECT_EQ(hs_ec, std::errc::operation_canceled);
    }

    {
        const auto [ok, hs_ec] = run_once(false, true);
        EXPECT_FALSE(ok);
        EXPECT_EQ(hs_ec, asio::error::fault);
    }

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test, VerifyClientFinishedCoversPlaintextValidationBranches)
{
    auto run_case = [](const std::vector<std::uint8_t>& plaintext, const std::uint8_t inner_content_type) -> bool
    {
        asio::io_context io_context;
        std::error_code ec;

        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
        asio::ip::tcp::socket writer(io_context);
        writer.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);
        auto reader = std::make_shared<asio::ip::tcp::socket>(io_context);
        acceptor.accept(*reader, ec);
        EXPECT_FALSE(ec);

        const std::vector<std::uint8_t> key(16, 0x41);
        const std::vector<std::uint8_t> iv(12, 0x62);
        const auto encrypted = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, inner_content_type);
        EXPECT_TRUE(encrypted.has_value());
        if (!encrypted)
        {
            return false;
        }
        asio::write(writer, asio::buffer(*encrypted), ec);
        EXPECT_FALSE(ec);
        writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

        mux::connection_context ctx;
        ctx.conn_id(88);
        ctx.trace_id("verify-client-finished");

        reality::handshake_keys hs_keys;
        hs_keys.client_handshake_traffic_secret.assign(32, 0x55);
        reality::transcript trans;

        bool ok = true;
        std::error_code verify_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           verify_ec = co_await mux::remote_server::verify_client_finished(
                               reader, {key, iv}, hs_keys, trans, EVP_aes_128_gcm(), EVP_sha256(), ctx);
                           ok = !verify_ec;
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        return ok;
    };

    EXPECT_FALSE(run_case({0x14, 0x00, 0x00, 0x00}, reality::kContentTypeApplicationData));
    EXPECT_FALSE(run_case({0x14, 0x00, 0x00, 0x01, 0x00}, reality::kContentTypeHandshake));

    std::vector<std::uint8_t> wrong_hmac(4 + 32, 0x00);
    wrong_hmac[0] = 0x14;
    wrong_hmac[3] = 0x20;
    EXPECT_FALSE(run_case(wrong_hmac, reality::kContentTypeHandshake));
}

TEST_F(remote_server_test, DeriveApplicationTrafficKeysCoversFirstAndSecondDeriveFailure)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));

    mux::remote_server::server_handshake_res sh_res{};
    sh_res.cipher = EVP_aes_128_gcm();
    sh_res.negotiated_md = EVP_sha256();
    sh_res.hs_keys.master_secret.assign(32, 0x71);
    sh_res.handshake_hash.assign(32, 0x72);

    fail_hkdf_add_info_on_call(3);
    const auto first_app_keys_res = server->derive_application_traffic_keys(sh_res);
    EXPECT_FALSE(first_app_keys_res.has_value());
    EXPECT_TRUE(first_app_keys_res.error());

    ec.clear();
    fail_hkdf_add_info_on_call(5);
    const auto second_app_keys_res = server->derive_application_traffic_keys(sh_res);
    EXPECT_FALSE(second_app_keys_res.has_value());
    EXPECT_TRUE(second_app_keys_res.error());
}

TEST_F(remote_server_test, DeriveServerKeyShareCoversX25519DeriveFailureBranch)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));

    std::uint8_t pub[32];
    std::uint8_t priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));

    mux::client_hello_info info{};
    info.has_x25519_share = true;
    info.x25519_pub.assign(32, 0x23);

    mux::connection_context ctx;

    fail_next_pkey_derive();
    const auto key_share_res = server->derive_server_key_share(info, pub, priv, ctx);
    EXPECT_FALSE(key_share_res.has_value());
    EXPECT_TRUE(key_share_res.error());
}

TEST_F(remote_server_test, StopCoversAcceptorCloseFailureBranch)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });

    auto server = std::make_shared<mux::remote_server>(pool, make_server_cfg(pick_free_port(), {}, "0102030405060708"));
    server->start();

    fail_next_close(EIO);
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    pool.stop();
    runner.join();
}

TEST_F(remote_server_test, HandleFallbackCoversCloseSocketErrorBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    std::thread runner([&pool]() { pool.run(); });

    auto cfg = make_server_cfg(pick_free_port(), {{"*", "127.0.0.1", "1"}}, "0102030405060708");
    cfg.reality.fallback_guard.enabled = true;
    cfg.reality.fallback_guard.rate_per_sec = 0;
    cfg.reality.fallback_guard.burst = 0;
    auto server = std::make_shared<mux::remote_server>(pool, cfg);

    auto fallback_socket = std::make_shared<asio::ip::tcp::socket>(pool.get_io_context());
    mux::connection_context ctx;
    ctx.conn_id(555);
    ctx.remote_addr("127.0.0.10");
    ctx.trace_id("fallback-close-errors");

    std::promise<void> done;
    auto done_future = done.get_future();

    fail_next_shutdown(EIO);
    fail_next_close(EIO);
    asio::co_spawn(pool.get_io_context(),
                   [server, fallback_socket, ctx, &done]() mutable -> asio::awaitable<void>
                   {
                       co_await server->handle_fallback(fallback_socket, std::vector<std::uint8_t>{0x16}, ctx, "blocked.test");
                       done.set_value();
                       co_return;
                   },
                   asio::detached);

    EXPECT_EQ(done_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);

    server->stop();
    pool.stop();
    runner.join();
}
