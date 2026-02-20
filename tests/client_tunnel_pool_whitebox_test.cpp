// NOLINTBEGIN(modernize-return-braced-init-list, readability-function-cognitive-complexity)
// NOLINTBEGIN(bugprone-unused-return-value, misc-include-cleaner)
#include <array>
#include <atomic>
#include <cerrno>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <sys/socket.h>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "config.h"
#include "context_pool.h"
#include "crypto_util.h"
#include "reality_messages.h"
#include "tls_record_layer.h"
#include "transcript.h"
#include "reality_fingerprint.h"
#include "statistics.h"
#define private public
#include "client_tunnel_pool.h"
#undef private
#include "test_util.h"

namespace
{

std::atomic<bool> g_fail_rand_bytes_once{false};
std::atomic<bool> g_fail_hkdf_add_info_once{false};
std::atomic<bool> g_fail_cipher_ctx_ctrl_once{false};
std::atomic<bool> g_fail_encrypt_init_once{false};
std::atomic<bool> g_fail_pkey_derive_once{false};
std::atomic<bool> g_fail_socket_once{false};
std::atomic<int> g_fail_socket_errno{EMFILE};
std::atomic<bool> g_fail_getsockname_once{false};
std::atomic<int> g_fail_getsockname_errno{ENOTSOCK};

void fail_next_rand_bytes() { g_fail_rand_bytes_once.store(true, std::memory_order_release); }

void fail_next_hkdf_add_info() { g_fail_hkdf_add_info_once.store(true, std::memory_order_release); }

void fail_next_cipher_ctx_ctrl() { g_fail_cipher_ctx_ctrl_once.store(true, std::memory_order_release); }

void fail_next_encrypt_init() { g_fail_encrypt_init_once.store(true, std::memory_order_release); }

void fail_next_pkey_derive() { g_fail_pkey_derive_once.store(true, std::memory_order_release); }

void fail_next_socket(const int err)
{
    g_fail_socket_errno.store(err, std::memory_order_release);
    g_fail_socket_once.store(true, std::memory_order_release);
}

void fail_next_getsockname(const int err = ENOTSOCK)
{
    g_fail_getsockname_errno.store(err, std::memory_order_release);
    g_fail_getsockname_once.store(true, std::memory_order_release);
}

extern "C" int __real_RAND_bytes(unsigned char* buf, int num);  // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen);  // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);  // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_EVP_EncryptInit_ex(  // NOLINT(bugprone-reserved-identifier)
    EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv);
extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);  // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_socket(int domain, int type, int protocol);  // NOLINT(bugprone-reserved-identifier)
extern "C" int __real_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen);  // NOLINT(bugprone-reserved-identifier)

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_rand_bytes_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_hkdf_add_info_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)  // NOLINT(bugprone-reserved-identifier)
{
    if (type == EVP_CTRL_GCM_GET_TAG && g_fail_cipher_ctx_ctrl_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_EVP_EncryptInit_ex(  // NOLINT(bugprone-reserved-identifier)
    EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)
{
    if (g_fail_encrypt_init_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_EncryptInit_ex(ctx, type, impl, key, iv);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_pkey_derive_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_socket(int domain, int type, int protocol)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);  // NOLINT(bugprone-reserved-identifier)
}

extern "C" int __wrap_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen)  // NOLINT(bugprone-reserved-identifier)
{
    if (g_fail_getsockname_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_getsockname_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_getsockname(sockfd, addr, addrlen);  // NOLINT(bugprone-reserved-identifier)
}

mux::config make_base_cfg()
{
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 0;
    cfg.reality.sni = "www.example.test";
    cfg.reality.short_id = "0102030405060708";
    cfg.limits.max_connections = 1;
    return cfg;
}

std::string generate_public_key_hex()
{
    std::uint8_t pub[32];
    std::uint8_t priv[32];
    if (!reality::crypto_util::generate_x25519_keypair(pub, priv))
    {
        return std::string(64, '0');
    }
    return reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
}

std::vector<std::uint8_t> build_minimal_valid_certificate_message()
{
    return {
        0x0b, 0x00, 0x00, 0x0a,    // handshake header (msg_len = 10)
        0x00,                      // certificate_request_context length
        0x00, 0x00, 0x06,          // certificate_list length
        0x00, 0x00, 0x03,          // first certificate length
        0x01, 0x02, 0x03           // first certificate bytes
    };
}

std::vector<std::uint8_t> build_certificate_verify_message()
{
    std::array<std::uint8_t, 32> sign_key_bytes{};
    for (std::size_t i = 0; i < sign_key_bytes.size(); ++i)
    {
        sign_key_bytes[i] = static_cast<std::uint8_t>(i + 1);
    }
    reality::openssl_ptrs::evp_pkey_ptr const sign_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), sign_key_bytes.size()));
    if (sign_key == nullptr)
    {
        return {};
    }
    return reality::construct_certificate_verify(sign_key.get(), {});
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> encrypt_record_expected(const EVP_CIPHER* cipher,
                                                                                   const std::vector<std::uint8_t>& key,
                                                                                   const std::vector<std::uint8_t>& iv,
                                                                                   const std::uint64_t seq,
                                                                                   const std::vector<std::uint8_t>& plaintext,
                                                                                   const std::uint8_t content_type)
{
    return reality::tls_record_layer::encrypt_record(cipher, key, iv, seq, plaintext, content_type);
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> tcp_connect_expected(mux::client_tunnel_pool& pool,
                                                                            boost::asio::io_context& io_context,
                                                                            boost::asio::ip::tcp::socket& socket)
{
    co_return co_await pool.tcp_connect(io_context, socket);
}

boost::asio::awaitable<std::expected<void, boost::system::error_code>> generate_and_send_client_hello_expected(mux::client_tunnel_pool& pool,
                                                                                                boost::asio::ip::tcp::socket& socket,
                                                                                                const std::uint8_t* public_key,
                                                                                                const std::uint8_t* private_key,
                                                                                                const reality::fingerprint_spec& spec,
                                                                                                reality::transcript& trans)
{
    co_return co_await pool.generate_and_send_client_hello(socket, public_key, private_key, spec, trans);
}

boost::asio::awaitable<std::expected<mux::client_tunnel_pool::server_hello_res, boost::system::error_code>> process_server_hello_expected(
    boost::asio::ip::tcp::socket& socket,
    const std::uint8_t* private_key,
    reality::transcript& trans)
{
    co_return co_await mux::client_tunnel_pool::process_server_hello(socket, private_key, trans);
}

boost::asio::awaitable<std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code>> perform_reality_handshake_expected(
    mux::client_tunnel_pool& pool,
    boost::asio::ip::tcp::socket& socket)
{
    co_return co_await pool.perform_reality_handshake(socket);
}

boost::asio::awaitable<std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code>> perform_reality_handshake_with_timeout_expected(
    mux::client_tunnel_pool& pool,
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
{
    co_return co_await pool.perform_reality_handshake_with_timeout(socket);
}

boost::asio::awaitable<std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code>> handshake_read_loop_expected(
    boost::asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
    const reality::handshake_keys& hs_keys,
    const bool strict_cert_verify,
    const std::string& sni,
    reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md)
{
    co_return co_await mux::client_tunnel_pool::handshake_read_loop(socket, s_hs_keys, hs_keys, strict_cert_verify, sni, trans, cipher, md);
}

}    // namespace

TEST(ClientTunnelPoolWhiteboxTest, ConfigValidationAndStartGuardBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();

    auto no_fingerprint_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_TRUE(no_fingerprint_pool->valid());

    cfg.reality.fingerprint.clear();
    auto empty_fingerprint_name_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_TRUE(empty_fingerprint_name_pool->valid());

    cfg.reality.fingerprint = "chrome";
    auto known_fingerprint_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_TRUE(known_fingerprint_pool->valid());
    EXPECT_TRUE(known_fingerprint_pool->fingerprint_type_.has_value());

    cfg.reality.short_id = "010203040506070809";
    auto long_short_id_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_FALSE(long_short_id_pool->valid());

    cfg.reality.short_id = "0102030405060708";
    cfg.reality.public_key = "0102";
    auto invalid_public_key_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_FALSE(invalid_public_key_pool->valid());

    cfg.reality.public_key = generate_public_key_hex();
    cfg.reality.fingerprint = "invalid-fingerprint";
    auto invalid_fingerprint_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_FALSE(invalid_fingerprint_pool->valid());

    invalid_fingerprint_pool->start();
    EXPECT_TRUE(invalid_fingerprint_pool->stop_.load(std::memory_order_acquire));
}

TEST(ClientTunnelPoolWhiteboxTest, StartNormalizesZeroMaxConnections)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    cfg.limits.max_connections = 0;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    tunnel_pool->start();
    EXPECT_EQ(tunnel_pool->limits_config_.max_connections, 1U);
    EXPECT_EQ(tunnel_pool->tunnel_pool_.size(), 1U);
    EXPECT_EQ(tunnel_pool->pending_sockets_.size(), 1U);
    EXPECT_EQ(tunnel_pool->tunnel_io_contexts_.size(), 1U);
    tunnel_pool->stop();
}

TEST(ClientTunnelPoolWhiteboxTest, SelectAndIndexGuardBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    EXPECT_EQ(tunnel_pool->select_tunnel(), nullptr);

    boost::asio::io_context io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);

    tunnel_pool->tunnel_io_contexts_.resize(1, nullptr);
    tunnel_pool->close_pending_socket(0, pending_socket);

    tunnel_pool->clear_pending_socket_if_match(42, pending_socket);
    tunnel_pool->clear_tunnel_if_match(42, nullptr);
    tunnel_pool->tunnel_pool_.resize(1);
    tunnel_pool->clear_tunnel_if_match(0, nullptr);

    auto created_socket = tunnel_pool->create_pending_socket(io_context, 9);
    ASSERT_NE(created_socket, nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, PublishTunnelRejectedWhenStopping)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    tunnel_pool->tunnel_pool_.resize(1);
    boost::asio::io_context io_context;
    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(io_context),
        io_context,
        mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()},
        true,
        1101);

    tunnel_pool->stop_.store(true, std::memory_order_release);
    EXPECT_FALSE(tunnel_pool->publish_tunnel(0, tunnel));
    EXPECT_EQ(tunnel_pool->tunnel_pool_[0], nullptr);

    tunnel_pool->stop_.store(false, std::memory_order_release);
    EXPECT_TRUE(tunnel_pool->publish_tunnel(0, tunnel));
    EXPECT_EQ(tunnel_pool->tunnel_pool_[0], tunnel);
    tunnel_pool->clear_tunnel_if_match(0, tunnel);
}

TEST(ClientTunnelPoolWhiteboxTest, ClosePendingSocketRunsWhenIoContextNotRunning)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context tunnel_io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(tunnel_io_context);
    (void)    pending_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(pending_socket->is_open());

    tunnel_pool->tunnel_io_contexts_.resize(1, &tunnel_io_context);
    tunnel_pool->close_pending_socket(0, pending_socket);
    EXPECT_FALSE(pending_socket->is_open());
}

TEST(ClientTunnelPoolWhiteboxTest, ClosePendingSocketRunsInlineWhenIoContextStopped)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context tunnel_io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(tunnel_io_context);
    (void)    pending_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(pending_socket->is_open());

    tunnel_pool->tunnel_io_contexts_.resize(1, &tunnel_io_context);
    tunnel_io_context.stop();
    tunnel_pool->close_pending_socket(0, pending_socket);
    EXPECT_FALSE(pending_socket->is_open());
}

TEST(ClientTunnelPoolWhiteboxTest, StopClosesPendingSocketWhenIoContextNotRunning)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context tunnel_io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(tunnel_io_context);
    (void)    pending_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(pending_socket->is_open());

    tunnel_pool->pending_sockets_.resize(1);
    tunnel_pool->pending_sockets_[0] = pending_socket;
    tunnel_pool->tunnel_io_contexts_.resize(1, &tunnel_io_context);

    tunnel_pool->stop();

    EXPECT_TRUE(tunnel_pool->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(pending_socket->is_open());
    EXPECT_EQ(tunnel_pool->pending_sockets_[0], nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, StopClosesPendingSocketWhenIoContextStopped)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context tunnel_io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(tunnel_io_context);
    (void)    pending_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(pending_socket->is_open());

    tunnel_pool->pending_sockets_.resize(1);
    tunnel_pool->pending_sockets_[0] = pending_socket;
    tunnel_pool->tunnel_io_contexts_.resize(1, &tunnel_io_context);

    tunnel_io_context.stop();
    tunnel_pool->stop();

    EXPECT_TRUE(tunnel_pool->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(pending_socket->is_open());
    EXPECT_EQ(tunnel_pool->pending_sockets_[0], nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, StopClosesPendingSocketWhenIoQueueBlocked)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context tunnel_io_context;
    auto pending_socket = std::make_shared<boost::asio::ip::tcp::socket>(tunnel_io_context);
    (void)    pending_socket->open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(pending_socket->is_open());

    tunnel_pool->pending_sockets_.resize(1);
    tunnel_pool->pending_sockets_[0] = pending_socket;
    tunnel_pool->tunnel_io_contexts_.resize(1, &tunnel_io_context);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(
        tunnel_io_context,
        [&blocker_started, &release_blocker]()
        {
            blocker_started.store(true, std::memory_order_release);
            while (!release_blocker.load(std::memory_order_acquire))
            {
                std::this_thread::yield();
            }
        });

    std::thread io_thread([&tunnel_io_context]() { tunnel_io_context.run(); });
    bool started = false;
    for (int i = 0; i < 100000; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::yield();
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        tunnel_io_context.stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    tunnel_pool->stop();
    EXPECT_TRUE(tunnel_pool->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(pending_socket->is_open());
    EXPECT_EQ(tunnel_pool->pending_sockets_[0], nullptr);

    release_blocker.store(true, std::memory_order_release);
    tunnel_io_context.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(ClientTunnelPoolWhiteboxTest, BuildTunnelAndWaitRetryBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket(io_context);

    mux::client_tunnel_pool::handshake_result bad_handshake{};
    bad_handshake.cipher_suite = 0x1301;
    bad_handshake.md = EVP_sha256();
    bad_handshake.cipher = EVP_aes_128_gcm();
    bad_handshake.c_app_secret.clear();
    bad_handshake.s_app_secret.clear();

    auto bad_tunnel = tunnel_pool->build_tunnel(std::move(socket), io_context, 1, bad_handshake, "trace-1");
    ASSERT_EQ(bad_tunnel, nullptr);

    boost::asio::ip::tcp::socket good_socket(io_context);
    auto good_handshake = bad_handshake;
    good_handshake.c_app_secret.assign(32, 0x11);
    good_handshake.s_app_secret.assign(32, 0x22);
    auto good_tunnel = tunnel_pool->build_tunnel(std::move(good_socket), io_context, 2, good_handshake, "trace-2");
    ASSERT_NE(good_tunnel, nullptr);

    tunnel_pool->stop_.store(true, std::memory_order_release);
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, &io_context]() -> boost::asio::awaitable<void>
                   {
                       co_await tunnel_pool->wait_remote_retry(io_context);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
}

TEST(ClientTunnelPoolWhiteboxTest, BuildTunnelReturnsNullWhenKeyDerivationFails)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket(io_context);

    mux::client_tunnel_pool::handshake_result handshake{};
    handshake.cipher_suite = 0x1301;
    handshake.md = EVP_sha256();
    handshake.cipher = EVP_aes_128_gcm();
    handshake.c_app_secret.assign(32, 0x11);
    handshake.s_app_secret.assign(32, 0x22);

    fail_next_hkdf_add_info();
    auto tunnel = tunnel_pool->build_tunnel(std::move(socket), io_context, 3, handshake, "trace-3");
    EXPECT_EQ(tunnel, nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, TcpConnectAndHandshakeErrorBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& stats = mux::statistics::instance();
    const auto resolve_errors_before = stats.client_tunnel_pool_resolve_errors();

    auto cfg = make_base_cfg();
    cfg.outbound.host = "invalid.host.for.coverage.test";
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;

    boost::asio::ip::tcp::socket socket(io_context);
    std::expected<void, boost::system::error_code> connect_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, &io_context, &socket, &connect_res]() -> boost::asio::awaitable<void>
                   {
                       connect_res = co_await tcp_connect_expected(*tunnel_pool, io_context, socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(connect_res.has_value());
    EXPECT_TRUE(connect_res.error());
    EXPECT_GE(stats.client_tunnel_pool_resolve_errors(), resolve_errors_before + 1);

    io_context.restart();
    const auto connect_errors_before = stats.client_tunnel_pool_connect_errors();

    auto connect_error_cfg = make_base_cfg();
    connect_error_cfg.outbound.host = "127.0.0.1";
    connect_error_cfg.outbound.port = 1;
    connect_error_cfg.reality.public_key = generate_public_key_hex();
    auto connect_error_pool = std::make_shared<mux::client_tunnel_pool>(pool, connect_error_cfg, 0);

    boost::asio::ip::tcp::socket try_socket(io_context);
    std::expected<void, boost::system::error_code> connect_error_res;
    boost::asio::co_spawn(io_context,
                   [connect_error_pool, &io_context, &try_socket, &connect_error_res]() -> boost::asio::awaitable<void>
                   {
                       connect_error_res = co_await tcp_connect_expected(*connect_error_pool, io_context, try_socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(connect_error_res.has_value());
    EXPECT_TRUE(connect_error_res.error());
    EXPECT_GE(stats.client_tunnel_pool_connect_errors(), connect_errors_before + 1);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeTimeoutCancelsSocketAndReturnsTimedOut)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& stats = mux::statistics::instance();
    const auto handshake_timeouts_before = stats.client_tunnel_pool_handshake_timeouts();

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    cfg.timeout.read = 1;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));

    auto client_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    (void)    client_socket->connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);

    boost::asio::ip::tcp::socket server_socket(io_context);
    (void)    acceptor.accept(server_socket, ec);
    ASSERT_FALSE(ec);

    std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code> handshake_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, client_socket, &handshake_res]() -> boost::asio::awaitable<void>
                   {
                       handshake_res = co_await perform_reality_handshake_with_timeout_expected(*tunnel_pool, client_socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    ASSERT_FALSE(handshake_res.has_value());
    EXPECT_EQ(handshake_res.error(), boost::asio::error::timed_out);
    EXPECT_FALSE(client_socket->is_open());
    EXPECT_GE(stats.client_tunnel_pool_handshake_timeouts(), handshake_timeouts_before + 1);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeIoErrorIncrementsHandshakeErrorMetric)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& stats = mux::statistics::instance();
    const auto handshake_errors_before = stats.client_tunnel_pool_handshake_errors();

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    cfg.timeout.read = 1;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;
    auto disconnected_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code> handshake_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, disconnected_socket, &handshake_res]() -> boost::asio::awaitable<void>
                   {
                       handshake_res = co_await perform_reality_handshake_with_timeout_expected(*tunnel_pool, disconnected_socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    ASSERT_FALSE(handshake_res.has_value());
    EXPECT_TRUE(handshake_res.error());
    EXPECT_NE(handshake_res.error(), boost::asio::error::timed_out);
    EXPECT_GE(stats.client_tunnel_pool_handshake_errors(), handshake_errors_before + 1);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeNullSocketReturnsInvalidArgument)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& stats = mux::statistics::instance();
    const auto handshake_errors_before = stats.client_tunnel_pool_handshake_errors();

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    cfg.timeout.read = 1;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;
    std::shared_ptr<boost::asio::ip::tcp::socket> const null_socket;
    std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code> handshake_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, null_socket, &handshake_res]() -> boost::asio::awaitable<void>
                   {
                       handshake_res = co_await perform_reality_handshake_with_timeout_expected(*tunnel_pool, null_socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    ASSERT_FALSE(handshake_res.has_value());
    EXPECT_EQ(handshake_res.error(), std::errc::invalid_argument);
    EXPECT_GE(stats.client_tunnel_pool_handshake_errors(), handshake_errors_before + 1);
}

TEST(ClientTunnelPoolWhiteboxTest, TcpConnectTimeoutReturnsTimedOutAndClosesSocket)
{
    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    auto& stats = mux::statistics::instance();
    const auto connect_timeouts_before = stats.client_tunnel_pool_connect_timeouts();

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor saturated_acceptor(io_context);
    ec = saturated_acceptor.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    ec = saturated_acceptor.listen(1, ec);
    ASSERT_FALSE(ec);

    const auto target_port = saturated_acceptor.local_endpoint().port();
    boost::asio::ip::tcp::socket queued_client_a(io_context);
    (void)    queued_client_a.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket queued_client_b(io_context);
    (void)    queued_client_b.connect({boost::asio::ip::make_address("127.0.0.1"), target_port}, ec);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = target_port;
    cfg.reality.public_key = generate_public_key_hex();
    cfg.timeout.read = 1;
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::ip::tcp::socket client_socket(io_context);
    std::expected<void, boost::system::error_code> connect_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, &io_context, &client_socket, &connect_res]() -> boost::asio::awaitable<void>
                   {
                       connect_res = co_await tcp_connect_expected(*tunnel_pool, io_context, client_socket);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();

    ASSERT_FALSE(connect_res.has_value());
    EXPECT_EQ(connect_res.error(), boost::asio::error::timed_out);
    EXPECT_FALSE(client_socket.is_open());
    EXPECT_GE(stats.client_tunnel_pool_connect_timeouts(), connect_timeouts_before + 1);

    boost::system::error_code close_ec;
    (void)    queued_client_a.close(close_ec);
    (void)    queued_client_b.close(close_ec);
    (void)    saturated_acceptor.close(close_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, ClientHelloAndServerHelloIoErrorBranches)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    boost::asio::io_context io_context;

    std::array<std::uint8_t, 32> ephemeral_pub{};
    std::array<std::uint8_t, 32> ephemeral_priv{};
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(ephemeral_pub.data(), ephemeral_priv.data()));

    boost::asio::ip::tcp::socket disconnected_socket(io_context);
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
    reality::transcript trans;

    std::expected<void, boost::system::error_code> hello_res;
    boost::asio::co_spawn(io_context,
                   [tunnel_pool, &disconnected_socket, ephemeral_pub, ephemeral_priv, spec, &trans, &hello_res]() mutable -> boost::asio::awaitable<void>
                   {
                       hello_res = co_await generate_and_send_client_hello_expected(
                           *tunnel_pool, disconnected_socket, ephemeral_pub.data(), ephemeral_priv.data(), spec, trans);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_res.has_value());
    EXPECT_TRUE(hello_res.error());

    io_context.restart();

    std::expected<mux::client_tunnel_pool::server_hello_res, boost::system::error_code> sh_res;
    boost::asio::co_spawn(io_context,
                   [&disconnected_socket, ephemeral_priv, &trans, &sh_res]() -> boost::asio::awaitable<void>
                   {
                       sh_res = co_await process_server_hello_expected(disconnected_socket, ephemeral_priv.data(), trans);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.has_value());
    EXPECT_TRUE(sh_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloRejectsUnsupportedCipherAndKeyshare)
{
    auto run_case = [](std::uint16_t cipher_suite, std::uint16_t group, std::size_t key_share_len)
    {
        boost::asio::io_context io_context;
        boost::system::error_code ec;

        boost::asio::ip::tcp::acceptor acceptor(io_context);
        ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
        boost::asio::ip::tcp::socket writer(io_context);
        (void)        writer.connect(acceptor.local_endpoint(), ec);
        ASSERT_FALSE(ec);
        boost::asio::ip::tcp::socket reader(io_context);
        (void)        acceptor.accept(reader, ec);
        ASSERT_FALSE(ec);

        std::vector<std::uint8_t> const server_random(32, 0x42);
        std::vector<std::uint8_t> const session_id(32, 0x11);
        std::vector<std::uint8_t> const key_share(key_share_len, 0x22);
        auto sh = reality::construct_server_hello(server_random, session_id, cipher_suite, group, key_share);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh.size()));
        record.insert(record.end(), sh.begin(), sh.end());
        boost::asio::write(writer, boost::asio::buffer(record), ec);
        ASSERT_FALSE(ec);
        (void)        writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        reality::transcript trans;
        std::expected<mux::client_tunnel_pool::server_hello_res, boost::system::error_code> sh_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           sh_res = co_await process_server_hello_expected(reader, peer_priv, trans);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(sh_res.has_value());
        EXPECT_TRUE(sh_res.error());
    };

    run_case(0x9999, reality::tls_consts::group::kX25519, 32);
    run_case(0x1301, 0x0017, 32);
    run_case(0x1301, reality::tls_consts::group::kX25519, 31);
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloRejectsTruncatedSessionData)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> truncated_sh(39, 0x00);
    truncated_sh[0] = 0x02;
    truncated_sh[4] = 0x03;
    truncated_sh[5] = 0x03;
    truncated_sh[38] = 5;
    auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(truncated_sh.size()));
    record.insert(record.end(), truncated_sh.begin(), truncated_sh.end());
    boost::asio::write(writer, boost::asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    reality::transcript trans;
    std::expected<mux::client_tunnel_pool::server_hello_res, boost::system::error_code> sh_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       sh_res = co_await process_server_hello_expected(reader, peer_priv, trans);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.has_value());
    EXPECT_TRUE(sh_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsCertVerifyBeforeCertificate)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x11);
    const std::vector<std::uint8_t> iv(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x0f, 0x00, 0x00, 0x00};
    const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(record.has_value());
    boost::asio::write(writer, boost::asio::buffer(*record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       loop_res = co_await handshake_read_loop_expected(
                           reader, {key, iv}, hs_keys, false, "verify-before-cert", trans, EVP_aes_128_gcm(), EVP_sha256());
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.has_value());
    EXPECT_TRUE(loop_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsFinishedBeforeCertificateVerify)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x31);
    const std::vector<std::uint8_t> iv(12, 0x41);
    const std::vector<std::uint8_t> plaintext = {0x14, 0x00, 0x00, 0x00};
    const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(record.has_value());
    boost::asio::write(writer, boost::asio::buffer(*record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       loop_res = co_await handshake_read_loop_expected(
                           reader, {key, iv}, hs_keys, false, "finished-before-verify", trans, EVP_aes_128_gcm(), EVP_sha256());
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.has_value());
    EXPECT_TRUE(loop_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsMalformedCertificateMessage)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x51);
    const std::vector<std::uint8_t> iv(12, 0x61);
    const std::vector<std::uint8_t> plaintext = {0x0b, 0x00, 0x00, 0x01, 0x00};
    const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(record.has_value());
    boost::asio::write(writer, boost::asio::buffer(*record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       loop_res = co_await handshake_read_loop_expected(
                           reader, {key, iv}, hs_keys, false, "bad-cert-msg", trans, EVP_aes_128_gcm(), EVP_sha256());
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.has_value());
    EXPECT_TRUE(loop_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, ClientHelloBuildFailureBranchesForAuthMaterialAndPayload)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    boost::asio::io_context io_context;

    std::uint8_t ephemeral_pub[32];
    std::uint8_t ephemeral_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(ephemeral_pub, ephemeral_priv));
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);

    mux::config missing_pub_cfg = make_base_cfg();
    missing_pub_cfg.reality.public_key.clear();
    auto missing_pub_pool = std::make_shared<mux::client_tunnel_pool>(pool, missing_pub_cfg, 0);
    boost::asio::ip::tcp::socket disconnected_socket_1(io_context);
    reality::transcript trans_1;
    std::expected<void, boost::system::error_code> hello_res_1;
    boost::asio::co_spawn(io_context,
                   [missing_pub_pool, &disconnected_socket_1, ephemeral_pub, ephemeral_priv, spec, &trans_1, &hello_res_1]() mutable -> boost::asio::awaitable<void>
                   {
                       hello_res_1 = co_await generate_and_send_client_hello_expected(
                           *missing_pub_pool, disconnected_socket_1, ephemeral_pub, ephemeral_priv, spec, trans_1);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_res_1.has_value());
    EXPECT_TRUE(hello_res_1.error());

    io_context.restart();

    auto invalid_short_id_cfg = make_base_cfg();
    invalid_short_id_cfg.reality.public_key = generate_public_key_hex();
    invalid_short_id_cfg.reality.short_id = "010203040506070809";
    auto invalid_short_id_pool = std::make_shared<mux::client_tunnel_pool>(pool, invalid_short_id_cfg, 0);
    boost::asio::ip::tcp::socket disconnected_socket_2(io_context);
    reality::transcript trans_2;
    std::expected<void, boost::system::error_code> hello_res_2;
    boost::asio::co_spawn(io_context,
                   [invalid_short_id_pool, &disconnected_socket_2, ephemeral_pub, ephemeral_priv, spec, &trans_2, &hello_res_2]() mutable -> boost::asio::awaitable<void>
                   {
                       hello_res_2 = co_await generate_and_send_client_hello_expected(
                           *invalid_short_id_pool, disconnected_socket_2, ephemeral_pub, ephemeral_priv, spec, trans_2);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_res_2.has_value());
    EXPECT_EQ(hello_res_2.error(), std::errc::invalid_argument);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsMalformedCertificateVerifyAfterCertificate)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x81);
    const std::vector<std::uint8_t> iv(12, 0x91);
    const std::vector<std::uint8_t> cert_msg = {0x0b, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> malformed_cert_verify = {0x0f, 0x00, 0x00, 0x00};
    std::vector<std::uint8_t> plaintext = cert_msg;
    plaintext.insert(plaintext.end(), malformed_cert_verify.begin(), malformed_cert_verify.end());
    const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(record.has_value());
    boost::asio::write(writer, boost::asio::buffer(*record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       loop_res = co_await handshake_read_loop_expected(
                           reader, {key, iv}, hs_keys, false, "bad-cert-verify-payload", trans, EVP_aes_128_gcm(), EVP_sha256());
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.has_value());
    EXPECT_EQ(loop_res.error(), boost::asio::error::invalid_argument);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsUnsupportedCertificateVerifyScheme)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0xa1);
    const std::vector<std::uint8_t> iv(12, 0xb1);
    const std::vector<std::uint8_t> cert_msg = {0x0b, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> unsupported_cert_verify = {0x0f, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00};
    std::vector<std::uint8_t> plaintext = cert_msg;
    plaintext.insert(plaintext.end(), unsupported_cert_verify.begin(), unsupported_cert_verify.end());
    const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
    ASSERT_TRUE(record.has_value());
    boost::asio::write(writer, boost::asio::buffer(*record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       loop_res = co_await handshake_read_loop_expected(
                           reader, {key, iv}, hs_keys, false, "unsupported-cert-verify-scheme", trans, EVP_aes_128_gcm(), EVP_sha256());
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.has_value());
    EXPECT_EQ(loop_res.error(), boost::asio::error::no_protocol_option);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopCertificateRangeAndFinishedBranches)
{
    auto run_case = [](const std::vector<std::uint8_t>& plaintext,
                       const reality::handshake_keys& hs_keys,
                       boost::system::error_code& loop_ec) -> bool
    {
        boost::asio::io_context io_context;
        boost::system::error_code ec;

        boost::asio::ip::tcp::acceptor acceptor(io_context);
        if (!mux::test::open_ephemeral_tcp_acceptor(acceptor))
        {
            ADD_FAILURE() << "failed to open ephemeral tcp acceptor";
            loop_ec = boost::asio::error::operation_aborted;
            return false;
        }
        boost::asio::ip::tcp::socket writer(io_context);
        (void)        writer.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);
        boost::asio::ip::tcp::socket reader(io_context);
        (void)        acceptor.accept(reader, ec);
        EXPECT_FALSE(ec);

        const std::vector<std::uint8_t> key(16, 0x12);
        const std::vector<std::uint8_t> iv(12, 0x34);
        const auto record = encrypt_record_expected(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake);
        EXPECT_TRUE(record.has_value());
        boost::asio::write(writer, boost::asio::buffer(*record), ec);
        EXPECT_FALSE(ec);
        (void)        writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

        reality::transcript trans;
        std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code> loop_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           loop_res = co_await handshake_read_loop_expected(
                               reader, {key, iv}, hs_keys, false, "whitebox-finished", trans, EVP_aes_128_gcm(), EVP_sha256());
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        if (!loop_res.has_value())
        {
            loop_ec = loop_res.error();
            return false;
        }
        loop_ec.clear();
        return true;
    };

    const auto cert_msg = build_minimal_valid_certificate_message();
    const auto cert_verify_msg = build_certificate_verify_message();
    ASSERT_FALSE(cert_verify_msg.empty());

    reality::handshake_keys hs_keys_ok{};
    hs_keys_ok.server_handshake_traffic_secret.assign(32, 0x21);
    hs_keys_ok.master_secret.assign(32, 0x45);

    boost::system::error_code case_ec;

    // Hit parse_first_certificate_range branch where cert_list length overflows message size.
    {
        const std::vector<std::uint8_t> bad_list_len = {
            0x0b, 0x00, 0x00, 0x07,
            0x00,
            0x00, 0x00, 0x0a,
            0x00, 0x00, 0x00};
        EXPECT_FALSE(run_case(bad_list_len, hs_keys_ok, case_ec));
        EXPECT_TRUE(case_ec);
    }

    // Hit parse_first_certificate_range branch where cert length overflows message size.
    {
        const std::vector<std::uint8_t> bad_cert_len = {
            0x0b, 0x00, 0x00, 0x07,
            0x00,
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x03};
        EXPECT_FALSE(run_case(bad_cert_len, hs_keys_ok, case_ec));
        EXPECT_TRUE(case_ec);
    }

    // Hit finished verify size mismatch branch.
    {
        std::vector<std::uint8_t> plaintext = cert_msg;
        plaintext.insert(plaintext.end(), cert_verify_msg.begin(), cert_verify_msg.end());
        const std::vector<std::uint8_t> bad_finished = {0x14, 0x00, 0x00, 0x01, 0x00};
        plaintext.insert(plaintext.end(), bad_finished.begin(), bad_finished.end());
        EXPECT_FALSE(run_case(plaintext, hs_keys_ok, case_ec));
        EXPECT_EQ(case_ec, boost::asio::error::invalid_argument);
    }

    // Hit repeated certificate short-circuit + finished hmac mismatch branch.
    {
        std::vector<std::uint8_t> plaintext = cert_msg;
        plaintext.insert(plaintext.end(), cert_msg.begin(), cert_msg.end());
        plaintext.insert(plaintext.end(), cert_verify_msg.begin(), cert_verify_msg.end());
        std::vector<std::uint8_t> wrong_finished(4 + 32, 0x00);
        wrong_finished[0] = 0x14;
        wrong_finished[3] = 0x20;
        plaintext.insert(plaintext.end(), wrong_finished.begin(), wrong_finished.end());
        EXPECT_FALSE(run_case(plaintext, hs_keys_ok, case_ec));
        EXPECT_EQ(case_ec, std::errc::permission_denied);
    }

    // Hit finished verify derive-failed branch (empty secret).
    {
        reality::handshake_keys hs_keys_fail{};
        hs_keys_fail.master_secret.assign(32, 0x67);
        std::vector<std::uint8_t> plaintext = cert_msg;
        plaintext.insert(plaintext.end(), cert_verify_msg.begin(), cert_verify_msg.end());
        const std::vector<std::uint8_t> finished = {0x14, 0x00, 0x00, 0x00};
        plaintext.insert(plaintext.end(), finished.begin(), finished.end());
        EXPECT_FALSE(run_case(plaintext, hs_keys_fail, case_ec));
        EXPECT_TRUE(case_ec);
    }

    // Hit read_handshake_message_bounds incomplete-message break branch.
    {
        const std::vector<std::uint8_t> partial = {0x0b, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00};
        EXPECT_FALSE(run_case(partial, hs_keys_ok, case_ec));
        EXPECT_TRUE(case_ec);
    }
}

TEST(ClientTunnelPoolWhiteboxTest, ClientHelloAndSocketPreparationFailureBranchesWithWrappers)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    boost::asio::io_context io_context;

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    cfg.reality.fingerprint = "chrome";
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 1);

    std::uint8_t ephemeral_pub[32];
    std::uint8_t ephemeral_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(ephemeral_pub, ephemeral_priv));
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);

    // Hit select_fingerprint_spec(fingerprint_type.has_value()) branch.
    {
        boost::asio::ip::tcp::socket disconnected(io_context);
        std::expected<mux::client_tunnel_pool::handshake_result, boost::system::error_code> hs_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           hs_res = co_await perform_reality_handshake_expected(*tunnel_pool, disconnected);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(hs_res.has_value());
        EXPECT_TRUE(hs_res.error());
    }

    io_context.restart();

    // Hit derive_client_auth_key_material RAND failure branch.
    {
        fail_next_rand_bytes();
        boost::asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        std::expected<void, boost::system::error_code> hello_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           hello_res = co_await generate_and_send_client_hello_expected(
                               *tunnel_pool, disconnected, ephemeral_pub, ephemeral_priv, spec, trans);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_res.has_value());
        EXPECT_EQ(hello_res.error(), std::errc::operation_canceled);
    }

    io_context.restart();

    // Hit derive_client_auth_key_material HKDF expand failure branch.
    {
        fail_next_hkdf_add_info();
        boost::asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        std::expected<void, boost::system::error_code> hello_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           hello_res = co_await generate_and_send_client_hello_expected(
                               *tunnel_pool, disconnected, ephemeral_pub, ephemeral_priv, spec, trans);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_res.has_value());
        EXPECT_TRUE(hello_res.error());
    }

    io_context.restart();

    // Hit encrypt_client_session_id failure branch.
    {
        fail_next_cipher_ctx_ctrl();
        fail_next_encrypt_init();
        boost::asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        std::expected<void, boost::system::error_code> hello_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           hello_res = co_await generate_and_send_client_hello_expected(
                               *tunnel_pool, disconnected, ephemeral_pub, ephemeral_priv, spec, trans);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_res.has_value());
        EXPECT_TRUE(hello_res.error());
    }

    io_context.restart();

    // Hit prepare_socket_for_connect open-failure branch.
    {
        fail_next_socket(EMFILE);
        boost::asio::ip::tcp::socket sock(io_context);
        std::expected<void, boost::system::error_code> connect_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           connect_res = co_await tcp_connect_expected(*tunnel_pool, io_context, sock);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(connect_res.has_value());
        EXPECT_TRUE(connect_res.error());
    }

    io_context.restart();

    // Hit prepare_socket_for_connect close/open and set-mark warning branches.
    {
        boost::asio::ip::tcp::socket sock(io_context);
        boost::system::error_code open_ec;
        (void)        sock.open(boost::asio::ip::tcp::v4(), open_ec);
        ASSERT_FALSE(open_ec);
        std::expected<void, boost::system::error_code> connect_res;
        boost::asio::co_spawn(io_context,
                       [&]() -> boost::asio::awaitable<void>
                       {
                           connect_res = co_await tcp_connect_expected(*tunnel_pool, io_context, sock);
                           co_return;
                       },
                       boost::asio::detached);
        io_context.run();
        EXPECT_FALSE(connect_res.has_value());
    }
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloCoversX25519DeriveFailure)
{
    boost::asio::io_context io_context;
    boost::system::error_code ec;

    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    boost::asio::ip::tcp::socket writer(io_context);
    (void)    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    boost::asio::ip::tcp::socket reader(io_context);
    (void)    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> const server_random(32, 0x52);
    std::vector<std::uint8_t> const session_id(32, 0x33);
    std::vector<std::uint8_t> const key_share(32, 0x44);
    auto sh = reality::construct_server_hello(server_random, session_id, 0x1301, reality::tls_consts::group::kX25519, key_share);
    auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh.size()));
    record.insert(record.end(), sh.begin(), sh.end());
    boost::asio::write(writer, boost::asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    (void)    writer.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    fail_next_pkey_derive();

    reality::transcript trans;
    std::expected<mux::client_tunnel_pool::server_hello_res, boost::system::error_code> sh_res;
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       sh_res = co_await process_server_hello_expected(reader, peer_priv, trans);
                       co_return;
                   },
                   boost::asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.has_value());
    EXPECT_TRUE(sh_res.error());
}

TEST(ClientTunnelPoolWhiteboxTest, TcpConnectSuccessCoversLocalEndpointFailureLogBranch)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    ASSERT_TRUE(mux::test::open_ephemeral_tcp_acceptor(acceptor));
    const auto listen_port = acceptor.local_endpoint().port();

    auto cfg = make_base_cfg();
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = listen_port;
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    std::shared_ptr<boost::asio::ip::tcp::socket> const accepted_peer = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
    acceptor.async_accept(
        *accepted_peer,
        [&](const boost::system::error_code&) {});

    boost::asio::ip::tcp::socket client_socket(io_context);
    std::expected<void, boost::system::error_code> connect_res;
    fail_next_getsockname(ENOTSOCK);
    boost::asio::co_spawn(io_context,
                   [&]() -> boost::asio::awaitable<void>
                   {
                       connect_res = co_await tcp_connect_expected(*tunnel_pool, io_context, client_socket);
                       co_return;
                   },
                   boost::asio::detached);

    io_context.run();
    EXPECT_TRUE(connect_res.has_value());
}
// NOLINTEND(bugprone-unused-return-value, misc-include-cleaner)
// NOLINTEND(modernize-return-braced-init-list, readability-function-cognitive-complexity)
