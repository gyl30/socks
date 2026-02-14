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
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/write.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>

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
#define private public
#include "client_tunnel_pool.h"
#undef private

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

extern "C" int __real_RAND_bytes(unsigned char* buf, int num);
extern "C" int __real_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen);
extern "C" int __real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr);
extern "C" int __real_EVP_EncryptInit_ex(
    EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv);
extern "C" int __real_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen);
extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen);

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)
{
    if (g_fail_rand_bytes_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_RAND_bytes(buf, num);
}

extern "C" int __wrap_EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* ctx, const unsigned char* info, int infolen)
{
    if (g_fail_hkdf_add_info_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);
}

extern "C" int __wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int type, int arg, void* ptr)
{
    if (type == EVP_CTRL_GCM_GET_TAG && g_fail_cipher_ctx_ctrl_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_CIPHER_CTX_ctrl(ctx, type, arg, ptr);
}

extern "C" int __wrap_EVP_EncryptInit_ex(
    EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, ENGINE* impl, const unsigned char* key, const unsigned char* iv)
{
    if (g_fail_encrypt_init_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_EncryptInit_ex(ctx, type, impl, key, iv);
}

extern "C" int __wrap_EVP_PKEY_derive(EVP_PKEY_CTX* ctx, unsigned char* key, size_t* keylen)
{
    if (g_fail_pkey_derive_once.exchange(false, std::memory_order_acq_rel))
    {
        return 0;
    }
    return __real_EVP_PKEY_derive(ctx, key, keylen);
}

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen)
{
    if (g_fail_getsockname_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_getsockname_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_getsockname(sockfd, addr, addrlen);
}

std::uint16_t pick_free_port()
{
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

mux::config make_base_cfg()
{
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = pick_free_port();
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
    reality::openssl_ptrs::evp_pkey_ptr sign_key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), sign_key_bytes.size()));
    if (sign_key == nullptr)
    {
        return {};
    }
    return reality::construct_certificate_verify(sign_key.get(), {});
}

}    // namespace

TEST(ClientTunnelPoolWhiteboxTest, ConfigValidationAndStartGuardBranches)
{
    std::error_code ec;
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
    cfg.reality.fingerprint = "invalid-fingerprint";
    auto invalid_fingerprint_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_FALSE(invalid_fingerprint_pool->valid());

    invalid_fingerprint_pool->start();
    EXPECT_TRUE(invalid_fingerprint_pool->stop_.load(std::memory_order_acquire));
}

TEST(ClientTunnelPoolWhiteboxTest, SelectAndIndexGuardBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    EXPECT_EQ(tunnel_pool->select_tunnel(), nullptr);

    asio::io_context io_context;
    auto pending_socket = std::make_shared<asio::ip::tcp::socket>(io_context);

    tunnel_pool->tunnel_io_contexts_.resize(1, nullptr);
    tunnel_pool->close_pending_socket(0, pending_socket);

    tunnel_pool->clear_pending_socket_if_match(42, pending_socket);
    tunnel_pool->clear_tunnel_if_match(42, nullptr);
    tunnel_pool->tunnel_pool_.resize(1);
    tunnel_pool->clear_tunnel_if_match(0, nullptr);

    auto created_socket = tunnel_pool->create_pending_socket(io_context, 9);
    ASSERT_NE(created_socket, nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, BuildTunnelAndWaitRetryBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    asio::io_context io_context;
    asio::ip::tcp::socket socket(io_context);

    mux::client_tunnel_pool::handshake_result bad_handshake{};
    bad_handshake.cipher_suite = 0x1301;
    bad_handshake.md = EVP_sha256();
    bad_handshake.cipher = EVP_aes_128_gcm();

    auto tunnel = tunnel_pool->build_tunnel(std::move(socket), io_context, 1, bad_handshake, "trace-1");
    ASSERT_NE(tunnel, nullptr);

    tunnel_pool->stop_.store(true, std::memory_order_release);
    asio::co_spawn(io_context,
                   [tunnel_pool, &io_context]() -> asio::awaitable<void>
                   {
                       co_await tunnel_pool->wait_remote_retry(io_context);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
}

TEST(ClientTunnelPoolWhiteboxTest, TcpConnectAndHandshakeErrorBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.outbound.host = "invalid.host.for.coverage.test";
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    asio::io_context io_context;

    asio::ip::tcp::socket socket(io_context);
    bool connect_ok = true;
    std::error_code connect_ec;
    asio::co_spawn(io_context,
                   [tunnel_pool, &io_context, &socket, &connect_ok, &connect_ec]() -> asio::awaitable<void>
                   {
                       connect_ok = co_await tunnel_pool->tcp_connect(io_context, socket, connect_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(connect_ok);
    EXPECT_TRUE(connect_ec);

    io_context.restart();

    asio::ip::tcp::socket try_socket(io_context);
    const asio::ip::tcp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), 1);
    std::error_code open_ec;
    try_socket.open(endpoint.protocol(), open_ec);
    ASSERT_FALSE(open_ec);

    bool try_connect_ok = true;
    std::error_code try_connect_ec;
    asio::co_spawn(io_context,
                   [tunnel_pool, &try_socket, endpoint, &try_connect_ok, &try_connect_ec]() -> asio::awaitable<void>
                   {
                       try_connect_ok = co_await tunnel_pool->try_connect_endpoint(try_socket, endpoint, try_connect_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(try_connect_ok);
    EXPECT_TRUE(try_connect_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, ClientHelloAndServerHelloIoErrorBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    asio::io_context io_context;

    std::array<std::uint8_t, 32> ephemeral_pub{};
    std::array<std::uint8_t, 32> ephemeral_priv{};
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(ephemeral_pub.data(), ephemeral_priv.data()));

    asio::ip::tcp::socket disconnected_socket(io_context);
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
    reality::transcript trans;

    bool hello_ok = true;
    std::error_code hello_ec;
    asio::co_spawn(io_context,
                   [tunnel_pool, &disconnected_socket, ephemeral_pub, ephemeral_priv, spec, &trans, &hello_ok, &hello_ec]() mutable -> asio::awaitable<void>
                   {
                       hello_ok = co_await tunnel_pool->generate_and_send_client_hello(
                           disconnected_socket, ephemeral_pub.data(), ephemeral_priv.data(), spec, trans, hello_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_ok);
    EXPECT_TRUE(hello_ec);

    io_context.restart();

    mux::client_tunnel_pool::server_hello_res sh_res;
    std::error_code sh_ec;
    asio::co_spawn(io_context,
                   [&disconnected_socket, ephemeral_priv, &trans, &sh_res, &sh_ec]() -> asio::awaitable<void>
                   {
                       sh_res = co_await mux::client_tunnel_pool::process_server_hello(disconnected_socket, ephemeral_priv.data(), trans, sh_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.ok);
    EXPECT_TRUE(sh_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloRejectsUnsupportedCipherAndKeyshare)
{
    auto run_case = [](std::uint16_t cipher_suite, std::uint16_t group, std::size_t key_share_len)
    {
        asio::io_context io_context;
        std::error_code ec;

        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
        asio::ip::tcp::socket writer(io_context);
        writer.connect(acceptor.local_endpoint(), ec);
        ASSERT_FALSE(ec);
        asio::ip::tcp::socket reader(io_context);
        acceptor.accept(reader, ec);
        ASSERT_FALSE(ec);

        std::vector<std::uint8_t> server_random(32, 0x42);
        std::vector<std::uint8_t> session_id(32, 0x11);
        std::vector<std::uint8_t> key_share(key_share_len, 0x22);
        auto sh = reality::construct_server_hello(server_random, session_id, cipher_suite, group, key_share);
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh.size()));
        record.insert(record.end(), sh.begin(), sh.end());
        asio::write(writer, asio::buffer(record), ec);
        ASSERT_FALSE(ec);
        writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

        std::uint8_t peer_pub[32];
        std::uint8_t peer_priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

        reality::transcript trans;
        std::error_code hs_ec;
        mux::client_tunnel_pool::server_hello_res sh_res;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           sh_res = co_await mux::client_tunnel_pool::process_server_hello(reader, peer_priv, trans, hs_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(sh_res.ok);
        EXPECT_TRUE(hs_ec);
    };

    run_case(0x9999, reality::tls_consts::group::kX25519, 32);
    run_case(0x1301, 0x0017, 32);
    run_case(0x1301, reality::tls_consts::group::kX25519, 31);
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloRejectsTruncatedSessionData)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> truncated_sh(39, 0x00);
    truncated_sh[0] = 0x02;
    truncated_sh[4] = 0x03;
    truncated_sh[5] = 0x03;
    truncated_sh[38] = 5;
    auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(truncated_sh.size()));
    record.insert(record.end(), truncated_sh.begin(), truncated_sh.end());
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    reality::transcript trans;
    std::error_code hs_ec;
    mux::client_tunnel_pool::server_hello_res sh_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       sh_res = co_await mux::client_tunnel_pool::process_server_hello(reader, peer_priv, trans, hs_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.ok);
    EXPECT_TRUE(hs_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsCertVerifyBeforeCertificate)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x11);
    const std::vector<std::uint8_t> iv(12, 0x22);
    const std::vector<std::uint8_t> plaintext = {0x0f, 0x00, 0x00, 0x00};
    auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
    ASSERT_FALSE(ec);
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::error_code loop_ec;
    std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                           reader, {key, iv}, hs_keys, false, "verify-before-cert", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.first);
    EXPECT_TRUE(loop_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsFinishedBeforeCertificateVerify)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x31);
    const std::vector<std::uint8_t> iv(12, 0x41);
    const std::vector<std::uint8_t> plaintext = {0x14, 0x00, 0x00, 0x00};
    auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
    ASSERT_FALSE(ec);
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::error_code loop_ec;
    std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                           reader, {key, iv}, hs_keys, false, "finished-before-verify", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.first);
    EXPECT_TRUE(loop_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsMalformedCertificateMessage)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x51);
    const std::vector<std::uint8_t> iv(12, 0x61);
    const std::vector<std::uint8_t> plaintext = {0x0b, 0x00, 0x00, 0x01, 0x00};
    auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
    ASSERT_FALSE(ec);
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::error_code loop_ec;
    std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                           reader, {key, iv}, hs_keys, false, "bad-cert-msg", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.first);
    EXPECT_TRUE(loop_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, ClientHelloBuildFailureBranchesForAuthMaterialAndPayload)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    asio::io_context io_context;

    std::uint8_t ephemeral_pub[32];
    std::uint8_t ephemeral_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(ephemeral_pub, ephemeral_priv));
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);

    mux::config missing_pub_cfg = make_base_cfg();
    missing_pub_cfg.reality.public_key.clear();
    auto missing_pub_pool = std::make_shared<mux::client_tunnel_pool>(pool, missing_pub_cfg, 0);
    asio::ip::tcp::socket disconnected_socket_1(io_context);
    reality::transcript trans_1;
    bool hello_ok_1 = true;
    std::error_code hello_ec_1;
    asio::co_spawn(io_context,
                   [missing_pub_pool, &disconnected_socket_1, ephemeral_pub, ephemeral_priv, spec, &trans_1, &hello_ok_1, &hello_ec_1]() mutable -> asio::awaitable<void>
                   {
                       hello_ok_1 = co_await missing_pub_pool->generate_and_send_client_hello(
                           disconnected_socket_1, ephemeral_pub, ephemeral_priv, spec, trans_1, hello_ec_1);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_ok_1);
    EXPECT_TRUE(hello_ec_1);

    io_context.restart();

    auto invalid_short_id_cfg = make_base_cfg();
    invalid_short_id_cfg.reality.public_key = generate_public_key_hex();
    invalid_short_id_cfg.reality.short_id = "010203040506070809";
    auto invalid_short_id_pool = std::make_shared<mux::client_tunnel_pool>(pool, invalid_short_id_cfg, 0);
    asio::ip::tcp::socket disconnected_socket_2(io_context);
    reality::transcript trans_2;
    bool hello_ok_2 = true;
    std::error_code hello_ec_2;
    asio::co_spawn(io_context,
                   [invalid_short_id_pool, &disconnected_socket_2, ephemeral_pub, ephemeral_priv, spec, &trans_2, &hello_ok_2, &hello_ec_2]() mutable -> asio::awaitable<void>
                   {
                       hello_ok_2 = co_await invalid_short_id_pool->generate_and_send_client_hello(
                           disconnected_socket_2, ephemeral_pub, ephemeral_priv, spec, trans_2, hello_ec_2);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(hello_ok_2);
    EXPECT_EQ(hello_ec_2, std::errc::invalid_argument);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsMalformedCertificateVerifyAfterCertificate)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0x81);
    const std::vector<std::uint8_t> iv(12, 0x91);
    const std::vector<std::uint8_t> cert_msg = {0x0b, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> malformed_cert_verify = {0x0f, 0x00, 0x00, 0x00};
    std::vector<std::uint8_t> plaintext = cert_msg;
    plaintext.insert(plaintext.end(), malformed_cert_verify.begin(), malformed_cert_verify.end());
    auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
    ASSERT_FALSE(ec);
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::error_code loop_ec;
    std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                           reader, {key, iv}, hs_keys, false, "bad-cert-verify-payload", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.first);
    EXPECT_EQ(loop_ec, asio::error::invalid_argument);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopRejectsUnsupportedCertificateVerifyScheme)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    const std::vector<std::uint8_t> key(16, 0xa1);
    const std::vector<std::uint8_t> iv(12, 0xb1);
    const std::vector<std::uint8_t> cert_msg = {0x0b, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> unsupported_cert_verify = {0x0f, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00};
    std::vector<std::uint8_t> plaintext = cert_msg;
    plaintext.insert(plaintext.end(), unsupported_cert_verify.begin(), unsupported_cert_verify.end());
    auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
    ASSERT_FALSE(ec);
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    reality::transcript trans;
    reality::handshake_keys hs_keys;
    std::error_code loop_ec;
    std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                           reader, {key, iv}, hs_keys, false, "unsupported-cert-verify-scheme", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(loop_res.first);
    EXPECT_EQ(loop_ec, asio::error::no_protocol_option);
}

TEST(ClientTunnelPoolWhiteboxTest, HandshakeReadLoopCertificateRangeAndFinishedBranches)
{
    auto run_case = [](const std::vector<std::uint8_t>& plaintext,
                       const reality::handshake_keys& hs_keys,
                       std::error_code& loop_ec) -> bool
    {
        asio::io_context io_context;
        std::error_code ec;

        asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
        asio::ip::tcp::socket writer(io_context);
        writer.connect(acceptor.local_endpoint(), ec);
        EXPECT_FALSE(ec);
        asio::ip::tcp::socket reader(io_context);
        acceptor.accept(reader, ec);
        EXPECT_FALSE(ec);

        const std::vector<std::uint8_t> key(16, 0x12);
        const std::vector<std::uint8_t> iv(12, 0x34);
        auto record = reality::tls_record_layer::encrypt_record(EVP_aes_128_gcm(), key, iv, 0, plaintext, reality::kContentTypeHandshake, ec);
        EXPECT_FALSE(ec);
        asio::write(writer, asio::buffer(record), ec);
        EXPECT_FALSE(ec);
        writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

        reality::transcript trans;
        std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> loop_res;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           loop_res = co_await mux::client_tunnel_pool::handshake_read_loop(
                               reader, {key, iv}, hs_keys, false, "whitebox-finished", trans, EVP_aes_128_gcm(), EVP_sha256(), loop_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        return loop_res.first;
    };

    const auto cert_msg = build_minimal_valid_certificate_message();
    const auto cert_verify_msg = build_certificate_verify_message();
    ASSERT_FALSE(cert_verify_msg.empty());

    reality::handshake_keys hs_keys_ok{};
    hs_keys_ok.server_handshake_traffic_secret.assign(32, 0x21);
    hs_keys_ok.master_secret.assign(32, 0x45);

    std::error_code case_ec;

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
        EXPECT_EQ(case_ec, asio::error::invalid_argument);
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
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);
    asio::io_context io_context;

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
        asio::ip::tcp::socket disconnected(io_context);
        std::error_code hs_ec;
        std::pair<bool, mux::client_tunnel_pool::handshake_result> hs_res;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           hs_res = co_await tunnel_pool->perform_reality_handshake(disconnected, hs_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(hs_res.first);
        EXPECT_TRUE(hs_ec);
    }

    io_context.restart();

    // Hit derive_client_auth_key_material RAND failure branch.
    {
        fail_next_rand_bytes();
        asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        bool hello_ok = true;
        std::error_code hello_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           hello_ok = co_await tunnel_pool->generate_and_send_client_hello(
                               disconnected, ephemeral_pub, ephemeral_priv, spec, trans, hello_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_ok);
        EXPECT_EQ(hello_ec, std::errc::operation_canceled);
    }

    io_context.restart();

    // Hit derive_client_auth_key_material HKDF expand failure branch.
    {
        fail_next_hkdf_add_info();
        asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        bool hello_ok = true;
        std::error_code hello_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           hello_ok = co_await tunnel_pool->generate_and_send_client_hello(
                               disconnected, ephemeral_pub, ephemeral_priv, spec, trans, hello_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_ok);
        EXPECT_TRUE(hello_ec);
    }

    io_context.restart();

    // Hit encrypt_client_session_id failure branch.
    {
        fail_next_cipher_ctx_ctrl();
        fail_next_encrypt_init();
        asio::ip::tcp::socket disconnected(io_context);
        reality::transcript trans;
        bool hello_ok = true;
        std::error_code hello_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           hello_ok = co_await tunnel_pool->generate_and_send_client_hello(
                               disconnected, ephemeral_pub, ephemeral_priv, spec, trans, hello_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(hello_ok);
        EXPECT_TRUE(hello_ec);
    }

    io_context.restart();

    // Hit prepare_socket_for_connect open-failure branch.
    {
        fail_next_socket(EMFILE);
        asio::ip::tcp::socket sock(io_context);
        bool connect_ok = true;
        std::error_code connect_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           connect_ok = co_await tunnel_pool->tcp_connect(io_context, sock, connect_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(connect_ok);
        EXPECT_TRUE(connect_ec);
    }

    io_context.restart();

    // Hit prepare_socket_for_connect close/open and set-mark warning branches.
    {
        asio::ip::tcp::socket sock(io_context);
        std::error_code open_ec;
        sock.open(asio::ip::tcp::v4(), open_ec);
        ASSERT_FALSE(open_ec);
        bool connect_ok = true;
        std::error_code connect_ec;
        asio::co_spawn(io_context,
                       [&]() -> asio::awaitable<void>
                       {
                           connect_ok = co_await tunnel_pool->tcp_connect(io_context, sock, connect_ec);
                           co_return;
                       },
                       asio::detached);
        io_context.run();
        EXPECT_FALSE(connect_ok);
    }
}

TEST(ClientTunnelPoolWhiteboxTest, ProcessServerHelloCoversX25519DeriveFailure)
{
    asio::io_context io_context;
    std::error_code ec;

    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    asio::ip::tcp::socket writer(io_context);
    writer.connect(acceptor.local_endpoint(), ec);
    ASSERT_FALSE(ec);
    asio::ip::tcp::socket reader(io_context);
    acceptor.accept(reader, ec);
    ASSERT_FALSE(ec);

    std::vector<std::uint8_t> server_random(32, 0x52);
    std::vector<std::uint8_t> session_id(32, 0x33);
    std::vector<std::uint8_t> key_share(32, 0x44);
    auto sh = reality::construct_server_hello(server_random, session_id, 0x1301, reality::tls_consts::group::kX25519, key_share);
    auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh.size()));
    record.insert(record.end(), sh.begin(), sh.end());
    asio::write(writer, asio::buffer(record), ec);
    ASSERT_FALSE(ec);
    writer.shutdown(asio::ip::tcp::socket::shutdown_send, ec);

    std::uint8_t peer_pub[32];
    std::uint8_t peer_priv[32];
    ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(peer_pub, peer_priv));

    fail_next_pkey_derive();

    reality::transcript trans;
    std::error_code hs_ec;
    mux::client_tunnel_pool::server_hello_res sh_res;
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       sh_res = co_await mux::client_tunnel_pool::process_server_hello(reader, peer_priv, trans, hs_ec);
                       co_return;
                   },
                   asio::detached);
    io_context.run();
    EXPECT_FALSE(sh_res.ok);
    EXPECT_TRUE(hs_ec);
}

TEST(ClientTunnelPoolWhiteboxTest, TcpConnectSuccessCoversLocalEndpointFailureLogBranch)
{
    std::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto listen_port = acceptor.local_endpoint().port();

    auto cfg = make_base_cfg();
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = listen_port;
    cfg.reality.public_key = generate_public_key_hex();
    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);

    std::shared_ptr<asio::ip::tcp::socket> accepted_peer = std::make_shared<asio::ip::tcp::socket>(io_context);
    acceptor.async_accept(
        *accepted_peer,
        [&](const std::error_code&) {});

    asio::ip::tcp::socket client_socket(io_context);
    bool connect_ok = false;
    std::error_code connect_ec;
    fail_next_getsockname(ENOTSOCK);
    asio::co_spawn(io_context,
                   [&]() -> asio::awaitable<void>
                   {
                       connect_ok = co_await tunnel_pool->tcp_connect(io_context, client_socket, connect_ec);
                       co_return;
                   },
                   asio::detached);

    io_context.run();
    EXPECT_TRUE(connect_ok);
    EXPECT_FALSE(connect_ec);
}
