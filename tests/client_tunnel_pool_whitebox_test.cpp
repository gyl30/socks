#include <array>
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

}    // namespace

TEST(ClientTunnelPoolWhiteboxTest, ConfigValidationAndStartGuardBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    auto cfg = make_base_cfg();
    cfg.reality.public_key = generate_public_key_hex();

    auto no_fingerprint_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    EXPECT_TRUE(no_fingerprint_pool->valid());

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
    mux::io_context_pool pool(1, ec);
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

    auto created_socket = tunnel_pool->create_pending_socket(io_context, 9);
    ASSERT_NE(created_socket, nullptr);
}

TEST(ClientTunnelPoolWhiteboxTest, BuildTunnelAndWaitRetryBranches)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
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
    mux::io_context_pool pool(1, ec);
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
    mux::io_context_pool pool(1, ec);
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
    mux::io_context_pool pool(1, ec);
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
