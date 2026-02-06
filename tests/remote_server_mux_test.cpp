#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>

#include "log.h"
#include "protocol.h"
#include "ch_parser.h"
#include "mux_codec.h"
#include "crypto_util.h"
#include "local_client.h"
#include "mux_protocol.h"
#include "remote_server.h"
#include "reality_auth.h"
#include "context_pool.h"
#include "reality_messages.h"

using namespace mux;

class RemoteServerMuxTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32], priv[32];
        (void)reality::crypto_util::generate_x25519_keypair(pub, priv);
        server_priv_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        server_pub_key = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        short_id = "0102030405060708";
    }
    std::string server_priv_key;
    std::string server_pub_key;
    std::string short_id;

    struct handshake_keys
    {
        std::vector<uint8_t> c_hs_key;
        std::vector<uint8_t> c_hs_iv;
        std::vector<uint8_t> s_hs_key;
        std::vector<uint8_t> s_hs_iv;
        std::vector<uint8_t> c_app_key;
        std::vector<uint8_t> c_app_iv;
        std::vector<uint8_t> s_app_key;
        std::vector<uint8_t> s_app_iv;
    };

    void perform_full_handshake(asio::ip::tcp::socket& sock, handshake_keys& keys)
    {
        std::error_code ec;
        std::uint8_t c_pub[32], c_priv[32];
        reality::crypto_util::generate_x25519_keypair(c_pub, c_priv);

        auto shared =
            reality::crypto_util::x25519_derive(reality::crypto_util::hex_to_bytes(server_priv_key), std::vector<uint8_t>(c_pub, c_pub + 32), ec);
        auto salt = std::vector<uint8_t>(32, 0x09);
        auto prk = reality::crypto_util::hkdf_extract(std::vector<uint8_t>(salt.begin(), salt.begin() + 20), shared, EVP_sha256(), ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, reality::crypto_util::hex_to_bytes("5245414c495459"), 16, EVP_sha256(), ec);

        std::array<uint8_t, 16> payload;
        reality::build_auth_payload(reality::crypto_util::hex_to_bytes(short_id), static_cast<uint32_t>(time(nullptr)), payload);

        auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
        auto ch_tmp =
            reality::ClientHelloBuilder::build(spec, std::vector<uint8_t>(32, 0), salt, std::vector<uint8_t>(c_pub, c_pub + 32), "www.google.com");
        auto info = mux::ch_parser::parse(ch_tmp);

        std::vector<uint8_t> aad = ch_tmp;
        std::fill_n(aad.begin() + info.sid_offset, 32, 0);

        auto sid = reality::crypto_util::aead_encrypt(EVP_aes_128_gcm(),
                                                      auth_key,
                                                      std::vector<uint8_t>(salt.begin() + 20, salt.end()),
                                                      std::vector<uint8_t>(payload.begin(), payload.end()),
                                                      aad,
                                                      ec);

        auto ch_final = reality::ClientHelloBuilder::build(spec, sid, salt, std::vector<uint8_t>(c_pub, c_pub + 32), "www.google.com");
        auto record = reality::write_record_header(reality::kContentTypeHandshake, static_cast<uint16_t>(ch_final.size()));
        record.insert(record.end(), ch_final.begin(), ch_final.end());
        asio::write(sock, asio::buffer(record));

        std::uint8_t sh_head[5];
        asio::read(sock, asio::buffer(sh_head, 5));
        uint16_t sh_len = (sh_head[3] << 8) | sh_head[4];
        std::vector<uint8_t> sh_body(sh_len);
        asio::read(sock, asio::buffer(sh_body));

        std::uint8_t next_head[5];
        asio::read(sock, asio::buffer(next_head, 5));
        if (next_head[0] == 0x14)
        {
            uint16_t l = (next_head[3] << 8) | next_head[4];
            std::vector<uint8_t> b(l);
            asio::read(sock, asio::buffer(b));
            asio::read(sock, asio::buffer(next_head, 5));
        }

        uint16_t enc_len = (next_head[3] << 8) | next_head[4];
        std::vector<uint8_t> enc_body(enc_len);
        asio::read(sock, asio::buffer(enc_body));
    }
};

TEST_F(RemoteServerMuxTest, ProcessTcpConnectRequest)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 30001;
    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});
    server->start();

    mux::config::timeout_t timeouts;
    timeouts.read = 5;
    timeouts.write = 5;
    uint16_t local_socks_port = 30002;
    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        local_socks_port,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        timeouts);
    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        std::uint8_t conn_req[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 1};
        asio::write(proxy_sock, asio::buffer(conn_req));

        std::uint8_t conn_resp[10];
        asio::read(proxy_sock, asio::buffer(conn_resp, 10));

        EXPECT_EQ(conn_resp[0], 0x05);
    }

    client->stop();
    server->stop();
    pool.stop();
    pool_thread.join();
}

TEST_F(RemoteServerMuxTest, ProcessUdpAssociateRequest)
{
    std::error_code ec;
    mux::io_context_pool pool(2, ec);
    ASSERT_FALSE(ec);
    std::thread pool_thread([&pool] { pool.run(); });

    std::uint16_t server_port = 30003;
    auto server = std::make_shared<mux::remote_server>(
        pool, server_port, std::vector<mux::config::fallback_entry>{}, server_priv_key, short_id, mux::config::timeout_t{}, mux::config::limits_t{});
    server->start();

    mux::config::timeout_t timeouts;
    timeouts.read = 5;
    timeouts.write = 5;
    uint16_t local_socks_port = 30004;
    auto client = std::make_shared<mux::local_client>(
        pool,
        "127.0.0.1",
        std::to_string(server_port),
        local_socks_port,
        server_pub_key,
        "www.google.com",
        short_id,
        reality::crypto_util::bytes_to_hex(reality::crypto_util::extract_ed25519_public_key(reality::crypto_util::hex_to_bytes(server_priv_key), ec)),
        timeouts);
    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    {
        asio::ip::tcp::socket proxy_sock(pool.get_io_context());
        proxy_sock.connect({asio::ip::make_address("127.0.0.1"), local_socks_port});

        std::uint8_t handshake[] = {0x05, 0x01, 0x00};
        asio::write(proxy_sock, asio::buffer(handshake));
        std::uint8_t resp[2];
        asio::read(proxy_sock, asio::buffer(resp, 2));

        std::uint8_t udp_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        asio::write(proxy_sock, asio::buffer(udp_req));

        std::uint8_t udp_resp[10];
        asio::read(proxy_sock, asio::buffer(udp_resp, 10));
        EXPECT_EQ(udp_resp[0], 0x05);
        EXPECT_EQ(udp_resp[1], 0x00);
    }

    client->stop();
    server->stop();
    pool.stop();
    pool_thread.join();
}
