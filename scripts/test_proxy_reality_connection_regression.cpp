#include <span>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <iostream>

#include <boost/asio.hpp>
extern "C"
{
#include <openssl/evp.h>
}

#include "config.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "reality/session/record_context.h"
#include "tls/core.h"
#include "tls/record_layer.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

reality::traffic_key_material make_key_material(const uint8_t key_seed, const uint8_t iv_seed)
{
    reality::traffic_key_material material;
    material.key.assign(16, key_seed);
    material.iv.assign(12, iv_seed);
    return material;
}

reality::reality_record_context make_record_context()
{
    reality::reality_record_context context;
    context.negotiated.cipher = EVP_aes_128_gcm();
    context.read_keys = make_key_material(0x11, 0x22);
    context.write_keys = make_key_material(0x11, 0x22);
    return context;
}

std::vector<uint8_t> make_new_session_ticket_plaintext(const std::size_t plaintext_size)
{
    if (plaintext_size < 18U)
    {
        return {};
    }
    std::vector<uint8_t> out;
    out.reserve(plaintext_size);
    out.push_back(tls::kHandshakeTypeNewSessionTicket);
    const auto body_len = static_cast<uint32_t>(plaintext_size - 4U);
    out.push_back(static_cast<uint8_t>((body_len >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((body_len >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(body_len & 0xFFU));
    out.insert(out.end(), {0x00, 0x01, 0x51, 0x80});
    out.insert(out.end(), {0x12, 0x34, 0x56, 0x78});
    out.push_back(0x00);
    const auto ticket_len = static_cast<uint16_t>(plaintext_size - 17U);
    out.push_back(static_cast<uint8_t>((ticket_len >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(ticket_len & 0xFFU));
    out.insert(out.end(), ticket_len, 0xAB);
    out.push_back(0x00);
    out.push_back(0x00);
    return out;
}

bool test_explicit_record_padding()
{
    boost::system::error_code ec;
    const tls::cipher_context encrypt_ctx;
    const auto key_material = make_key_material(0x11, 0x22);
    const std::vector<uint8_t> plaintext{'h', 's'};
    constexpr std::size_t padding_len = 7;
    std::vector<uint8_t> ciphertext;
    tls::record_layer::encrypt_tls_record(
        encrypt_ctx, EVP_aes_128_gcm(), key_material, 0, plaintext, tls::kContentTypeHandshake, ciphertext, ec, padding_len);

    bool ok = require(!ec, "explicit padding encrypt failed");
    const auto expected_wire_size = tls::kTlsRecordHeaderSize + plaintext.size() + 1U + padding_len + tls::kAeadTagSize;
    ok = ok && require(ciphertext.size() == expected_wire_size, "explicit padding produced wrong wire size");

    const tls::cipher_context decrypt_ctx;
    std::vector<uint8_t> decrypted(plaintext.size() + 1U + padding_len);
    uint8_t content_type = 0;
    const auto decrypted_len = tls::record_layer::decrypt_tls_record(
        decrypt_ctx, EVP_aes_128_gcm(), key_material.key, key_material.iv, 0, ciphertext, decrypted, content_type, ec);
    decrypted.resize(decrypted_len);
    ok = ok && require(!ec, "explicit padding decrypt failed");
    ok = ok && require(content_type == tls::kContentTypeHandshake, "explicit padding changed content type");
    ok = ok && require(decrypted == plaintext, "explicit padding changed plaintext");

    constexpr std::size_t max_record_padding_len = 128;
    const std::vector<uint8_t> max_plaintext(tls::kMaxTlsPlaintextLen, 0x42);
    std::vector<uint8_t> max_ciphertext;
    tls::record_layer::encrypt_tls_record(encrypt_ctx,
                                          EVP_aes_128_gcm(),
                                          key_material,
                                          1,
                                          max_plaintext,
                                          tls::kContentTypeApplicationData,
                                          max_ciphertext,
                                          ec,
                                          max_record_padding_len);
    const auto expected_max_wire_size =
        tls::kTlsRecordHeaderSize + max_plaintext.size() + 1U + max_record_padding_len + tls::kAeadTagSize;
    ok = ok && require(!ec, "max plaintext explicit padding encrypt failed");
    ok = ok && require(max_ciphertext.size() == expected_max_wire_size, "max plaintext explicit padding produced wrong wire size");
    ok = ok && require(max_ciphertext.size() <= tls::kMaxTls13RecordWireLen, "max plaintext explicit padding exceeded tls13 record limit");

    std::vector<uint8_t> max_decrypted(max_plaintext.size() + 1U + max_record_padding_len);
    content_type = 0;
    const auto max_decrypted_len = tls::record_layer::decrypt_tls_record(
        decrypt_ctx, EVP_aes_128_gcm(), key_material.key, key_material.iv, 1, max_ciphertext, max_decrypted, content_type, ec);
    max_decrypted.resize(max_decrypted_len);
    ok = ok && require(!ec, "max plaintext explicit padding decrypt failed");
    ok = ok && require(content_type == tls::kContentTypeApplicationData, "max plaintext explicit padding changed content type");
    ok = ok && require(max_decrypted == max_plaintext, "max plaintext explicit padding changed plaintext");

    std::vector<uint8_t> app_ciphertext;
    tls::record_layer::encrypt_tls_record(
        encrypt_ctx, EVP_aes_128_gcm(), key_material, 2, plaintext, tls::kContentTypeApplicationData, app_ciphertext, ec);
    const auto expected_unpadded_app_size = tls::kTlsRecordHeaderSize + plaintext.size() + 1U + tls::kAeadTagSize;
    ok = ok && require(!ec, "default application data encrypt failed");
    ok = ok && require(app_ciphertext.size() == expected_unpadded_app_size, "application data should not get default inner padding");
    return ok;
}

boost::asio::awaitable<bool> run_post_handshake_ticket_regression()
{
    auto executor = co_await boost::asio::this_coro::executor;
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor(executor);
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    bool ok = require(!ec, "ticket regression acceptor open failed");
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
    ok = ok && require(!ec, "ticket regression acceptor bind failed");
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    ok = ok && require(!ec, "ticket regression acceptor listen failed");
    if (!ok)
    {
        co_return false;
    }

    const auto endpoint = acceptor.local_endpoint(ec);
    if (!require(!ec, "ticket regression endpoint failed"))
    {
        co_return false;
    }

    boost::asio::ip::tcp::socket client_socket(executor);
    co_await client_socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "ticket regression client connect failed"))
    {
        co_return false;
    }

    auto server_socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "ticket regression server accept failed"))
    {
        co_return false;
    }

    auto client_connection = std::make_shared<relay::proxy_reality_connection>(std::move(client_socket), make_record_context(), cfg, 3);

    const tls::cipher_context record_ctx;
    const auto key_material = make_key_material(0x11, 0x22);
    std::vector<uint8_t> ciphertext;
    const auto ticket_plaintext = make_new_session_ticket_plaintext(64);
    if (!require(!ticket_plaintext.empty(), "ticket regression ticket build failed"))
    {
        co_return false;
    }
    tls::record_layer::encrypt_tls_record(record_ctx, EVP_aes_128_gcm(), key_material, 0, ticket_plaintext, tls::kContentTypeHandshake, ciphertext, ec);
    if (!require(!ec, "ticket regression encrypt ticket failed"))
    {
        co_return false;
    }

    const std::vector<uint8_t> payload{'h', 'e', 'l', 'l', 'o'};
    tls::record_layer::encrypt_tls_record(record_ctx, EVP_aes_128_gcm(), key_material, 1, payload, tls::kContentTypeApplicationData, ciphertext, ec);
    if (!require(!ec, "ticket regression encrypt appdata failed"))
    {
        co_return false;
    }

    co_await boost::asio::async_write(server_socket, boost::asio::buffer(ciphertext), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "ticket regression write ciphertext failed"))
    {
        co_return false;
    }

    std::vector<uint8_t> read_buffer(16);
    const auto bytes_read = co_await client_connection->read_some(read_buffer, cfg.timeout.read, ec);
    read_buffer.resize(bytes_read);
    ok = ok && require(!ec && read_buffer == payload, "post-handshake ticket should be ignored before appdata");

    boost::system::error_code close_ec;
    server_socket.close(close_ec);
    co_await client_connection->async_close(close_ec);
    ok = ok && require(!close_ec, "ticket regression close failed");
    co_return ok;
}

boost::asio::awaitable<bool> run_close_notify_regression()
{
    auto executor = co_await boost::asio::this_coro::executor;
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor(executor);
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    bool ok = require(!ec, "close_notify acceptor open failed");
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
    ok = ok && require(!ec, "close_notify acceptor bind failed");
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    ok = ok && require(!ec, "close_notify acceptor listen failed");
    if (!ok)
    {
        co_return false;
    }

    const auto endpoint = acceptor.local_endpoint(ec);
    if (!require(!ec, "close_notify endpoint failed"))
    {
        co_return false;
    }

    boost::asio::ip::tcp::socket client_socket(executor);
    co_await client_socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "close_notify client connect failed"))
    {
        co_return false;
    }

    auto server_socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "close_notify server accept failed"))
    {
        co_return false;
    }

    auto client_connection = std::make_shared<relay::proxy_reality_connection>(std::move(client_socket), make_record_context(), cfg, 4);

    const tls::cipher_context record_ctx;
    const auto key_material = make_key_material(0x11, 0x22);
    std::vector<uint8_t> ciphertext;
    const std::vector<uint8_t> close_notify{0x01, 0x00};
    tls::record_layer::encrypt_tls_record(
        record_ctx, EVP_aes_128_gcm(), key_material, 0, close_notify, tls::kContentTypeAlert, ciphertext, ec);
    if (!require(!ec, "close_notify encrypt failed"))
    {
        co_return false;
    }

    co_await boost::asio::async_write(server_socket, boost::asio::buffer(ciphertext), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "close_notify write ciphertext failed"))
    {
        co_return false;
    }

    std::vector<uint8_t> read_buffer(16);
    const auto bytes_read = co_await client_connection->read_some(read_buffer, cfg.timeout.read, ec);
    ok = ok && require(bytes_read == 0, "close_notify should not yield plaintext");
    ok = ok && require(ec == boost::asio::error::eof, "close_notify should surface eof");

    boost::system::error_code close_ec;
    server_socket.close(close_ec);
    co_await client_connection->async_close(close_ec);
    ok = ok && require(!close_ec, "close_notify close failed");
    co_return ok;
}

boost::asio::awaitable<bool> run_error_code_regression()
{
    auto executor = co_await boost::asio::this_coro::executor;
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    boost::system::error_code ec;
    boost::asio::ip::tcp::acceptor acceptor(executor);
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    bool ok = require(!ec, "acceptor open failed");
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
    ok = ok && require(!ec, "acceptor bind failed");
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    ok = ok && require(!ec, "acceptor listen failed");
    if (!ok)
    {
        co_return false;
    }

    const auto endpoint = acceptor.local_endpoint(ec);
    if (!require(!ec, "acceptor endpoint failed"))
    {
        co_return false;
    }

    boost::asio::ip::tcp::socket client_socket(executor);
    co_await client_socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "client connect failed"))
    {
        co_return false;
    }

    auto server_socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (!require(!ec, "server accept failed"))
    {
        co_return false;
    }

    auto client_connection = std::make_shared<relay::proxy_reality_connection>(std::move(client_socket), make_record_context(), cfg, 1);
    auto server_connection = std::make_shared<relay::proxy_reality_connection>(std::move(server_socket), make_record_context(), cfg, 2);

    ec = boost::asio::error::operation_aborted;
    co_await client_connection->write(std::span<const uint8_t>{}, ec);
    ok = ok && require(!ec, "empty write should clear stale error_code");

    const std::vector<uint8_t> packet{'o', 'k'};
    ec = boost::asio::error::operation_aborted;
    co_await client_connection->write_packet(packet, 1, ec);
    ok = ok && require(!ec, "write_packet(timeout) should clear stale error_code on success");

    ec = boost::asio::error::operation_aborted;
    const auto received_packet = co_await server_connection->read_packet(cfg.timeout.read, ec);
    ok = ok && require(!ec && received_packet == packet, "read_packet should clear stale error_code on success");

    const std::vector<uint8_t> plaintext{'d', 'a', 't', 'a'};
    ec = boost::asio::error::operation_aborted;
    co_await server_connection->write(std::span<const uint8_t>(plaintext.data(), plaintext.size()), 1, ec);
    ok = ok && require(!ec, "write(timeout) should clear stale error_code on success");

    std::vector<uint8_t> read_buffer(16);
    ec = boost::asio::error::operation_aborted;
    const auto bytes_read = co_await client_connection->read_some(read_buffer, cfg.timeout.read, ec);
    read_buffer.resize(bytes_read);
    ok = ok && require(!ec && read_buffer == plaintext, "read_some should clear stale error_code on success");

    ec = boost::asio::error::operation_aborted;
    co_await client_connection->write_packet(std::vector<uint8_t>(relay::proxy::kMaxPacketSize + 1U, 0x00), ec);
    ok = ok && require(ec == boost::asio::error::message_size, "oversized write_packet should report message_size");

    boost::system::error_code close_ec;
    co_await client_connection->async_close(close_ec);
    ok = ok && require(!close_ec, "async_close should close client without error");

    std::vector<uint8_t> close_buffer(16);
    boost::system::error_code read_close_ec;
    const auto close_bytes = co_await server_connection->read_some(close_buffer, 1, read_close_ec);
    ok = ok && require(close_bytes == 0, "peer close should not yield application bytes");
    ok = ok && require(read_close_ec == boost::asio::error::eof, "async_close should complete before peer read observes eof");

    co_await server_connection->async_close(close_ec);
    ok = ok && require(!close_ec, "async_close should close server without error");
    co_return ok;
}

}    // namespace

int main()
{
    if (!test_explicit_record_padding())
    {
        return 1;
    }

    boost::asio::io_context io_context;
    auto result = boost::asio::co_spawn(
        io_context,
        []() -> boost::asio::awaitable<bool>
        {
            const auto base_ok = co_await run_error_code_regression();
            if (!base_ok)
            {
                co_return false;
            }
            const auto ticket_ok = co_await run_post_handshake_ticket_regression();
            if (!ticket_ok)
            {
                co_return false;
            }
            co_return co_await run_close_notify_regression();
        }(),
        boost::asio::use_future);
    io_context.run();
    return result.get() ? 0 : 1;
}
