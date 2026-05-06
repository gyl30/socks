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
    co_await client_connection->write_packet(packet, ec);
    ok = ok && require(!ec, "write_packet should clear stale error_code on success");

    ec = boost::asio::error::operation_aborted;
    const auto received_packet = co_await server_connection->read_packet(cfg.timeout.read, ec);
    ok = ok && require(!ec && received_packet == packet, "read_packet should clear stale error_code on success");

    const std::vector<uint8_t> plaintext{'d', 'a', 't', 'a'};
    ec = boost::asio::error::operation_aborted;
    co_await server_connection->write(std::span<const uint8_t>(plaintext.data(), plaintext.size()), ec);
    ok = ok && require(!ec, "write should clear stale error_code on success");

    std::vector<uint8_t> read_buffer(16);
    ec = boost::asio::error::operation_aborted;
    const auto bytes_read = co_await client_connection->read_some(read_buffer, cfg.timeout.read, ec);
    read_buffer.resize(bytes_read);
    ok = ok && require(!ec && read_buffer == plaintext, "read_some should clear stale error_code on success");

    ec = boost::asio::error::operation_aborted;
    co_await client_connection->write_packet(std::vector<uint8_t>(relay::proxy::kMaxPacketSize + 1U, 0x00), ec);
    ok = ok && require(ec == boost::asio::error::message_size, "oversized write_packet should report message_size");

    boost::system::error_code close_ec;
    client_connection->close(close_ec);
    server_connection->close(close_ec);
    co_return ok;
}

}    // namespace

int main()
{
    boost::asio::io_context io_context;
    auto result = boost::asio::co_spawn(io_context, run_error_code_regression(), boost::asio::use_future);
    io_context.run();
    return result.get() ? 0 : 1;
}
