// NOLINTBEGIN(bugprone-narrowing-conversions)
// NOLINTBEGIN(bugprone-unused-return-value, misc-include-cleaner)
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>
#include <optional>

#include <gtest/gtest.h>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>

#include "mux_codec.h"
#include "protocol.h"
#include "log.h"
#include "crypto_util.h"
#include "context_pool.h"
#include "socks_client.h"
#include "remote_server.h"
#include "reality_messages.h"

using mux::io_context_pool;
using mux::socks_client;
using mux::remote_server;

class UdpIntegrationTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        std::uint8_t pub[32];
        std::uint8_t priv[32];
        ASSERT_TRUE(reality::crypto_util::generate_x25519_keypair(pub, priv));
        server_priv_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(priv, priv + 32));
        client_pub_key_ = reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(pub, pub + 32));
        short_id_ = "0102030405060708";
    }

    [[nodiscard]] const std::string& server_priv_key() const { return server_priv_key_; }
    [[nodiscard]] const std::string& client_pub_key() const { return client_pub_key_; }
    [[nodiscard]] const std::string& short_id() const { return short_id_; }

   private:
    std::string server_priv_key_;
    std::string client_pub_key_;
    std::string short_id_;
};

static boost::asio::awaitable<void> run_udp_echo_server(std::shared_ptr<boost::asio::ip::udp::socket> socket,
                                                 const std::uint16_t port,
                                                 const std::shared_ptr<std::atomic<bool>>& stopped)
{
    const auto mark_stopped = [&stopped]()
    {
        if (stopped != nullptr)
        {
            stopped->store(true, std::memory_order_release);
        }
    };

    boost::system::error_code ec;
    socket->open(boost::asio::ip::udp::v4(), ec);
    if (ec)
    {
        LOG_ERROR("echo server open failed: {}", ec.message());
        mark_stopped();
        co_return;
    }
    socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port), ec);
    if (ec)
    {
        LOG_ERROR("echo server bind failed on port {}: {}", port, ec.message());
        mark_stopped();
        co_return;
    }

    std::vector<char> data(65535);
    boost::asio::ip::udp::endpoint sender_ep;

    for (;;)
    {
        auto [receive_ec, n] = co_await socket->async_receive_from(boost::asio::buffer(data), sender_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (receive_ec)
        {
            if (receive_ec != boost::asio::error::operation_aborted)
            {
                LOG_ERROR("echo server receive error: {}", receive_ec.message());
            }
            break;
        }

        auto [send_ec, sn] = co_await socket->async_send_to(boost::asio::buffer(data, n), sender_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (send_ec)
        {
            LOG_ERROR("echo server send error: {}", send_ec.message());
            break;
        }
    }
    mark_stopped();
}

static bool wait_for_flag(const std::shared_ptr<std::atomic<bool>>& done, const std::chrono::milliseconds timeout)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (done != nullptr && !done->load(std::memory_order_acquire))
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return true;
}

static bool wait_for_tcp_port(const std::uint16_t port, const int attempts = 60)
{
    for (int i = 0; i < attempts; ++i)
    {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::system::error_code ec;
        socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port), ec);
        if (!ec)
        {
            boost::system::error_code ignore;
            socket.close(ignore);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

static std::uint16_t wait_for_socks_listen_port(const std::shared_ptr<socks_client>& client, const int attempts = 80)
{
    for (int i = 0; i < attempts; ++i)
    {
        const auto port = client->listen_port();
        if (port != 0 && wait_for_tcp_port(port, 1))
        {
            return port;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return 0;
}

static void close_tcp_socket_quietly(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
{
    if (socket == nullptr)
    {
        return;
    }
    boost::system::error_code ignore;
    socket->close(ignore);
}

static boost::asio::awaitable<void> wait_socks_retry(boost::asio::steady_timer& retry_timer)
{
    retry_timer.expires_after(std::chrono::milliseconds(50));
    auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)wait_ec;
}

static boost::asio::awaitable<bool> send_socks_method_no_auth(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
{
    std::uint8_t method_req[] = {0x05, 0x01, 0x00};
    auto [write_ec, write_n] = co_await boost::asio::async_write(*socket, boost::asio::buffer(method_req), boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)write_n;
    if (write_ec)
    {
        co_return false;
    }

    std::uint8_t method_res[2];
    auto [read_ec, read_n] = co_await boost::asio::async_read(*socket, boost::asio::buffer(method_res), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (read_ec || read_n != sizeof(method_res))
    {
        co_return false;
    }
    co_return method_res[0] == 0x05 && method_res[1] == 0x00;
}

static boost::asio::awaitable<std::optional<std::uint16_t>> request_udp_associate_port(
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket)
{
    std::uint8_t associate_req[] = {0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    auto [assoc_write_ec, assoc_write_n] =
        co_await boost::asio::async_write(*socket, boost::asio::buffer(associate_req), boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)assoc_write_n;
    if (assoc_write_ec)
    {
        co_return std::nullopt;
    }

    std::uint8_t associate_res[10];
    auto [assoc_read_ec, assoc_read_n] =
        co_await boost::asio::async_read(*socket, boost::asio::buffer(associate_res), boost::asio::as_tuple(boost::asio::use_awaitable));
    if (assoc_read_ec || assoc_read_n != sizeof(associate_res) || associate_res[1] != 0x00)
    {
        co_return std::nullopt;
    }
    co_return static_cast<std::uint16_t>((associate_res[8] << 8) | associate_res[9]);
}

struct udp_associate_ready
{
    std::shared_ptr<boost::asio::ip::tcp::socket> tcp_socket;
    std::uint16_t proxy_bind_port = 0;
};

static boost::asio::awaitable<std::optional<udp_associate_ready>> establish_udp_associate_channel(const std::uint16_t local_socks_port,
                                                                                            const int max_attempts = 60)
{
    auto exec = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer retry_timer(exec);

    for (int attempt = 0; attempt < max_attempts; ++attempt)
    {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(exec);
        auto [connect_ec] =
            co_await socket->async_connect({boost::asio::ip::make_address("127.0.0.1"), local_socks_port}, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (connect_ec)
        {
            co_await wait_socks_retry(retry_timer);
            continue;
        }

        const bool method_ok = co_await send_socks_method_no_auth(socket);
        if (!method_ok)
        {
            close_tcp_socket_quietly(socket);
            co_await wait_socks_retry(retry_timer);
            continue;
        }

        const auto proxy_port = co_await request_udp_associate_port(socket);
        if (!proxy_port.has_value())
        {
            close_tcp_socket_quietly(socket);
            co_await wait_socks_retry(retry_timer);
            continue;
        }

        co_return udp_associate_ready{.tcp_socket = socket, .proxy_bind_port = *proxy_port};
    }
    co_return std::nullopt;
}

static std::vector<std::uint8_t> build_udp_packet(const std::uint16_t echo_server_port, const std::string& payload_data)
{
    std::vector<std::uint8_t> packet;
    packet.reserve(10 + payload_data.size());
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);
    packet.push_back(127);
    packet.push_back(0);
    packet.push_back(0);
    packet.push_back(1);
    packet.push_back(static_cast<std::uint8_t>((echo_server_port >> 8) & 0xFF));
    packet.push_back(static_cast<std::uint8_t>(echo_server_port & 0xFF));
    packet.insert(packet.end(), payload_data.begin(), payload_data.end());
    return packet;
}

static boost::asio::awaitable<bool> send_udp_echo_and_validate(const std::shared_ptr<boost::asio::ip::udp::socket>& udp_socket,
                                                        const std::uint16_t proxy_bind_port,
                                                        const std::uint16_t echo_server_port,
                                                        const std::string& payload_data)
{
    const auto packet = build_udp_packet(echo_server_port, payload_data);
    const boost::asio::ip::udp::endpoint proxy_ep(boost::asio::ip::make_address("127.0.0.1"), proxy_bind_port);
    auto [send_ec, send_n] = co_await udp_socket->async_send_to(boost::asio::buffer(packet), proxy_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
    (void)send_n;
    if (send_ec)
    {
        co_return false;
    }

    std::vector<std::uint8_t> recv_buf(4096);
    boost::asio::ip::udp::endpoint sender_ep;
    auto [recv_ec, recv_n] = co_await udp_socket->async_receive_from(boost::asio::buffer(recv_buf), sender_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (recv_ec || recv_n <= 10)
    {
        co_return false;
    }

    const std::string recv_payload(recv_buf.begin() + 10, recv_buf.begin() + recv_n);
    co_return recv_payload == payload_data;
}

static boost::asio::awaitable<void> run_udp_associate_echo_flow(const std::uint16_t local_socks_port,
                                                         const std::uint16_t echo_server_port,
                                                         std::atomic<bool>& test_passed,
                                                         std::atomic<bool>& test_failed,
                                                         std::shared_ptr<boost::asio::ip::tcp::socket>& client_tcp,
                                                         std::shared_ptr<boost::asio::ip::udp::socket>& client_udp)
{
    const auto ready = co_await establish_udp_associate_channel(local_socks_port);
    if (!ready.has_value())
    {
        test_failed = true;
        co_return;
    }

    client_tcp = ready->tcp_socket;
    auto exec = co_await boost::asio::this_coro::executor;
    client_udp = std::make_shared<boost::asio::ip::udp::socket>(exec);

    boost::system::error_code udp_ec;
    client_udp->open(boost::asio::ip::udp::v4(), udp_ec);
    if (udp_ec)
    {
        test_failed = true;
        co_return;
    }

    const std::string payload_data = "Hello UDP Multi-Stage Handshake";
    const bool echo_ok = co_await send_udp_echo_and_validate(client_udp, ready->proxy_bind_port, echo_server_port, payload_data);
    test_passed = echo_ok;
    test_failed = !echo_ok;
}

TEST_F(UdpIntegrationTest, UdpAssociateAndEcho)
{
    boost::system::error_code ec;
    io_context_pool pool(4);
    ASSERT_FALSE(ec);

    std::uint16_t echo_server_port = 0;
    const std::string sni = "www.google.com";

    mux::config cfg;
    cfg.inbound.host = "127.0.0.1";
    cfg.inbound.port = 0;
    cfg.reality.private_key = server_priv_key();
    cfg.reality.short_id = short_id();
    cfg.timeout.read = 10;
    cfg.timeout.write = 10;

    auto server = std::make_shared<remote_server>(pool, cfg);
    const auto dummy_cert = reality::construct_certificate({0x01, 0x02, 0x03});
    reality::server_fingerprint const dummy_fp;
    server->set_certificate(sni, dummy_cert, dummy_fp);
    server->start();
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout.read = 10;
    client_cfg.timeout.write = 10;
    auto client = std::make_shared<socks_client>(pool, client_cfg);
    client->start();

    auto echo_socket = std::make_shared<boost::asio::ip::udp::socket>(pool.get_io_context());

    echo_socket->open(boost::asio::ip::udp::v4(), ec);
    echo_socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
    echo_server_port = echo_socket->local_endpoint().port();
    echo_socket->close();

    auto echo_stopped = std::make_shared<std::atomic<bool>>(false);
    boost::asio::co_spawn(echo_socket->get_executor(), run_udp_echo_server(echo_socket, echo_server_port, echo_stopped), boost::asio::detached);

    std::thread pool_thread([&pool]() { pool.run(); });
    const auto local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    std::atomic<bool> test_passed{false};
    std::atomic<bool> test_failed{false};
    std::shared_ptr<boost::asio::ip::tcp::socket> client_tcp;
    std::shared_ptr<boost::asio::ip::udp::socket> client_udp;

    boost::asio::cancellation_signal cancel_sig;
    boost::asio::co_spawn(
        pool.get_io_context(),
        run_udp_associate_echo_flow(local_socks_port, echo_server_port, test_passed, test_failed, client_tcp, client_udp),
        boost::asio::bind_cancellation_slot(cancel_sig.slot(), boost::asio::detached));

    for (int i = 0; i < 200; ++i)
    {
        if (test_passed || test_failed)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    client->stop();
    server->stop();
    cancel_sig.emit(boost::asio::cancellation_type::all);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    boost::system::error_code ignore;
    if (client_tcp)
    {
        client_tcp->close(ignore);
    }
    if (client_udp)
    {
        client_udp->close(ignore);
    }
    echo_socket->close(ignore);
    EXPECT_TRUE(wait_for_flag(echo_stopped, std::chrono::seconds(2)));

    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }

    EXPECT_TRUE(test_passed.load());
    EXPECT_FALSE(test_failed.load());
}

TEST_F(UdpIntegrationTest, UdpAssociateIgnoresFragmentedPacketAndKeepsSessionAlive)
{
    boost::system::error_code ec;
    io_context_pool pool(4);
    ASSERT_FALSE(ec);

    const std::string sni = "www.google.com";

    mux::config server_cfg;
    server_cfg.inbound.host = "127.0.0.1";
    server_cfg.inbound.port = 0;
    server_cfg.reality.private_key = server_priv_key();
    server_cfg.reality.short_id = short_id();
    server_cfg.timeout.read = 10;
    server_cfg.timeout.write = 10;
    server_cfg.timeout.idle = 10;
    auto server = std::make_shared<remote_server>(pool, server_cfg);
    const auto dummy_cert = reality::construct_certificate({0x01, 0x02, 0x03});
    reality::server_fingerprint const dummy_fp;
    server->set_certificate(sni, dummy_cert, dummy_fp);
    server->start();
    const auto server_port = server->listen_port();
    ASSERT_NE(server_port, 0);

    mux::config client_cfg;
    client_cfg.outbound.host = "127.0.0.1";
    client_cfg.outbound.port = server_port;
    client_cfg.socks.port = 0;
    client_cfg.reality.public_key = client_pub_key();
    client_cfg.reality.sni = sni;
    client_cfg.reality.short_id = short_id();
    client_cfg.reality.strict_cert_verify = false;
    client_cfg.timeout.read = 10;
    client_cfg.timeout.write = 10;
    client_cfg.timeout.idle = 10;
    auto client = std::make_shared<socks_client>(pool, client_cfg);
    client->start();

    auto echo_socket = std::make_shared<boost::asio::ip::udp::socket>(pool.get_io_context());
    echo_socket->open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    echo_socket->bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
    ASSERT_FALSE(ec);
    const auto echo_server_port = echo_socket->local_endpoint().port();
    echo_socket->close(ec);
    ASSERT_FALSE(ec);
    auto echo_stopped = std::make_shared<std::atomic<bool>>(false);
    boost::asio::co_spawn(echo_socket->get_executor(), run_udp_echo_server(echo_socket, echo_server_port, echo_stopped), boost::asio::detached);

    std::thread pool_thread([&pool]() { pool.run(); });
    const auto local_socks_port = wait_for_socks_listen_port(client);
    ASSERT_NE(local_socks_port, 0);

    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket tcp_socket(io_context);
    tcp_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), local_socks_port), ec);
    ASSERT_FALSE(ec);

    std::uint8_t method_req[] = {socks::kVer, 0x01, socks::kMethodNoAuth};
    boost::asio::write(tcp_socket, boost::asio::buffer(method_req), ec);
    ASSERT_FALSE(ec);
    std::uint8_t method_res[2] = {0};
    boost::asio::read(tcp_socket, boost::asio::buffer(method_res), ec);
    ASSERT_FALSE(ec);
    ASSERT_EQ(method_res[0], socks::kVer);
    ASSERT_EQ(method_res[1], socks::kMethodNoAuth);

    std::uint8_t associate_req[] = {socks::kVer, socks::kCmdUdpAssociate, 0x00, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    boost::asio::write(tcp_socket, boost::asio::buffer(associate_req), ec);
    ASSERT_FALSE(ec);

    std::uint8_t associate_res[10] = {0};
    boost::asio::read(tcp_socket, boost::asio::buffer(associate_res), ec);
    ASSERT_FALSE(ec);
    ASSERT_EQ(associate_res[0], socks::kVer);
    ASSERT_EQ(associate_res[1], socks::kRepSuccess);
    const auto proxy_bind_port = static_cast<std::uint16_t>((associate_res[8] << 8) | associate_res[9]);
    ASSERT_NE(proxy_bind_port, 0);

    boost::asio::ip::udp::socket udp_socket(io_context);
    udp_socket.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    udp_socket.non_blocking(true, ec);
    ASSERT_FALSE(ec);

    const boost::asio::ip::udp::endpoint proxy_ep(boost::asio::ip::make_address("127.0.0.1"), proxy_bind_port);
    const std::string payload = "udp-fragment-should-drop";
    std::vector<std::uint8_t> frag_packet = {0x00,
                                             0x00,
                                             0x01,
                                             socks::kAtypIpv4,
                                             127,
                                             0,
                                             0,
                                             1,
                                             static_cast<std::uint8_t>((echo_server_port >> 8) & 0xFF),
                                             static_cast<std::uint8_t>(echo_server_port & 0xFF)};
    frag_packet.insert(frag_packet.end(), payload.begin(), payload.end());
    udp_socket.send_to(boost::asio::buffer(frag_packet), proxy_ep, 0, ec);
    ASSERT_FALSE(ec);

    auto poll_udp = [&](std::vector<std::uint8_t>& out, const std::chrono::milliseconds timeout) -> bool
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        for (;;)
        {
            std::vector<std::uint8_t> recv_buf(4096);
            boost::asio::ip::udp::endpoint sender;
            boost::system::error_code recv_ec;
            const auto n = udp_socket.receive_from(boost::asio::buffer(recv_buf), sender, 0, recv_ec);
            if (!recv_ec)
            {
                recv_buf.resize(n);
                out = std::move(recv_buf);
                return true;
            }
            if (recv_ec != boost::asio::error::would_block && recv_ec != boost::asio::error::try_again)
            {
                ADD_FAILURE() << "unexpected udp recv error: " << recv_ec.message();
                return false;
            }
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    };

    std::vector<std::uint8_t> recv_packet;
    const bool got_fragment_reply = poll_udp(recv_packet, std::chrono::milliseconds(400));
    EXPECT_FALSE(got_fragment_reply);

    const std::string good_payload = "udp-valid-after-frag";
    std::vector<std::uint8_t> good_packet = {0x00,
                                             0x00,
                                             0x00,
                                             socks::kAtypIpv4,
                                             127,
                                             0,
                                             0,
                                             1,
                                             static_cast<std::uint8_t>((echo_server_port >> 8) & 0xFF),
                                             static_cast<std::uint8_t>(echo_server_port & 0xFF)};
    good_packet.insert(good_packet.end(), good_payload.begin(), good_payload.end());
    udp_socket.send_to(boost::asio::buffer(good_packet), proxy_ep, 0, ec);
    ASSERT_FALSE(ec);

    recv_packet.clear();
    ASSERT_TRUE(poll_udp(recv_packet, std::chrono::seconds(3)));
    ASSERT_GT(recv_packet.size(), 10U);
    EXPECT_EQ(std::string(recv_packet.begin() + 10, recv_packet.end()), good_payload);

    client->stop();
    server->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    boost::system::error_code ignore;
    tcp_socket.close(ignore);
    udp_socket.close(ignore);
    echo_socket->close(ignore);
    EXPECT_TRUE(wait_for_flag(echo_stopped, std::chrono::seconds(2)));

    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}
// NOLINTEND(bugprone-unused-return-value, misc-include-cleaner)
// NOLINTEND(bugprone-narrowing-conversions)
