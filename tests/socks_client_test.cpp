#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <system_error>
#include <future>

#include <gtest/gtest.h>
#include <asio/ip/tcp.hpp>

#include "context_pool.h"
#define private public
#include "socks_client.h"
#undef private

using mux::io_context_pool;

namespace
{

bool wait_for_listen_port(const std::shared_ptr<mux::socks_client>& client)
{
    for (int i = 0; i < 40; ++i)
    {
        if (client->listen_port() != 0)
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    return false;
}

template <typename Func>
auto run_on_io_context(asio::io_context& io_context, Func&& fn) -> decltype(fn())
{
    using result_type = decltype(fn());
    std::promise<result_type> promise;
    auto future = promise.get_future();
    asio::post(io_context,
               [func = std::forward<Func>(fn), promise = std::move(promise)]() mutable
               {
                   promise.set_value(func());
               });
    return future.get();
}

std::size_t session_count(asio::io_context& io_context, const std::shared_ptr<mux::socks_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->sessions_.size(); });
}

}    // namespace

TEST(LocalClientTest, BasicStartStop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10081;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    client->start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    client->stop();
}

TEST(LocalClientTest, InvalidHexConfig)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string bad_hex_odd = "ABC";
    const std::string bad_hex_chars = "GG";
    const std::string server_pub_key(64, 'a');

    mux::config cfg1;
    cfg1.outbound.host = "127.0.0.1";
    cfg1.outbound.port = 12345;
    cfg1.socks.port = 10083;
    cfg1.reality.public_key = server_pub_key;
    cfg1.reality.sni = "example.com";
    cfg1.reality.short_id = bad_hex_odd;
    auto client1 = std::make_shared<mux::socks_client>(pool, cfg1);

    mux::config cfg2;
    cfg2.outbound.host = "127.0.0.1";
    cfg2.outbound.port = 12345;
    cfg2.socks.port = 10084;
    cfg2.reality.public_key = server_pub_key;
    cfg2.reality.sni = "example.com";
    cfg2.reality.short_id = bad_hex_chars;
    auto client2 = std::make_shared<mux::socks_client>(pool, cfg2);

    mux::config cfg3;
    cfg3.outbound.host = "127.0.0.1";
    cfg3.outbound.port = 12345;
    cfg3.socks.port = 10085;
    cfg3.reality.public_key = server_pub_key;
    cfg3.reality.sni = "example.com";
    cfg3.reality.short_id = "0102";
    auto client3 = std::make_shared<mux::socks_client>(pool, cfg3);
}

TEST(LocalClientTest, InvalidMaxConnectionsFallback)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10089;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    cfg.limits.max_connections = 0;
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
}

TEST(LocalClientTest, InvalidAuthConfigAborts)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string bad_hex_odd = "abc";
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 1080;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";
    cfg.reality.short_id = bad_hex_odd;
    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    client->stop();
}

TEST(LocalClientTest, Getters)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10082;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    EXPECT_EQ(client->listen_port(), 10082);
}

TEST(LocalClientTest, StopWhenNotStarted)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10086;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->stop();
}

TEST(LocalClientTest, DoubleStop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10087;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
    client->stop();
}

TEST(LocalClientTest, HandshakeFailInvalidServerPubKey)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string bad_pub(31, 'a');
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 10090;
    cfg.reality.public_key = bad_pub;
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}

TEST(LocalClientTest, ConnectFailureLoop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.port = 10088;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    auto client = std::make_shared<mux::socks_client>(pool, cfg);

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}

TEST(LocalClientTest, DisabledSocksStopsImmediately)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 12345;
    cfg.socks.port = 0;
    cfg.socks.enabled = false;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    client->start();
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(LocalClientTest, InvalidListenHostAbortsAcceptLoop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "not-an-ip";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

TEST(LocalClientTest, ListenPortConflictTriggersSetupFailure)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    asio::io_context blocker_ctx;
    asio::ip::tcp::acceptor blocker(blocker_ctx, {asio::ip::make_address("127.0.0.1"), 0});
    const auto blocked_port = blocker.local_endpoint().port();

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = blocked_port;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}

TEST(LocalClientTest, NoTunnelSelectionAndSessionPrunePath)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.outbound.host = "127.0.0.1";
    cfg.outbound.port = 1;
    cfg.socks.host = "127.0.0.1";
    cfg.socks.port = 0;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.reality.sni = "example.com";

    const auto client = std::make_shared<mux::socks_client>(pool, cfg);
    std::thread pool_thread([&pool]() { pool.run(); });

    client->start();
    ASSERT_TRUE(wait_for_listen_port(client));

    asio::io_context connect_ctx;
    asio::ip::tcp::socket first(connect_ctx);
    asio::ip::tcp::socket second(connect_ctx);
    const asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), client->listen_port());
    first.connect(ep, ec);
    ASSERT_FALSE(ec);
    second.connect(ep, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(2800));
    EXPECT_GT(session_count(pool.get_io_context(), client), 0U);

    client->stop();
    pool.stop();
    if (pool_thread.joinable())
    {
        pool_thread.join();
    }
}
