#include <string>
#include <thread>
#include <memory>
#include <chrono>
#include <system_error>

#include <gtest/gtest.h>
#include <gtest/gtest-death-test.h>

#include "context_pool.h"
#include "local_client.h"

using mux::io_context_pool;

namespace
{
void set_death_style() { ::testing::FLAGS_gtest_death_test_style = "threadsafe"; }

std::shared_ptr<mux::local_client> make_client(io_context_pool& pool, const std::string& verify_key_hex)
{
    const std::string server_pub_key(64, 'a');
    return std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 1080, server_pub_key, "example.com", "", verify_key_hex);
}
}    // namespace

TEST(LocalClientTest, MissingVerifyPublicKeyAborts)
{
    set_death_style();
    EXPECT_DEATH(
        {
            std::error_code ec;
            const io_context_pool pool(1, ec);
            ASSERT_FALSE(ec);
            const auto client = make_client(const_cast<io_context_pool&>(pool), "");
            client->start();
        },
        ".*");
}

TEST(LocalClientTest, BasicStartStop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10081, server_pub_key, "example.com", "", verify_key_hex);

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

    auto client1 = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10083, server_pub_key, "example.com", bad_hex_odd, "6262");

    auto client2 = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10084, server_pub_key, "example.com", "0102", bad_hex_chars);

    const std::string short_verify_key = "aabbcc";
    auto client3 = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10085, server_pub_key, "example.com", "", short_verify_key);
}

TEST(LocalClientTest, InvalidMaxConnectionsFallback)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string pub(64, 'a');
    const std::string verify(64, 'b');
    mux::config::limits_t limits;
    limits.max_connections = 0;
    const auto client = std::make_shared<mux::local_client>(
        pool, "127.0.0.1", "12345", 10089, pub, "example.com", "", verify, mux::config::timeout_t{}, mux::config::socks_t{}, limits);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
}

TEST(LocalClientTest, InvalidAuthConfigAborts)
{
    set_death_style();
    EXPECT_DEATH(
        {
            std::error_code ec;
            io_context_pool pool(1, ec);
            const std::string pub(64, 'a');
            const std::string verify_odd = "abc";
            const auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 1080, pub, "example.com", "", verify_odd);
            client->start();
        },
        ".*");
}

TEST(LocalClientTest, Getters)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10082, server_pub_key, "example.com", "trace-123", verify_key_hex);

    EXPECT_EQ(client->listen_port(), 10082);
}

TEST(LocalClientTest, StopWhenNotStarted)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10086, server_pub_key, "example.com", "", verify_key_hex);
    client->stop();
}

TEST(LocalClientTest, DoubleStop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10087, server_pub_key, "example.com", "", verify_key_hex);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    client->stop();
    client->stop();
}

TEST(LocalClientTest, HandshakeFailInvalidServerPubKey)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string bad_pub(31, 'a');    // Wrong size
    const std::string verify(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10090, bad_pub, "example.com", "", verify);
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}

TEST(LocalClientTest, ConnectFailureLoop)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "1", 10088, server_pub_key, "example.com", "", verify_key_hex);

    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    client->stop();
}
