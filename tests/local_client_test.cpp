#include <memory>
#include <string>
#include <system_error>
#include <chrono>
#include <thread>

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

TEST(LocalClientTest, Getters)
{
    std::error_code ec;
    io_context_pool pool(1, ec);
    const std::string server_pub_key(64, 'a');
    const std::string verify_key_hex(64, 'b');

    auto client = std::make_shared<mux::local_client>(pool, "127.0.0.1", "12345", 10082, server_pub_key, "example.com", "trace-123", verify_key_hex);

    EXPECT_EQ(client->listen_port(), 10082);
}
