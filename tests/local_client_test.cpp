#include <gtest/gtest.h>
#include <memory>
#include "local_client.h"
#include "context_pool.h"

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
            io_context_pool pool(1, ec);
            ASSERT_FALSE(ec);
            auto client = make_client(pool, "");
            client->start();
        },
        ".*");
}

TEST(LocalClientTest, InvalidVerifyPublicKeyLengthAborts)
{
    set_death_style();
    EXPECT_DEATH(
        {
            std::error_code ec;
            io_context_pool pool(1, ec);
            ASSERT_FALSE(ec);
            auto client = make_client(pool, "aa");
            client->start();
        },
        ".*");
}
