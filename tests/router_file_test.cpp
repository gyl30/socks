#include <string>
#include <fstream>
#include <cstdint>
#include <unistd.h>
#include <filesystem>

#include <gtest/gtest.h>
#include <asio/ip/address.hpp>
#include <asio/io_context.hpp>

#include "router.h"
#include "test_util.h"

namespace
{

class RouterFileTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        const auto pid = static_cast<unsigned long>(::getpid());
        tmp_dir_ = std::filesystem::temp_directory_path() / ("router_file_test_" + std::to_string(pid));
        std::filesystem::create_directories(tmp_dir_);
        old_dir_ = std::filesystem::current_path();
        std::filesystem::current_path(tmp_dir_);

        touch("block_ip.txt");
        touch("direct_ip.txt");
        touch("proxy_domain.txt");
        touch("block_domain.txt");
        touch("direct_domain.txt");
    }

    void TearDown() override
    {
        std::filesystem::current_path(old_dir_);
        std::filesystem::remove_all(tmp_dir_);
    }

    static void touch(const std::string& name)
    {
        std::ofstream out(name);
        out.close();
    }

   private:
    std::filesystem::path tmp_dir_;
    std::filesystem::path old_dir_;
};

}    // namespace

TEST_F(RouterFileTest, EmptyDirectIpDefaultsProxy)
{
    mux::router router;
    ASSERT_TRUE(router.load());

    asio::io_context ctx;
    mux::connection_context conn_ctx;
    const auto addr = asio::ip::make_address("8.8.8.8");
    const auto result = mux::test::run_awaitable(
        ctx, router.decide_ip(conn_ctx, "8.8.8.8", addr, ctx.get_executor()));

    EXPECT_EQ(result, mux::route_type::proxy);
}
