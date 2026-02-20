// NOLINTBEGIN(google-runtime-int)
// NOLINTBEGIN(misc-include-cleaner)
#include <string>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <filesystem>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>

#include "router.h"
#include "test_util.h"

namespace
{

class env_var_guard
{
   public:
    env_var_guard(const char* name, const std::string& value) : name_(name)
    {
        if (const char* old = std::getenv(name_); old != nullptr)
        {
            had_old_value_ = true;
            old_value_ = old;
        }
        ::setenv(name_, value.c_str(), 1);
    }

    ~env_var_guard()
    {
        if (had_old_value_)
        {
            ::setenv(name_, old_value_.c_str(), 1);
            return;
        }
        ::unsetenv(name_);
    }

   private:
    const char* name_;
    bool had_old_value_ = false;
    std::string old_value_;
};

class router_file_test_fixture : public ::testing::Test
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

    static void write_file(const std::filesystem::path& path, const std::string& content)
    {
        std::ofstream out(path);
        out << content;
        out.close();
    }

   private:
    std::filesystem::path tmp_dir_;
    std::filesystem::path old_dir_;
};

}    // namespace

TEST_F(router_file_test_fixture, EmptyDirectIpDefaultsProxy)
{
    mux::router router;
    ASSERT_TRUE(router.load());

    boost::asio::io_context ctx;
    mux::connection_context const conn_ctx;
    const auto addr = boost::asio::ip::make_address("8.8.8.8");
    const auto result = mux::test::run_awaitable(ctx, router.decide_ip(conn_ctx, "8.8.8.8", addr));

    EXPECT_EQ(result, mux::route_type::kProxy);
}

TEST_F(router_file_test_fixture, MissingRuleFileCausesLoadFailure)
{
    std::filesystem::remove("direct_ip.txt");

    mux::router router;
    EXPECT_FALSE(router.load());
}

TEST_F(router_file_test_fixture, MissingDomainRuleFileCausesLoadFailure)
{
    std::filesystem::remove("block_domain.txt");

    mux::router router;
    EXPECT_FALSE(router.load());
}

TEST_F(router_file_test_fixture, UnreadableIpRuleFileCausesLoadFailure)
{
    boost::system::error_code ec;
    std::filesystem::permissions("direct_ip.txt", std::filesystem::perms::none, std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec) << ec.message();

    mux::router router;
    EXPECT_FALSE(router.load());

    std::filesystem::permissions(
        "direct_ip.txt", std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, ec);
    EXPECT_FALSE(ec) << ec.message();
}

TEST_F(router_file_test_fixture, UnreadableDomainRuleFileCausesLoadFailure)
{
    boost::system::error_code ec;
    std::filesystem::permissions("block_domain.txt", std::filesystem::perms::none, std::filesystem::perm_options::replace, ec);
    ASSERT_FALSE(ec) << ec.message();

    mux::router router;
    EXPECT_FALSE(router.load());

    std::filesystem::permissions(
        "block_domain.txt", std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, ec);
    EXPECT_FALSE(ec) << ec.message();
}

TEST_F(router_file_test_fixture, LoadRuleFilesFromSocksConfigDir)
{
    const auto cfg_dir = std::filesystem::path("env_config");
    std::filesystem::create_directories(cfg_dir);

    write_file(cfg_dir / "block_ip.txt", "");
    write_file(cfg_dir / "direct_ip.txt", "8.8.8.0/24\n");
    write_file(cfg_dir / "proxy_domain.txt", "");
    write_file(cfg_dir / "block_domain.txt", "");
    write_file(cfg_dir / "direct_domain.txt", "");

    std::filesystem::remove("block_ip.txt");
    std::filesystem::remove("direct_ip.txt");
    std::filesystem::remove("proxy_domain.txt");
    std::filesystem::remove("block_domain.txt");
    std::filesystem::remove("direct_domain.txt");

    env_var_guard const guard("SOCKS_CONFIG_DIR", cfg_dir.string());

    mux::router router;
    ASSERT_TRUE(router.load());

    boost::asio::io_context ctx;
    mux::connection_context const conn_ctx;
    const auto addr = boost::asio::ip::make_address("8.8.8.8");
    const auto result = mux::test::run_awaitable(ctx, router.decide_ip(conn_ctx, "8.8.8.8", addr));
    EXPECT_EQ(result, mux::route_type::kDirect);
}
// NOLINTEND(misc-include-cleaner)
// NOLINTEND(google-runtime-int)
