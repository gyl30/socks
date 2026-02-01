#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include "config.h"

class ConfigTest : public ::testing::Test
{
   protected:
    void SetUp() override { tmp_file = "test_config.json"; }

    void TearDown() override { std::remove(tmp_file.c_str()); }

    void write_file(const std::string& content)
    {
        std::ofstream out(tmp_file);
        out << content;
        out.close();
    }

    std::string tmp_file;
};

TEST_F(ConfigTest, DefaultConfigValid)
{
    auto json = dump_default_config();
    ASSERT_FALSE(json.empty());
    // 检查预期键的基本检查
    EXPECT_NE(json.find("\"mode\""), std::string::npos);
    EXPECT_NE(json.find("\"inbound\""), std::string::npos);
}

TEST_F(ConfigTest, ParseValues)
{
    std::string content = R"({
        "mode": "client",
        "inbound": {
            "host": "127.0.0.1",
            "port": 1080
        },
        "socks": {
            "auth": true,
            "username": "user",
            "password": "pass"
        },
        "reality": {
            "sni": "google.com"
        }
    })";
    write_file(content);

    auto cfg_opt = parse_config(tmp_file);
    ASSERT_TRUE(cfg_opt.has_value());
    const auto& cfg = cfg_opt.value();

    EXPECT_EQ(cfg.mode, "client");
    EXPECT_EQ(cfg.inbound.host, "127.0.0.1");
    EXPECT_EQ(cfg.inbound.port, 1080);
    EXPECT_TRUE(cfg.socks.auth);
    EXPECT_EQ(cfg.socks.username, "user");
    EXPECT_EQ(cfg.socks.password, "pass");
    EXPECT_EQ(cfg.reality.sni, "google.com");
}

TEST_F(ConfigTest, MissingFile)
{
    auto cfg = parse_config("non_existent_file.json");
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(ConfigTest, InvalidJson)
{
    write_file("{ invalid_json }");
    auto cfg = parse_config(tmp_file);
    EXPECT_FALSE(cfg.has_value());
}
