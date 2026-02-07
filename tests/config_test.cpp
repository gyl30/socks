#include <string>
#include <cstdio>
#include <fstream>

#include <gtest/gtest.h>

#include "config.h"

class ConfigTest : public ::testing::Test
{
   protected:
    void SetUp() override { tmp_file_ = "test_config.json"; }

    void TearDown() override { std::remove(tmp_file_.c_str()); }

    void write_config_file(const std::string& content)
    {
        std::ofstream out(tmp_file_);
        out << content;
        out.close();
    }

    const std::string& tmp_file() const { return tmp_file_; }

   private:
    std::string tmp_file_;
};

TEST_F(ConfigTest, DefaultConfigValid)
{
    const auto json = mux::dump_default_config();
    ASSERT_FALSE(json.empty());

    EXPECT_NE(json.find("\"mode\""), std::string::npos);
    EXPECT_NE(json.find("\"inbound\""), std::string::npos);
}

TEST_F(ConfigTest, ParseValues)
{
    const std::string content = R"({
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
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (cfg_opt.has_value())
    {
        const auto& cfg = *cfg_opt;

        EXPECT_EQ(cfg.mode, "client");
        EXPECT_EQ(cfg.inbound.host, "127.0.0.1");
        EXPECT_EQ(cfg.inbound.port, 1080);
        EXPECT_TRUE(cfg.socks.auth);
        EXPECT_EQ(cfg.socks.username, "user");
        EXPECT_EQ(cfg.socks.password, "pass");
        EXPECT_EQ(cfg.reality.sni, "google.com");
    }
}

TEST_F(ConfigTest, MissingFile)
{
    const auto cfg = mux::parse_config("non_existent_file.json");
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(ConfigTest, InvalidJson)
{
    write_config_file("{ invalid_json }");
    const auto cfg = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg.has_value());
}
