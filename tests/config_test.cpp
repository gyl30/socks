#include <cstdio>
#include <string>
#include <fstream>
#include <unistd.h>

#include <gtest/gtest.h>

#include "config.h"

class config_test : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        tmp_file_ = std::string("test_config_") + info->test_suite_name() + "_" + info->name() + "_" + std::to_string(::getpid()) + ".json";
    }

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

TEST_F(config_test, DefaultConfigValid)
{
    const auto json = mux::dump_default_config();
    ASSERT_FALSE(json.empty());

    EXPECT_NE(json.find("\"mode\""), std::string::npos);
    EXPECT_NE(json.find("\"inbound\""), std::string::npos);
}

TEST_F(config_test, ParseValues)
{
    const std::string content = R"({
        "mode": "client",
        "inbound": {
            "host": "127.0.0.1",
            "port": 1080
        },
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": "pass"
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "::1",
            "tcp_port": 18080,
            "udp_port": 18081,
            "mark": 17
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
        EXPECT_TRUE(cfg.tproxy.enabled);
        EXPECT_EQ(cfg.tproxy.listen_host, "::1");
        EXPECT_EQ(cfg.tproxy.tcp_port, 18080);
        EXPECT_EQ(cfg.tproxy.udp_port, 18081);
        EXPECT_EQ(cfg.tproxy.mark, 17);
        EXPECT_EQ(cfg.reality.sni, "google.com");
    }
}

TEST_F(config_test, MissingFile)
{
    const auto cfg = mux::parse_config("non_existent_file.json");
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test, InvalidJson)
{
    write_config_file("{ invalid_json }");
    const auto cfg = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test, MissingFieldsUseDefaults)
{
    const std::string content = R"({})";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_EQ(cfg_opt->mode, "server");
}

TEST_F(config_test, InvalidPortRange)
{
    const std::string content = R"({
        "inbound": {
            "port": 70000
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
}

TEST_F(config_test, EmptyHostAddress)
{
    const std::string content = R"({
        "inbound": {
            "host": ""
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_TRUE(cfg_opt->inbound.host.empty());
}
