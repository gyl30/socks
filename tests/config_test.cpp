#include <cstdio>
#include <string>
#include <atomic>
#include <cerrno>
#include <fstream>
#include <cctype>
#include <unistd.h>

#include <gtest/gtest.h>

#include "config.h"
#include "mux_protocol.h"

namespace
{

std::atomic<bool> g_force_fread_error{false};
std::atomic<bool> g_injected_fread_error{false};

bool is_hex_string(const std::string& value)
{
    if (value.empty())
    {
        return false;
    }

    for (const unsigned char ch : value)
    {
        if (!std::isxdigit(ch))
        {
            return false;
        }
    }
    return true;
}

}    // namespace

extern "C" std::size_t __real_fread(void* ptr, std::size_t size, std::size_t count, FILE* stream);
extern "C" int __real_ferror(FILE* stream);

extern "C" std::size_t __wrap_fread(void* ptr, std::size_t size, std::size_t count, FILE* stream)
{
    if (g_force_fread_error.exchange(false))
    {
        g_injected_fread_error.store(true);
        errno = EIO;
        return 0;
    }
    return __real_fread(ptr, size, count, stream);
}

extern "C" int __wrap_ferror(FILE* stream)
{
    if (g_injected_fread_error.exchange(false))
    {
        return 1;
    }
    return __real_ferror(stream);
}

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

TEST_F(config_test, DumpDefaultConfigGeneratesRealityKeyPair)
{
    const auto json = mux::dump_default_config();
    write_config_file(json);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_EQ(cfg_opt->reality.private_key.size(), 64U);
    EXPECT_EQ(cfg_opt->reality.public_key.size(), 64U);
    EXPECT_TRUE(is_hex_string(cfg_opt->reality.private_key));
    EXPECT_TRUE(is_hex_string(cfg_opt->reality.public_key));
}

TEST_F(config_test, ParseValues)
{
    const std::string content = R"({
        "mode": "client",
        "workers": 6,
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
            "sni": "google.com",
            "strict_cert_verify": true,
            "replay_cache_max_entries": 4096
        },
        "heartbeat": {
            "enabled": true,
            "idle_timeout": 42,
            "min_interval": 15,
            "max_interval": 30,
            "min_padding": 16,
            "max_padding": 128
        },
        "limits": {
            "max_connections_per_source": 3,
            "source_prefix_v4": 24,
            "source_prefix_v6": 64
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (cfg_opt.has_value())
    {
        const auto& cfg = *cfg_opt;

        EXPECT_EQ(cfg.mode, "client");
        EXPECT_EQ(cfg.workers, 6U);
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
        EXPECT_TRUE(cfg.reality.strict_cert_verify);
        EXPECT_EQ(cfg.reality.replay_cache_max_entries, 4096);
        EXPECT_EQ(cfg.heartbeat.idle_timeout, 42);
        EXPECT_EQ(cfg.heartbeat.max_padding, 128);
        EXPECT_EQ(cfg.limits.max_connections_per_source, 3U);
        EXPECT_EQ(cfg.limits.source_prefix_v4, 24U);
        EXPECT_EQ(cfg.limits.source_prefix_v6, 64U);
    }
}

TEST_F(config_test, MissingFile)
{
    const auto cfg = mux::parse_config("non_existent_file.json");
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test, ClientWithoutAnyInboundRejected)
{
    const std::string content = R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": false
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, ClientWithTproxyOnlyAccepted)
{
    const std::string content = R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "tcp_port": 18080
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_TRUE(cfg_opt->tproxy.enabled);
    EXPECT_FALSE(cfg_opt->socks.enabled);
}

TEST_F(config_test, InvalidJson)
{
    write_config_file("{ invalid_json }");
    const auto cfg = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test, ReadErrorReturnsEmptyConfig)
{
    const std::string content = R"({
        "mode": "client"
    })";
    write_config_file(content);

    g_force_fread_error.store(true);
    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, ReplayCacheMaxEntriesWrongTypeRejected)
{
    const std::string content = R"({
        "reality": {
            "replay_cache_max_entries": "bad"
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, MissingFieldsUseDefaults)
{
    const std::string content = R"({})";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_EQ(cfg_opt->mode, "server");
    EXPECT_FALSE(cfg_opt->reality.strict_cert_verify);
    EXPECT_EQ(cfg_opt->reality.replay_cache_max_entries, 100000);
    EXPECT_TRUE(cfg_opt->reality.private_key.empty());
    EXPECT_TRUE(cfg_opt->reality.public_key.empty());
    EXPECT_TRUE(cfg_opt->reality.fallback_guard.enabled);
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
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, NegativePortRejected)
{
    const std::string content = R"({
        "inbound": {
            "port": -1
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, NegativeWorkersRejected)
{
    const std::string content = R"({
        "workers": -1
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, WorkersZeroUsesAutoDetection)
{
    const std::string content = R"({
        "workers": 0
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_EQ(cfg_opt->workers, 0U);
}

TEST_F(config_test, HeartbeatIntervalRangeRejected)
{
    const std::string content = R"({
        "heartbeat": {
            "min_interval": 30,
            "max_interval": 10
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, HeartbeatZeroIntervalRejected)
{
    const std::string content = R"({
        "heartbeat": {
            "min_interval": 0,
            "max_interval": 0
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, HeartbeatPaddingRangeRejected)
{
    const std::string content = R"({
        "heartbeat": {
            "min_padding": 256,
            "max_padding": 128
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, HeartbeatPaddingTooLargeRejected)
{
    const auto too_large_padding = static_cast<std::uint64_t>(mux::kMaxPayload) + 1ULL;
    const std::string content = std::string(R"({
        "heartbeat": {
            "min_padding": 16,
            "max_padding": )")
        + std::to_string(too_large_padding) + R"(
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test, MaxConnectionsZeroNormalizedToOne)
{
    const std::string content = R"({
        "limits": {
            "max_connections": 0
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    EXPECT_EQ(cfg_opt->limits.max_connections, 1U);
}

TEST_F(config_test, MaxBufferZeroRejected)
{
    const std::string content = R"({
        "limits": {
            "max_buffer": 0
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
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

TEST_F(config_test, DumpConfigIncludesHeartbeatIdleTimeout)
{
    mux::config cfg;
    cfg.heartbeat.idle_timeout = 77;

    const auto dumped = mux::dump_config(cfg);
    EXPECT_NE(dumped.find("\"idle_timeout\""), std::string::npos);
    EXPECT_NE(dumped.find("\"heartbeat\""), std::string::npos);
}
