#include <array>
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

std::string read_text_file(const char* path)
{
    std::ifstream in(path);
    if (!in.is_open())
    {
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::string load_configuration_doc()
{
    for (const char* path : {"doc/configuration.md", "../doc/configuration.md", "../../doc/configuration.md"})
    {
        auto content = read_text_file(path);
        if (!content.empty())
        {
            return content;
        }
    }
    return {};
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
        "queues": {
            "udp_session_recv_channel_capacity": 256,
            "tproxy_udp_dispatch_queue_capacity": 4096
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
        EXPECT_EQ(cfg.queues.udp_session_recv_channel_capacity, 256U);
        EXPECT_EQ(cfg.queues.tproxy_udp_dispatch_queue_capacity, 4096U);
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

TEST_F(config_test, ParseConfigWithErrorReportsJsonSyntax)
{
    write_config_file("{ invalid_json }");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/");
    EXPECT_NE(parsed.error().reason.find("json parse error"), std::string::npos);
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

TEST_F(config_test, ParseConfigWithErrorReportsTypeErrorPath)
{
    const std::string content = R"({
        "reality": {
            "replay_cache_max_entries": "bad"
        }
    })";
    write_config_file(content);

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/replay_cache_max_entries");
    EXPECT_NE(parsed.error().reason.find("invalid type or value"), std::string::npos);
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
    EXPECT_EQ(cfg_opt->queues.udp_session_recv_channel_capacity, 512U);
    EXPECT_EQ(cfg_opt->queues.tproxy_udp_dispatch_queue_capacity, 512U);
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

TEST_F(config_test, ParseConfigWithErrorReportsValidationPath)
{
    const std::string content = R"({
        "heartbeat": {
            "min_interval": 30,
            "max_interval": 10
        }
    })";
    write_config_file(content);

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/heartbeat/min_interval");
    EXPECT_NE(parsed.error().reason.find("must be less than or equal to max_interval"), std::string::npos);
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

TEST_F(config_test, QueueCapacityOutOfRangeRejected)
{
    write_config_file(R"({
        "queues": {
            "udp_session_recv_channel_capacity": 0
        }
    })");

    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/queues/udp_session_recv_channel_capacity");
    EXPECT_NE(parsed.error().reason.find("must be between 1 and 65535"), std::string::npos);

    write_config_file(R"({
        "queues": {
            "tproxy_udp_dispatch_queue_capacity": 70000
        }
    })");

    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/queues/tproxy_udp_dispatch_queue_capacity");
    EXPECT_NE(parsed.error().reason.find("must be between 1 and 65535"), std::string::npos);
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

TEST_F(config_test, ContractMatrixTimeoutRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("timeout.read"), std::string::npos);
    EXPECT_NE(doc.find("timeout.write"), std::string::npos);
    EXPECT_NE(doc.find("timeout.idle"), std::string::npos);
    EXPECT_NE(doc.find("timeout.read = 0` 与 `timeout.write = 0`"), std::string::npos);
    EXPECT_NE(doc.find("timeout.idle = 0`：表示禁用空闲超时"), std::string::npos);

    write_config_file(R"({
        "timeout": {
            "read": 0,
            "write": 0,
            "idle": 0
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->timeout.read, 0U);
    EXPECT_EQ(parsed->timeout.write, 0U);
    EXPECT_EQ(parsed->timeout.idle, 0U);
}

TEST_F(config_test, ContractMatrixHeartbeatRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("heartbeat.min_interval <= heartbeat.max_interval"), std::string::npos);
    EXPECT_NE(doc.find("heartbeat.min_interval` 和 `heartbeat.max_interval` 必须大于 `0`"), std::string::npos);
    EXPECT_NE(doc.find("heartbeat.max_padding` 必须小于等于"), std::string::npos);

    struct heartbeat_contract_case
    {
        const char* json;
        const char* expected_path;
        const char* expected_reason_substr;
    };

    const std::array<heartbeat_contract_case, 3> cases = {
        heartbeat_contract_case{
            R"({
                "heartbeat": {
                    "min_interval": 30,
                    "max_interval": 10
                }
            })",
            "/heartbeat/min_interval",
            "must be less than or equal to max_interval"},
        heartbeat_contract_case{
            R"({
                "heartbeat": {
                    "min_interval": 1,
                    "max_interval": 0
                }
            })",
            "/heartbeat/max_interval",
            "must be greater than 0"},
        heartbeat_contract_case{
            R"({
                "heartbeat": {
                    "min_padding": 1,
                    "max_padding": 70000
                }
            })",
            "/heartbeat/max_padding",
            "max payload"}};

    for (const auto& c : cases)
    {
        write_config_file(c.json);
        const auto parsed = mux::parse_config_with_error(tmp_file());
        ASSERT_FALSE(parsed.has_value());
        EXPECT_EQ(parsed.error().path, c.expected_path);
        EXPECT_NE(parsed.error().reason.find(c.expected_reason_substr), std::string::npos);
    }
}

TEST_F(config_test, ContractMatrixLimitsRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("limits.max_connections"), std::string::npos);
    EXPECT_NE(doc.find("`0` 会在加载与运行时归一化为 `1`"), std::string::npos);
    EXPECT_NE(doc.find("limits.max_buffer` 必须大于 `0`"), std::string::npos);

    write_config_file(R"({
        "limits": {
            "max_connections": 0
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->limits.max_connections, 1U);

    write_config_file(R"({
        "limits": {
            "max_buffer": 0
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/limits/max_buffer");
    EXPECT_NE(parsed.error().reason.find("must be greater than 0"), std::string::npos);
}

TEST_F(config_test, ContractMatrixQueueRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("queues.udp_session_recv_channel_capacity"), std::string::npos);
    EXPECT_NE(doc.find("queues.tproxy_udp_dispatch_queue_capacity"), std::string::npos);
    EXPECT_NE(doc.find("必须在 `1-65535`"), std::string::npos);

    write_config_file(R"({
        "queues": {
            "udp_session_recv_channel_capacity": 1024,
            "tproxy_udp_dispatch_queue_capacity": 8192
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->queues.udp_session_recv_channel_capacity, 1024U);
    EXPECT_EQ(parsed->queues.tproxy_udp_dispatch_queue_capacity, 8192U);

    write_config_file(R"({
        "queues": {
            "udp_session_recv_channel_capacity": 0
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/queues/udp_session_recv_channel_capacity");
}

TEST_F(config_test, ContractMatrixMonitorRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("monitor.enabled"), std::string::npos);
    EXPECT_NE(doc.find("monitor.port"), std::string::npos);
    EXPECT_NE(doc.find("仅支持 HTTP `GET /metrics`"), std::string::npos);

    write_config_file(R"({
        "monitor": {
            "enabled": true,
            "port": 19090
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->monitor.enabled);
    EXPECT_EQ(parsed->monitor.port, 19090);
}

TEST_F(config_test, SocksAuthEnabledRequiresNonEmptyCredentials)
{
    write_config_file(R"({
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "",
            "password": "pass"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");
    EXPECT_NE(parsed.error().reason.find("must be non-empty when auth is enabled"), std::string::npos);

    write_config_file(R"({
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": ""
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
    EXPECT_NE(parsed.error().reason.find("must be non-empty when auth is enabled"), std::string::npos);

    write_config_file(R"({
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": "pass"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->socks.auth);
    EXPECT_EQ(parsed->socks.username, "user");
    EXPECT_EQ(parsed->socks.password, "pass");
}

TEST_F(config_test, ContractMatrixSocksAuthRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `socks.auth = true` 时，`socks.username` 与 `socks.password` 必须均为非空字符串"), std::string::npos);
    EXPECT_NE(doc.find("任一为空会在配置解析阶段直接报错"), std::string::npos);

    write_config_file(R"({
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "",
            "password": "pass"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");

    write_config_file(R"({
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": ""
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
}
