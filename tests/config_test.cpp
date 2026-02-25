
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <string>
#include <fstream>
#include <cstdint>
#include <iterator>
#include <unistd.h>
#include <algorithm>

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
    return std::all_of(
        value.begin(),
        value.end(),
        [](const char ch)
        {
            return std::isxdigit(static_cast<unsigned char>(ch)) != 0;
        });
}

std::string read_text_file(const char* path)
{
    std::ifstream in(path);
    if (!in.is_open())
    {
        return {};
    }
    return {(std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>()};
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

class config_test_fixture : public ::testing::Test
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

    [[nodiscard]] const std::string& tmp_file() const { return tmp_file_; }

   private:
    std::string tmp_file_;
};

TEST_F(config_test_fixture, DefaultConfigValid)
{
    const auto json = mux::dump_default_config();
    ASSERT_FALSE(json.empty());

    EXPECT_NE(json.find("\"mode\""), std::string::npos);
    EXPECT_NE(json.find("\"inbound\""), std::string::npos);
}

TEST_F(config_test_fixture, DumpDefaultConfigGeneratesRealityKeyPair)
{
    const auto json = mux::dump_default_config();
    write_config_file(json);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (!cfg_opt.has_value())
    {
        return;
    }
    EXPECT_EQ(cfg_opt->reality.private_key.size(), 64U);
    EXPECT_EQ(cfg_opt->reality.public_key.size(), 64U);
    EXPECT_TRUE(is_hex_string(cfg_opt->reality.private_key));
    EXPECT_TRUE(is_hex_string(cfg_opt->reality.public_key));
}

TEST_F(config_test_fixture, ParseValues)
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
        "timeout": {
            "read": 21,
            "write": 22,
            "connect": 23,
            "idle": 24
        },
        "reality": {
            "sni": "google.com",
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
        EXPECT_EQ(cfg.reality.public_key, std::string(64, 'a'));
        EXPECT_TRUE(cfg.reality.strict_cert_verify);
        EXPECT_EQ(cfg.reality.replay_cache_max_entries, 4096);
        EXPECT_EQ(cfg.heartbeat.idle_timeout, 42);
        EXPECT_EQ(cfg.heartbeat.max_padding, 128);
        EXPECT_EQ(cfg.timeout.read, 21U);
        EXPECT_EQ(cfg.timeout.write, 22U);
        EXPECT_EQ(cfg.timeout.connect, 23U);
        EXPECT_EQ(cfg.timeout.idle, 24U);
        EXPECT_EQ(cfg.queues.udp_session_recv_channel_capacity, 256U);
        EXPECT_EQ(cfg.queues.tproxy_udp_dispatch_queue_capacity, 4096U);
        EXPECT_EQ(cfg.limits.max_connections_per_source, 3U);
        EXPECT_EQ(cfg.limits.source_prefix_v4, 24U);
        EXPECT_EQ(cfg.limits.source_prefix_v6, 64U);
    }
}

TEST_F(config_test_fixture, MissingFile)
{
    const auto cfg = mux::parse_config("non_existent_file.json");
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test_fixture, ClientWithoutAnyInboundRejected)
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

TEST_F(config_test_fixture, ClientWithTproxyOnlyAccepted)
{
    const std::string content = R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "tcp_port": 18080
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (!cfg_opt.has_value())
    {
        return;
    }
    EXPECT_TRUE(cfg_opt->tproxy.enabled);
    EXPECT_FALSE(cfg_opt->socks.enabled);
    EXPECT_EQ(cfg_opt->reality.public_key, std::string(64, 'a'));
}

TEST_F(config_test_fixture, ClientModeRequiresRealityPublicKey)
{
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": ""
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/public_key");
    EXPECT_NE(parsed.error().reason.find("must be non-empty in client mode"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.public_key, std::string(64, 'a'));
}

TEST_F(config_test_fixture, ServerModeRequiresRealityPrivateKey)
{
    write_config_file(R"({
        "mode": "server",
        "reality": {
            "private_key": ""
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/private_key");
    EXPECT_NE(parsed.error().reason.find("must be non-empty in server mode"), std::string::npos);

    write_config_file(R"({
        "mode": "server",
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.private_key, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

TEST_F(config_test_fixture, RealityTypeOnlySupportsTcp)
{
    write_config_file(R"({
        "reality": {
            "type": "udp"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/type");
    EXPECT_NE(parsed.error().reason.find("must be tcp when provided"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "type": "tcp"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.type, "tcp");
}

TEST_F(config_test_fixture, ClientModeRequiresSupportedRealityFingerprint)
{
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fingerprint": "not-supported"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fingerprint");
    EXPECT_NE(parsed.error().reason.find("must be random/chrome/firefox/ios/android"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fingerprint": "firefox-120"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.fingerprint, "firefox-120");
}

TEST_F(config_test_fixture, ClientModeRequiresOutboundHostAndPort)
{
    write_config_file(R"({
        "mode": "client",
        "outbound": {
            "host": "",
            "port": 8844
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/outbound/host");
    EXPECT_NE(parsed.error().reason.find("must be non-empty in client mode"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "outbound": {
            "host": "example.com",
            "port": 0
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/outbound/port");
    EXPECT_NE(parsed.error().reason.find("must be non-zero in client mode"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "outbound": {
            "host": "example.com",
            "port": 443
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->outbound.host, "example.com");
    EXPECT_EQ(parsed->outbound.port, 443);
}

TEST_F(config_test_fixture, SocksEnabledRequiresValidListenHost)
{
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "host": "",
            "port": 1080
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/host");
    EXPECT_NE(parsed.error().reason.find("must be non-empty ip address when socks is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "host": "not-an-ip",
            "port": 1080
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/host");
    EXPECT_NE(parsed.error().reason.find("must be valid ip address when socks is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "server",
        "socks": {
            "enabled": false,
            "host": "not-an-ip",
            "port": 1080
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_FALSE(parsed->socks.enabled);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "host": "::1",
            "port": 1080
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->socks.enabled);
    EXPECT_EQ(parsed->socks.host, "::1");
}

TEST_F(config_test_fixture, SocksAuthCredentialsMustNotContainNul)
{
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user\u0000name",
            "password": "pass"
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");
    EXPECT_NE(parsed.error().reason.find("must not contain nul"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": "pass\u0000word"
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
    EXPECT_NE(parsed.error().reason.find("must not contain nul"), std::string::npos);
}

TEST_F(config_test_fixture, TproxyEnabledRequiresValidListenHostAndNonZeroTcpPort)
{
#if SOCKS_HAS_TPROXY
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "",
            "tcp_port": 18080
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/listen_host");
    EXPECT_NE(parsed.error().reason.find("must be non-empty ip address when tproxy is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "not-an-ip",
            "tcp_port": 18080
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/listen_host");
    EXPECT_NE(parsed.error().reason.find("must be valid ip address when tproxy is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "::1",
            "tcp_port": 0
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/tcp_port");
    EXPECT_NE(parsed.error().reason.find("must be non-zero when tproxy is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "::1",
            "tcp_port": 18080,
            "udp_port": 0
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->tproxy.enabled);
    EXPECT_EQ(parsed->tproxy.listen_host, "::1");
    EXPECT_EQ(parsed->tproxy.tcp_port, 18080);
    EXPECT_EQ(parsed->tproxy.udp_port, 0);
#endif
}

TEST_F(config_test_fixture, InvalidJson)
{
    write_config_file("{ invalid_json }");
    const auto cfg = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg.has_value());
}

TEST_F(config_test_fixture, ParseConfigWithErrorReportsJsonSyntax)
{
    write_config_file("{ invalid_json }");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/");
    EXPECT_NE(parsed.error().reason.find("json parse error"), std::string::npos);
}

TEST_F(config_test_fixture, ParseConfigWithErrorRejectsEmbeddedNulInFileContent)
{
    std::string content = R"({"mode":"client"})";
    content.push_back('\0');
    content += R"({"mode":"server"})";
    write_config_file(content);

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/");
    EXPECT_NE(parsed.error().reason.find("json parse error"), std::string::npos);
}

TEST_F(config_test_fixture, ReadErrorReturnsEmptyConfig)
{
    const std::string content = R"({
        "mode": "client"
    })";
    write_config_file(content);

    g_force_fread_error.store(true);
    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test_fixture, ReplayCacheMaxEntriesWrongTypeRejected)
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

TEST_F(config_test_fixture, ParseConfigWithErrorReportsTypeErrorPath)
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

TEST_F(config_test_fixture, RealityHexFieldsWhenProvidedMustBeValid)
{
    write_config_file(R"({
        "reality": {
            "private_key": "abc"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/private_key");
    EXPECT_NE(parsed.error().reason.find("must be even-length hex when provided"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "public_key": "zz"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/public_key");
    EXPECT_NE(parsed.error().reason.find("must be valid hex when provided"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "short_id": "010203040506070809"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/short_id");
    EXPECT_NE(parsed.error().reason.find("must be at most 8 bytes when provided"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "public_key": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "short_id": "01020304"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.short_id, "01020304");
}

TEST_F(config_test_fixture, RealityDestWhenProvidedMustBeValid)
{
    write_config_file(R"({
        "reality": {
            "dest": "example.com"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");
    EXPECT_NE(parsed.error().reason.find("must be host:port or [ipv6]:port"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "dest": "example.com:0"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");

    write_config_file(R"({
        "reality": {
            "dest": "[::1]443"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");

    write_config_file(R"({
        "reality": {
            "dest": "::1:443"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");

    write_config_file(R"({
        "reality": {
            "dest": "example.com:443",
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.dest, "example.com:443");

    write_config_file(R"({
        "reality": {
            "dest": "[::1]:443",
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.dest, "[::1]:443");

    write_config_file(R"({
        "reality": {
            "dest": "example.com\u0000:443",
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");
    EXPECT_NE(parsed.error().reason.find("must not contain nul"), std::string::npos);
}

TEST_F(config_test_fixture, FallbackEntryRequiresNonEmptyHostAndValidPort)
{
    write_config_file(R"({
        "fallbacks": [
            {
                "sni": "www.example.com",
                "host": "",
                "port": "443"
            }
        ]
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/fallbacks/0/host");
    EXPECT_NE(parsed.error().reason.find("must be non-empty"), std::string::npos);

    write_config_file(R"({
        "fallbacks": [
            {
                "sni": "www.example.com",
                "host": "127.0.0.1",
                "port": "0"
            }
        ]
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/fallbacks/0/port");
    EXPECT_NE(parsed.error().reason.find("must be in 1-65535"), std::string::npos);
}

TEST_F(config_test_fixture, FallbackEntryRejectsNulInHostOrSni)
{
    write_config_file(R"({
        "fallbacks": [
            {
                "sni": "www.example.com",
                "host": "127.0.0.1\u0000x",
                "port": "443"
            }
        ]
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/fallbacks/0/host");
    EXPECT_NE(parsed.error().reason.find("must not contain nul"), std::string::npos);

    write_config_file(R"({
        "fallbacks": [
            {
                "sni": "www.exa\u0000mple.com",
                "host": "127.0.0.1",
                "port": "443"
            }
        ]
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/fallbacks/0/sni");
    EXPECT_NE(parsed.error().reason.find("must not contain nul"), std::string::npos);
}

TEST_F(config_test_fixture, FallbackSniMustRemainNonEmptyAfterNormalization)
{
    write_config_file(R"({
        "fallbacks": [
            {
                "sni": ".",
                "host": "127.0.0.1",
                "port": "443"
            }
        ]
    })");
    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/fallbacks/0/sni");
    EXPECT_NE(parsed.error().reason.find("must be non-empty after normalization"), std::string::npos);
}

TEST_F(config_test_fixture, MissingFieldsUseDefaults)
{
    const std::string content = R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (!cfg_opt.has_value())
    {
        return;
    }
    EXPECT_EQ(cfg_opt->mode, "server");
    EXPECT_FALSE(cfg_opt->reality.strict_cert_verify);
    EXPECT_EQ(cfg_opt->reality.replay_cache_max_entries, 100000);
    EXPECT_EQ(cfg_opt->reality.private_key, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    EXPECT_TRUE(cfg_opt->reality.public_key.empty());
    EXPECT_TRUE(cfg_opt->reality.fallback_guard.enabled);
    EXPECT_EQ(cfg_opt->timeout.connect, 10U);
    EXPECT_EQ(cfg_opt->queues.udp_session_recv_channel_capacity, 512U);
    EXPECT_EQ(cfg_opt->queues.tproxy_udp_dispatch_queue_capacity, 512U);
}

TEST_F(config_test_fixture, InvalidPortRange)
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

TEST_F(config_test_fixture, NegativePortRejected)
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

TEST_F(config_test_fixture, NegativeWorkersRejected)
{
    const std::string content = R"({
        "workers": -1
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test_fixture, WorkersZeroUsesAutoDetection)
{
    const std::string content = R"({
        "workers": 0,
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (!cfg_opt.has_value())
    {
        return;
    }
    EXPECT_EQ(cfg_opt->workers, 0U);
}

TEST_F(config_test_fixture, HeartbeatIntervalRangeRejected)
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

TEST_F(config_test_fixture, ParseConfigWithErrorReportsValidationPath)
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

TEST_F(config_test_fixture, HeartbeatZeroIntervalRejected)
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

TEST_F(config_test_fixture, HeartbeatPaddingRangeRejected)
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

TEST_F(config_test_fixture, HeartbeatPaddingTooLargeRejected)
{
    const auto too_large_padding = static_cast<std::uint64_t>(mux::kMaxPayloadPerRecord) + 1ULL;
    const std::string content = std::string(R"({
        "heartbeat": {
            "min_padding": 16,
            "max_padding": )") + std::to_string(too_large_padding) +
                                R"(
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}

TEST_F(config_test_fixture, MaxConnectionsZeroNormalizedToOne)
{
    const std::string content = R"({
        "limits": {
            "max_connections": 0
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })";
    write_config_file(content);

    const auto cfg_opt = mux::parse_config(tmp_file());
    ASSERT_TRUE(cfg_opt.has_value());
    if (!cfg_opt.has_value())
    {
        return;
    }
    EXPECT_EQ(cfg_opt->limits.max_connections, 1U);
}

TEST_F(config_test_fixture, MaxBufferZeroRejected)
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

TEST_F(config_test_fixture, QueueCapacityOutOfRangeRejected)
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

TEST_F(config_test_fixture, EmptyHostAddressRejected)
{
    const std::string content = R"({
        "inbound": {
            "host": ""
        }
    })";
    write_config_file(content);

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/inbound/host");
    EXPECT_NE(parsed.error().reason.find("non-empty ip address"), std::string::npos);
}

TEST_F(config_test_fixture, InvalidInboundHostRejectedAtParseStage)
{
    write_config_file(R"({
        "inbound": {
            "host": "not-a-valid-ip"
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/inbound/host");
    EXPECT_NE(parsed.error().reason.find("valid ip address"), std::string::npos);
}

TEST_F(config_test_fixture, ClientModeAllowsEmptyInboundHost)
{
    write_config_file(R"({
        "mode": "client",
        "inbound": {
            "host": ""
        },
        "outbound": {
            "host": "127.0.0.1",
            "port": 443
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "socks": {
            "enabled": true
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->mode, "client");
}

TEST_F(config_test_fixture, FallbackGuardEnabledRequiresPositiveParameters)
{
    write_config_file(R"({
        "reality": {
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 0
            }
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/rate_per_sec");

    write_config_file(R"({
        "reality": {
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 0
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/burst");

    write_config_file(R"({
        "reality": {
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "state_ttl_sec": 0
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/state_ttl_sec");

    write_config_file(R"({
        "reality": {
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "state_ttl_sec": 1,
                "circuit_fail_threshold": 1,
                "circuit_open_sec": 0
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/circuit_open_sec");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "key_mode": "bad-mode"
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/key_mode");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "key_mode": ""
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/key_mode");
}

TEST_F(config_test_fixture, FallbackGuardAllowsZeroCircuitOpenWhenThresholdDisabled)
{
    write_config_file(R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "state_ttl_sec": 1,
                "circuit_fail_threshold": 0,
                "circuit_open_sec": 0
            }
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());

    write_config_file(R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "fallback_guard": {
                "enabled": false,
                "rate_per_sec": 0,
                "burst": 0,
                "state_ttl_sec": 0,
                "circuit_fail_threshold": 0,
                "circuit_open_sec": 0
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 1,
                "burst": 1,
                "key_mode": "ip_sni"
            }
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.fallback_guard.key_mode, "ip_sni");
}

TEST_F(config_test_fixture, DumpConfigIncludesHeartbeatIdleTimeout)
{
    mux::config cfg;
    cfg.heartbeat.idle_timeout = 77;

    const auto dumped = mux::dump_config(cfg);
    EXPECT_NE(dumped.find("\"idle_timeout\""), std::string::npos);
    EXPECT_NE(dumped.find("\"heartbeat\""), std::string::npos);
}

TEST_F(config_test_fixture, ContractMatrixTimeoutRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("timeout.read"), std::string::npos);
    EXPECT_NE(doc.find("timeout.write"), std::string::npos);
    EXPECT_NE(doc.find("timeout.connect"), std::string::npos);
    EXPECT_NE(doc.find("timeout.idle"), std::string::npos);
    EXPECT_NE(doc.find("timeout.read = 0`、`timeout.write = 0` 与 `timeout.connect = 0`"), std::string::npos);
    EXPECT_NE(doc.find("timeout.idle = 0`：表示禁用空闲超时"), std::string::npos);

    write_config_file(R"({
        "timeout": {
            "read": 0,
            "write": 0,
            "connect": 0,
            "idle": 0
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->timeout.read, 0U);
    EXPECT_EQ(parsed->timeout.write, 0U);
    EXPECT_EQ(parsed->timeout.connect, 0U);
    EXPECT_EQ(parsed->timeout.idle, 0U);
}

TEST_F(config_test_fixture, ContractMatrixHeartbeatRulesStayAlignedWithDocumentation)
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
        heartbeat_contract_case{.json = R"({
                "heartbeat": {
                    "min_interval": 30,
                    "max_interval": 10
                }
            })",
                                .expected_path = "/heartbeat/min_interval",
                                .expected_reason_substr = "must be less than or equal to max_interval"},
        heartbeat_contract_case{.json = R"({
                "heartbeat": {
                    "min_interval": 1,
                    "max_interval": 0
                }
            })",
                                .expected_path = "/heartbeat/max_interval",
                                .expected_reason_substr = "must be greater than 0"},
        heartbeat_contract_case{.json = R"({
                "heartbeat": {
                    "min_padding": 1,
                    "max_padding": 70000
                }
            })",
                                .expected_path = "/heartbeat/max_padding",
                                .expected_reason_substr = "single record payload"}};

    for (const auto& c : cases)
    {
        write_config_file(c.json);
        const auto parsed = mux::parse_config_with_error(tmp_file());
        ASSERT_FALSE(parsed.has_value());
        EXPECT_EQ(parsed.error().path, c.expected_path);
        EXPECT_NE(parsed.error().reason.find(c.expected_reason_substr), std::string::npos);
    }
}

TEST_F(config_test_fixture, ContractMatrixLimitsRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("limits.max_connections"), std::string::npos);
    EXPECT_NE(doc.find("`0` 会在加载与运行时归一化为 `1`"), std::string::npos);
    EXPECT_NE(doc.find("limits.max_buffer` 必须大于 `0`"), std::string::npos);

    write_config_file(R"({
        "limits": {
            "max_connections": 0
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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

TEST_F(config_test_fixture, ContractMatrixQueueRulesStayAlignedWithDocumentation)
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
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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

TEST_F(config_test_fixture, ContractMatrixMonitorRulesStayAlignedWithDocumentation)
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
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->monitor.enabled);
    EXPECT_EQ(parsed->monitor.port, 19090);
}

TEST_F(config_test_fixture, ContractMatrixTproxyRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `tproxy.enabled = true` 时，`tproxy.listen_host` 必须是非空且合法的 IP 地址"), std::string::npos);
    EXPECT_NE(doc.find("当 `tproxy.enabled = true` 时，`tproxy.tcp_port` 必须大于 `0`"), std::string::npos);
    EXPECT_NE(doc.find("`tproxy` 入站仅在 `mode = client` 时生效"), std::string::npos);

#if SOCKS_HAS_TPROXY
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "",
            "tcp_port": 18080
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/listen_host");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": false
        },
        "tproxy": {
            "enabled": true,
            "listen_host": "::1",
            "tcp_port": 0
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/tcp_port");
#endif
}

TEST_F(config_test_fixture, ServerModeRejectsTproxyInbound)
{
    write_config_file(R"({
        "mode": "server",
        "tproxy": {
            "enabled": true,
            "listen_host": "::",
            "tcp_port": 18080
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/tproxy/enabled");
    EXPECT_NE(parsed.error().reason.find("server mode does not support tproxy inbound"), std::string::npos);
}

TEST_F(config_test_fixture, ContractMatrixSocksHostRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `socks.enabled = true` 时，`socks.host` 必须是非空且合法的 IP 地址"), std::string::npos);
    EXPECT_NE(doc.find("该约束仅在 `mode = client` 下生效"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "host": "",
            "port": 1080
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/host");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "host": "127.0.0.1",
            "port": 1080
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->socks.host, "127.0.0.1");
}

TEST_F(config_test_fixture, ServerModeSkipsSocksValidation)
{
    write_config_file(R"({
        "mode": "server",
        "socks": {
            "enabled": true,
            "host": "not-an-ip",
            "auth": true,
            "username": "",
            "password": ""
        },
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->mode, "server");
}

TEST_F(config_test_fixture, ContractMatrixClientRealityPublicKeyRuleStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `mode = client` 时，`reality.public_key` 必须为非空值"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": ""
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/public_key");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.public_key, std::string(64, 'a'));
}

TEST_F(config_test_fixture, ContractMatrixClientOutboundRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `mode = client` 时，`outbound.host` 必须为非空字符串"), std::string::npos);
    EXPECT_NE(doc.find("当 `mode = client` 时，`outbound.port` 必须大于 `0`"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "outbound": {
            "host": "",
            "port": 443
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/outbound/host");

    write_config_file(R"({
        "mode": "client",
        "outbound": {
            "host": "example.com",
            "port": 443
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->outbound.host, "example.com");
    EXPECT_EQ(parsed->outbound.port, 443);
}

TEST_F(config_test_fixture, ContractMatrixClientInboundRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("`inbound.host` 仅在 `mode = server` 时作为服务端监听地址参与校验"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "inbound": {
            "host": ""
        },
        "outbound": {
            "host": "example.com",
            "port": 443
        },
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->mode, "client");
}

TEST_F(config_test_fixture, ContractMatrixClientRealityFingerprintRuleStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("可选值：`random`、`chrome`、`firefox`、`ios`、`android`"), std::string::npos);
    EXPECT_NE(doc.find("当 `mode = client` 时，`reality.fingerprint` 仅允许上述值"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fingerprint": "bad-fp"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fingerprint");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "fingerprint": "android"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.fingerprint, "android");
}

TEST_F(config_test_fixture, ContractMatrixRealityDestRuleStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("在提供时必须符合 `host:port` 或 `[ipv6]:port`"), std::string::npos);
    EXPECT_NE(doc.find("端口范围必须在 `1-65535`"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "dest": "example.com"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/dest");

    write_config_file(R"({
        "reality": {
            "dest": "example.com:443",
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.dest, "example.com:443");
}

TEST_F(config_test_fixture, ContractMatrixRealityHexRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("解码后长度必须为 `32` 字节"), std::string::npos);
    EXPECT_NE(doc.find("解码后长度不得超过 `8` 字节"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "public_key": "zz"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/public_key");

    write_config_file(R"({
        "reality": {
            "private_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "public_key": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "short_id": "01020304"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->reality.short_id, "01020304");
}

TEST_F(config_test_fixture, ContractMatrixFallbackGuardRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `reality.fallback_guard.enabled = true` 时"), std::string::npos);
    EXPECT_NE(doc.find("`rate_per_sec` 与 `burst` 必须大于 `0`"), std::string::npos);
    EXPECT_NE(doc.find("`state_ttl_sec` 必须大于 `0`"), std::string::npos);
    EXPECT_NE(doc.find("`circuit_fail_threshold > 0` 时，`circuit_open_sec` 必须大于 `0`"), std::string::npos);

    write_config_file(R"({
        "reality": {
            "fallback_guard": {
                "enabled": true,
                "rate_per_sec": 0
            }
        }
    })");
    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/reality/fallback_guard/rate_per_sec");
}

TEST_F(config_test_fixture, SocksAuthEnabledRequiresNonEmptyCredentials)
{
    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "",
            "password": "pass"
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");
    EXPECT_NE(parsed.error().reason.find("must be non-empty when auth is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": ""
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
    EXPECT_NE(parsed.error().reason.find("must be non-empty when auth is enabled"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": "pass"
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->socks.auth);
    EXPECT_EQ(parsed->socks.username, "user");
    EXPECT_EQ(parsed->socks.password, "pass");

    const std::string too_long_username(256, 'u');
    write_config_file("{\"mode\":\"client\",\"socks\":{\"enabled\":true,\"auth\":true,\"username\":\"" + too_long_username +
                      "\",\"password\":\"pass\"},\"reality\":{\"public_key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");
    EXPECT_NE(parsed.error().reason.find("must be at most 255 bytes when auth is enabled"), std::string::npos);

    const std::string too_long_password(256, 'p');
    write_config_file("{\"mode\":\"client\",\"socks\":{\"enabled\":true,\"auth\":true,\"username\":\"user\",\"password\":\"" + too_long_password +
                      "\"},\"reality\":{\"public_key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
    EXPECT_NE(parsed.error().reason.find("must be at most 255 bytes when auth is enabled"), std::string::npos);
}

TEST_F(config_test_fixture, ContractMatrixSocksAuthRulesStayAlignedWithDocumentation)
{
    const auto doc = load_configuration_doc();
    ASSERT_FALSE(doc.empty());
    EXPECT_NE(doc.find("当 `socks.auth = true` 时，`socks.username` 与 `socks.password` 必须均为非空字符串"), std::string::npos);
    EXPECT_NE(doc.find("任一为空会在配置解析阶段直接报错"), std::string::npos);
    EXPECT_NE(doc.find("两者长度均不得超过 `255` 字节"), std::string::npos);

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "",
            "password": "pass"
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/username");

    write_config_file(R"({
        "mode": "client",
        "socks": {
            "enabled": true,
            "auth": true,
            "username": "user",
            "password": ""
        },
        "reality": {
            "public_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    })");
    parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/socks/password");
}

TEST_F(config_test_fixture, UnsupportedModeRejectedAtParseStage)
{
    write_config_file(R"({
        "mode": "invalid"
    })");

    const auto parsed = mux::parse_config_with_error(tmp_file());
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().path, "/mode");
    EXPECT_NE(parsed.error().reason.find("must be client or server"), std::string::npos);

    const auto cfg_opt = mux::parse_config(tmp_file());
    EXPECT_FALSE(cfg_opt.has_value());
}
