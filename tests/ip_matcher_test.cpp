#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include "ip_matcher.h"

class IpMatcherTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        // 创建临时文件名
        rule_file_ = "temp_test_rules.txt";
    }

    void TearDown() override
    {
        // 如果文件存在则删除
        std::remove(rule_file_.c_str());
    }

    void WriteRules(const std::vector<std::string>& rules)
    {
        std::ofstream f(rule_file_);
        for (const auto& rule : rules)
        {
            f << rule << "\n";
        }
        f.close();
    }

    std::string rule_file_;
};

TEST_F(IpMatcherTest, MatchIPv4_Basic)
{
    WriteRules({"192.168.1.0/24", "10.0.0.0/8"});

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 正向匹配
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.255", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.255.255.255", ec)));

    // 反向匹配 (预期失败)
    EXPECT_FALSE(matcher.match(asio::ip::make_address("192.168.2.1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("11.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_Basic)
{
    WriteRules({
        "2001:db8::/32",    // 文档保留段
        "fe80::/10",        // 链路本地地址
        "::1/128"           // 本地回环
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;

    // 2001:db8::/32
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("2001:db9::1", ec)));

    // fe80::/10
    EXPECT_TRUE(matcher.match(asio::ip::make_address("fe80::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("febf::1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("fec0::1", ec)));    // 超出 /10 范围

    // ::1/128
    EXPECT_TRUE(matcher.match(asio::ip::make_address("::1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("::2", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_ComplexMasks)
{
    WriteRules({
        "2400:cb00::/32",
        "2606:4700:4700::/96"    // Cloudflare DNS 示例网段
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2400:cb00:1234::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2606:4700:4700::1111", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("2606:4700:4700:1::1", ec)));    // 超出 /96 范围
}

TEST_F(IpMatcherTest, EdgeCases_Optimization)
{
    // 重叠和相邻规则应被正确优化
    WriteRules({
        "192.168.1.0/24",
        "192.168.1.0/25",    // 前一条规则的子集
        "192.168.2.0/24",    // 相邻网段
        "2001:db8::/32",
        "2001:db8:8000::/33"    // IPv6 子集
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));
    // 实现说明：优化逻辑合并了这些。我们严格测试匹配结果是否正确。

    asio::error_code ec;
    // 192.168.1.x 和 192.168.2.x 均应匹配
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.100", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.200", ec)));    // 原属于 /24 但不在 /25
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.2.50", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("192.168.3.1", ec)));

    // IPv6 子集检查
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8:8000::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
}

TEST_F(IpMatcherTest, EdgeCases_InvalidInputs)
{
    WriteRules({"1.2.3.4/24",
                "invalid_ip",
                "999.999.999.999/24",    // 无效 IP
                "10.0.0.1/33",           // 无效 v4 前缀
                "fe80::1/129",           // 无效 v6 前缀
                "# Comments should be ignored",
                "   ",    // 空行
                "8.8.8.8/32"});

    mux::ip_matcher matcher;
    // 即便部分行解析失败，加载通常也返回 true，除非文件无法打开。当前实现会记录警告但继续。
    // 基于代码：除非文件打开失败，否则返回 true。
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("1.2.3.10", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("8.8.8.8", ec)));

    // 无效规则不应被添加
    // 10.0.0.1 前缀无效，不应匹配
    EXPECT_FALSE(matcher.match(asio::ip::make_address("10.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv4_MatchAll)
{
    WriteRules({"0.0.0.0/0"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("1.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("255.255.255.255", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_MatchAll)
{
    WriteRules({"::/0"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("fe80::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("::1", ec)));
}

TEST_F(IpMatcherTest, PrefixWithSpaces)
{
    // "192.168.1.0/24 " 带有尾部空格 -> 严格解析可能失败
    // "192.168.2.0/ 24" 前缀带有前导空格
    WriteRules({"192.168.1.0/24 ", "192.168.2.0/ 24"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 如果你修复了 trim 逻辑，这些规则应该能匹配。这里 EXPECT_TRUE 验证修复后的行为。

    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.2.1", ec)));
}

TEST_F(IpMatcherTest, PrefixLeadingZero)
{
    // "08" 应解析为十进制 8，而不是错误或八进制
    WriteRules({"10.0.0.0/08"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.1.1.1", ec)));
}

TEST_F(IpMatcherTest, PrefixOutOfRange)
{
    // /999 应被忽略或报错，绝不应崩溃或扩大匹配范围
    WriteRules({"192.168.1.0/999"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_FALSE(matcher.match(asio::ip::make_address("192.168.1.1", ec)));
}

TEST_F(IpMatcherTest, IPv6_Exact128BitBoundary)
{
    WriteRules({"2001:db8::1/128"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("2001:db8::2", ec)));
}

TEST_F(IpMatcherTest, LargeRuleSet)
{
    std::vector<std::string> rules;
    // 生成 1000 条规则：10.0.0.0/24, 10.0.1.0/24, ...
    // 使用 10.x.y.0/24 创建大量小规则
    // 1000 条大约覆盖 10.0.0.0 到 10.3.231.0
    for (int i = 0; i < 1000; ++i)
    {
        int b2 = (i / 256) % 256;
        int b3 = i % 256;
        char buf[64];
        snprintf(buf, sizeof(buf), "10.%d.%d.0/24", b2, b3);
        rules.push_back(std::string(buf));
    }
    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 检查边界
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.0.0.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.0.255.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.1.0.1", ec)));

    // 检查未覆盖区域
    // 1000 rules -> up to i=999 -> 10.3.231.0/24
    // 10.4.0.0 应失败
    EXPECT_FALSE(matcher.match(asio::ip::make_address("10.5.0.1", ec)));
}

TEST_F(IpMatcherTest, IPv6_OddBitPrefix)
{
    // /65 非 nibble 对齐 (64 + 1)
    // 2001:db8::/65
    // 网络：2001:0db8:0000:0000:0xxx...
    // 第 65 位是 0。
    // 2001:db8::1 第 65 位为 0。匹配。
    // 2001:db8:0:0:8000::1 第 65 位为 1。不匹配。
    // (8000 十六进制 = 1000 1000... 错误，应该是 1000 0000...)
    WriteRules({"2001:db8::/65"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("2001:db8:0:0:8000::1", ec)));
}

TEST_F(IpMatcherTest, IPv6_NonCanonicalNetwork)
{
    // 测试非规范化网络地址：2001:db8::8000/65
    // 第 65 位是 1，但前缀长度只覆盖前 65 位
    // 真实的 DPI 应当在加载时进行掩码处理 (network &= mask)
    // 从而将其视为 2001:db8::/65
    WriteRules({"2001:db8::8000/65"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 如果 canonicalization 正确，2001:db8::1 应该匹配 (归一化后的网络段为 2001:db8::/65)
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
}

TEST_F(IpMatcherTest, Attack_MixedIPv4IPv6Massive)
{
    std::vector<std::string> rules;
    // 5000 条混合规则
    for (int i = 0; i < 5000; ++i)
    {
        // v4: 10.x.0.0/16
        // i%255 保证生成有效的 0-254 第二八位组
        rules.push_back("10." + std::to_string(i % 255) + ".0.0/16");

        // v6: 2001:db8:xxxx::/48
        char v6buf[100];
        snprintf(v6buf, sizeof(v6buf), "2001:db8:%x::/48", i % 65536);
        rules.push_back(std::string(v6buf));
    }

    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 测试随机样本 (正向)
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8:1::1", ec)));

    // 关键检查：验证 Merge 逻辑是否错误地将不连续网段合并
    // 我们使用了 i%255，所以 10.255.0.0/16 应该没有被添加
    EXPECT_FALSE(matcher.match(asio::ip::make_address("10.255.1.1", ec)));
}

TEST_F(IpMatcherTest, DoS_NestedSubnets)
{
    std::vector<std::string> rules;
    // 高度嵌套子网攻击：10.0.0.0/1, /2, ... /32
    // 如果 merge 算法是 O(N^2) 或者逻辑处理不当，可能导致性能爆炸或逻辑错误
    for (int i = 1; i <= 32; ++i)
    {
        rules.push_back("10.0.0.0/" + std::to_string(i));
    }
    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // 应该匹配最精细的规则
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.0.0.1", ec)));
    // 10.128.0.1 应该被 /1 匹配
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.128.0.1", ec)));
}
