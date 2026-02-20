// NOLINTBEGIN(misc-include-cleaner)
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>

#include <gtest/gtest.h>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address.hpp>

#include "ip_matcher.h"

class IpMatcherTest : public ::testing::Test
{
   protected:
    void SetUp() override
    {
        const testing::TestInfo* const test_info = testing::UnitTest::GetInstance()->current_test_info();
        rule_file_ = std::string("/tmp/temp_test_rules_") + test_info->name() + ".txt";
    }

    void TearDown() override { std::remove(rule_file_.c_str()); }

    void WriteRules(const std::vector<std::string>& rules)
    {
        std::ofstream f(rule_file_);
        for (const auto& rule : rules)
        {
            f << rule << "\n";
        }
        f.close();
    }

    [[nodiscard]] const std::string& rule_file() const { return rule_file_; }

   private:
    std::string rule_file_;
};

TEST_F(IpMatcherTest, MatchIPv4Basic)
{
    WriteRules({"192.168.1.0/24", "10.0.0.0/8"});

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.1.255", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.255.255.255", ec)));

    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("192.168.2.1", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("11.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6Basic)
{
    WriteRules({"2001:db8::/32", "fe80::/10", "::1/128"});

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("2001:db9::1", ec)));

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("fe80::1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("febf::1", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("fec0::1", ec)));

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("::1", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("::2", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6ComplexMasks)
{
    WriteRules({"2400:cb00::/32", "2606:4700:4700::/96"});

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2400:cb00:1234::1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2606:4700:4700::1111", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("2606:4700:4700:1::1", ec)));
}

TEST_F(IpMatcherTest, EdgeCasesOptimization)
{
    WriteRules({"192.168.1.0/24", "192.168.1.0/25", "192.168.2.0/24", "2001:db8::/32", "2001:db8:8000::/33"});

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.1.100", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.1.200", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.2.50", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("192.168.3.1", ec)));

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8:8000::1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
}

TEST_F(IpMatcherTest, EdgeCasesInvalidInputs)
{
    WriteRules({"1.2.3.4/24", "invalid_ip", "999.999.999.999/24", "10.0.0.1/33", "fe80::1/129", "# Comments should be ignored", "   ", "8.8.8.8/32"});

    mux::ip_matcher matcher;

    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("1.2.3.10", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("8.8.8.8", ec)));

    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("10.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv4MatchAll)
{
    WriteRules({"0.0.0.0/0"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("1.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("255.255.255.255", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6MatchAll)
{
    WriteRules({"::/0"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("fe80::1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("::1", ec)));
}

TEST_F(IpMatcherTest, PrefixWithSpaces)
{
    WriteRules({"192.168.1.0/24 ", "192.168.2.0/ 24"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("192.168.2.1", ec)));
}

TEST_F(IpMatcherTest, PrefixLeadingZero)
{
    WriteRules({"10.0.0.0/08"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.1.1.1", ec)));
}

TEST_F(IpMatcherTest, PrefixOutOfRange)
{
    WriteRules({"192.168.1.0/999"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("192.168.1.1", ec)));
}

TEST_F(IpMatcherTest, IPv6Exact128BitBoundary)
{
    WriteRules({"2001:db8::1/128"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("2001:db8::2", ec)));
}

TEST_F(IpMatcherTest, LargeRuleSet)
{
    std::vector<std::string> rules;

    for (int i = 0; i < 1000; ++i)
    {
        const int b2 = (i / 256) % 256;
        const int b3 = i % 256;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "10.%d.%d.0/24", b2, b3);
        rules.emplace_back(buf);
    }
    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.0.0.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.0.255.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.1.0.1", ec)));

    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("10.5.0.1", ec)));
}

TEST_F(IpMatcherTest, IPv6OddBitPrefix)
{
    WriteRules({"2001:db8::/65"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("2001:db8:0:0:8000::1", ec)));
}

TEST_F(IpMatcherTest, IPv6NonCanonicalNetwork)
{
    WriteRules({"2001:db8::8000/65"});
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
}

TEST_F(IpMatcherTest, AttackMixedIPv4IPv6Massive)
{
    std::vector<std::string> rules;

    for (int i = 0; i < 5000; ++i)
    {
        rules.push_back("10." + std::to_string(i % 255) + ".0.0/16");

        char v6buf[100];
        std::snprintf(v6buf, sizeof(v6buf), "2001:db8:%x::/48", i % 65536);
        rules.emplace_back(v6buf);
    }

    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8:1::1", ec)));

    EXPECT_FALSE(matcher.match(boost::asio::ip::make_address("10.255.1.1", ec)));
}

TEST_F(IpMatcherTest, DoSNestedSubnets)
{
    std::vector<std::string> rules;

    for (int i = 1; i <= 32; ++i)
    {
        rules.push_back("10.0.0.0/" + std::to_string(i));
    }
    WriteRules(rules);

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.0.0.1", ec)));

    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.128.0.1", ec)));
}

TEST_F(IpMatcherTest, CarriageReturnAndPrefixParsingBranches)
{
    {
        std::ofstream f(rule_file(), std::ios::binary);
        f << "10.10.0.0/16\r\n";
        f << "10.20.0.0/abc\r\n";
        f << "   /24\r\n";
        f << "0.0.0.0/0\r\n";
        f << "10.30.0.0/8\r\n";
        f << "::/0\r\n";
        f << "2001:db8::/32\r\n";
    }

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file()));

    boost::system::error_code ec;
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("10.10.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("11.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(boost::asio::ip::make_address("2001:db8::1", ec)));
}
// NOLINTEND(misc-include-cleaner)
