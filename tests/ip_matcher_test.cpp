#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>
#include "ip_matcher.h"

class IpMatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a temporary file name
        rule_file_ = "temp_test_rules.txt";
    }

    void TearDown() override {
        // Remove the file if it exists
        std::remove(rule_file_.c_str());
    }

    void WriteRules(const std::vector<std::string>& rules) {
        std::ofstream f(rule_file_);
        for (const auto& rule : rules) {
            f << rule << "\n";
        }
        f.close();
    }

    std::string rule_file_;
};

TEST_F(IpMatcherTest, MatchIPv4_Basic) {
    WriteRules({
        "192.168.1.0/24",
        "10.0.0.0/8"
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    // Positive matches
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.255", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("10.255.255.255", ec)));

    // Negative matches
    EXPECT_FALSE(matcher.match(asio::ip::make_address("192.168.2.1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("11.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_Basic) {
    WriteRules({
        "2001:db8::/32",         // Documentation range
        "fe80::/10",             // Link-local
        "::1/128"                // Localhost
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
    EXPECT_FALSE(matcher.match(asio::ip::make_address("fec0::1", ec))); // Outside /10

    // ::1/128
    EXPECT_TRUE(matcher.match(asio::ip::make_address("::1", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("::2", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_ComplexMasks) {
    WriteRules({
        "2400:cb00::/32",
        "2606:4700:4700::/96"   // Cloudflare DNS range example
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2400:cb00:1234::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2606:4700:4700::1111", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("2606:4700:4700:1::1", ec))); // Outside /96
}

TEST_F(IpMatcherTest, EdgeCases_Optimization) {
    // Overlapping and adjacent rules should be optimized correctly
    WriteRules({
        "192.168.1.0/24",
        "192.168.1.0/25",   // Subset of previous
        "192.168.2.0/24",   // Adjacent
        "2001:db8::/32",
        "2001:db8:8000::/33" // Subset IPv6
    });

    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));
    // Implementation note: optimization logic merges these. 
    // We strictly test if the match result is correct.

    asio::error_code ec;
    // 192.168.1.x and 192.168.2.x should both match
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.100", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.1.200", ec))); // Was in /24 but not /25
    EXPECT_TRUE(matcher.match(asio::ip::make_address("192.168.2.50", ec)));
    EXPECT_FALSE(matcher.match(asio::ip::make_address("192.168.3.1", ec)));

    // IPv6 subset check
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8:8000::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("2001:db8::1", ec)));
}

TEST_F(IpMatcherTest, EdgeCases_InvalidInputs) {
    WriteRules({
        "1.2.3.4/24",
        "invalid_ip",
        "999.999.999.999/24", // Invalid IP
        "10.0.0.1/33",        // Invalid prefix v4
        "fe80::1/129",        // Invalid prefix v6
        "# Comments should be ignored",
        "   ",                // Empty lines
        "8.8.8.8/32"
    });

    mux::ip_matcher matcher;
    // Load should typically return true even if some lines fail, 
    // or false if file access fails. The current implementation logs warnings but continues.
    // Based on code: returns true unless file open fails.
    ASSERT_TRUE(matcher.load(rule_file_));

    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("1.2.3.10", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("8.8.8.8", ec)));
    
    // Invalid rules should not have been added
    // 10.0.0.1 was invalid prefix, should not match
    EXPECT_FALSE(matcher.match(asio::ip::make_address("10.0.0.1", ec)));
}

TEST_F(IpMatcherTest, MatchIPv4_MatchAll) {
    WriteRules({ "0.0.0.0/0" });
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));
    
    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("1.1.1.1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("255.255.255.255", ec)));
}

TEST_F(IpMatcherTest, MatchIPv6_MatchAll) {
    WriteRules({ "::/0" });
    mux::ip_matcher matcher;
    ASSERT_TRUE(matcher.load(rule_file_));
    
    asio::error_code ec;
    EXPECT_TRUE(matcher.match(asio::ip::make_address("fe80::1", ec)));
    EXPECT_TRUE(matcher.match(asio::ip::make_address("::1", ec)));
}
