#include <string>
#include <fstream>
#include <filesystem>

#include <gtest/gtest.h>

#include "domain_matcher.h"

using mux::domain_matcher;

class domain_matcher_test : public ::testing::Test
{
   protected:
    domain_matcher& matcher() { return matcher_; }

   private:
    domain_matcher matcher_;
};

TEST_F(domain_matcher_test, BasicMatch)
{
    matcher().add("google.com");
    EXPECT_TRUE(matcher().match("google.com"));
    EXPECT_TRUE(matcher().match("www.google.com"));
    EXPECT_TRUE(matcher().match("mail.google.com"));
    EXPECT_FALSE(matcher().match("google.com.cn"));
    EXPECT_FALSE(matcher().match("agoogle.com"));
}

TEST_F(domain_matcher_test, CaseInsensitive)
{
    matcher().add("Google.Com");
    EXPECT_TRUE(matcher().match("GOOGLE.COM"));
    EXPECT_TRUE(matcher().match("www.google.com"));
}

TEST_F(domain_matcher_test, TrailingDot)
{
    matcher().add("example.com.");
    EXPECT_TRUE(matcher().match("example.com"));
    EXPECT_TRUE(matcher().match("example.com."));

    matcher().add("another.com");
    EXPECT_TRUE(matcher().match("another.com."));
}

TEST_F(domain_matcher_test, EmptyDomain)
{
    matcher().add("");
    EXPECT_FALSE(matcher().match(""));
    EXPECT_FALSE(matcher().match("any.com"));
}

TEST_F(domain_matcher_test, SuffixMatch)
{
    matcher().add("com.cn");
    EXPECT_TRUE(matcher().match("test.com.cn"));
    EXPECT_TRUE(matcher().match("sub.test.com.cn"));
    EXPECT_FALSE(matcher().match("mycom.cn"));
}

TEST_F(domain_matcher_test, LoadFromFile)
{
    const std::string filename = "test_domains.txt";
    {
        std::ofstream of(filename);
        of << "  # comment line  \n";
        of << "google.com  \n";
        of << "  NETFLIX.COM # another comment\n";
        of << "  \n";
        of << "apple.com.  \n";
    }

    EXPECT_TRUE(matcher().load(filename));
    EXPECT_TRUE(matcher().match("google.com"));
    EXPECT_TRUE(matcher().match("www.netflix.com"));
    EXPECT_TRUE(matcher().match("apple.com"));

    std::filesystem::remove(filename);
}

TEST_F(domain_matcher_test, LoadNonExistentFile) { EXPECT_FALSE(matcher().load("non_existent_file.txt")); }

TEST_F(domain_matcher_test, MatchWithEmptyOrDotOnly)
{
    EXPECT_FALSE(matcher().match(""));

    EXPECT_FALSE(matcher().match("."));
}
