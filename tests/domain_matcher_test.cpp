#include <gtest/gtest.h>
#include "domain_matcher.h"
#include <fstream>
#include <filesystem>

using namespace mux;

class DomainMatcherTest : public ::testing::Test
{
   protected:
    domain_matcher matcher_;
};

TEST_F(DomainMatcherTest, BasicMatch)
{
    matcher_.add("google.com");
    EXPECT_TRUE(matcher_.match("google.com"));
    EXPECT_TRUE(matcher_.match("www.google.com"));
    EXPECT_TRUE(matcher_.match("mail.google.com"));
    EXPECT_FALSE(matcher_.match("google.com.cn"));
    EXPECT_FALSE(matcher_.match("agoogle.com"));
}

TEST_F(DomainMatcherTest, CaseInsensitive)
{
    matcher_.add("Google.Com");
    EXPECT_TRUE(matcher_.match("GOOGLE.COM"));
    EXPECT_TRUE(matcher_.match("www.google.com"));
}

TEST_F(DomainMatcherTest, TrailingDot)
{
    matcher_.add("example.com.");
    EXPECT_TRUE(matcher_.match("example.com"));
    EXPECT_TRUE(matcher_.match("example.com."));

    matcher_.add("another.com");
    EXPECT_TRUE(matcher_.match("another.com."));
}

TEST_F(DomainMatcherTest, EmptyDomain)
{
    matcher_.add("");
    EXPECT_FALSE(matcher_.match(""));
    EXPECT_FALSE(matcher_.match("any.com"));
}

TEST_F(DomainMatcherTest, SuffixMatch)
{
    matcher_.add("com.cn");
    EXPECT_TRUE(matcher_.match("test.com.cn"));
    EXPECT_TRUE(matcher_.match("sub.test.com.cn"));
    EXPECT_FALSE(matcher_.match("mycom.cn"));
}

TEST_F(DomainMatcherTest, LoadFromFile)
{
    std::string filename = "test_domains.txt";
    {
        std::ofstream of(filename);
        of << "  # comment line  " << std::endl;
        of << "google.com  " << std::endl;
        of << "  NETFLIX.COM # another comment" << std::endl;
        of << "  " << std::endl;
        of << "apple.com.  " << std::endl;
    }

    EXPECT_TRUE(matcher_.load(filename));
    EXPECT_TRUE(matcher_.match("google.com"));
    EXPECT_TRUE(matcher_.match("www.netflix.com"));
    EXPECT_TRUE(matcher_.match("apple.com"));

    std::filesystem::remove(filename);
}

TEST_F(DomainMatcherTest, LoadNonExistentFile) { EXPECT_FALSE(matcher_.load("non_existent_file.txt")); }

TEST_F(DomainMatcherTest, MatchWithEmptyOrDotOnly)
{
    EXPECT_FALSE(matcher_.match(""));

    EXPECT_FALSE(matcher_.match("."));
}
