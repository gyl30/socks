#include <gtest/gtest.h>
#include "cert_manager.h"
#include "reality_messages.h"
#include <vector>
#include <string>

namespace reality
{

TEST(CertManagerTest, BasicCache)
{
    cert_manager manager;
    server_fingerprint fp;
    fp.alpn = "h2";
    fp.cipher_suite = 0x1301;

    std::vector<uint8_t> cert = {0x01, 0x02};
    manager.set_certificate("example.com", cert, fp, "trace-1");

    auto entry = manager.get_certificate("example.com");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->cert_msg, cert);
    EXPECT_EQ(entry->fingerprint.alpn, "h2");
}

TEST(CertManagerTest, DefaultSNI)
{
    cert_manager manager;
    server_fingerprint fp;
    std::vector<uint8_t> cert = {0x01};

    manager.set_certificate("", cert, fp, "trace-2");

    auto entry = manager.get_certificate("anything.com");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->cert_msg, cert);
}

TEST(CertManagerTest, CacheEviction)
{
    cert_manager manager;
    server_fingerprint fp;
    std::vector<uint8_t> cert = {0x01};

    for (int i = 0; i < 105; ++i)
    {
        manager.set_certificate("sni" + std::to_string(i), cert, fp, "trace");
    }

    auto entry = manager.get_certificate("sni0");
    EXPECT_FALSE(entry.has_value());

    auto entry_recent = manager.get_certificate("sni104");
    EXPECT_TRUE(entry_recent.has_value());
}

}    // namespace reality
