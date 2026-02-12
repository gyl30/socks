#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "cert_manager.h"
#include "reality_messages.h"

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

    auto entry_survived = manager.get_certificate("sni5");
    EXPECT_TRUE(entry_survived.has_value());
}

TEST(CertManagerTest, LruEvictionRespectsRecentUse)
{
    cert_manager manager(3);
    server_fingerprint fp;
    std::vector<uint8_t> cert = {0x01};

    manager.set_certificate("sni0", cert, fp, "trace");
    manager.set_certificate("sni1", cert, fp, "trace");
    manager.set_certificate("sni2", cert, fp, "trace");

    ASSERT_TRUE(manager.get_certificate("sni0").has_value());
    manager.set_certificate("sni3", cert, fp, "trace");

    EXPECT_FALSE(manager.get_certificate("sni1").has_value());
    EXPECT_TRUE(manager.get_certificate("sni0").has_value());
    EXPECT_TRUE(manager.get_certificate("sni2").has_value());
    EXPECT_TRUE(manager.get_certificate("sni3").has_value());
}

TEST(CertManagerTest, UpdateExistingEntryDoesNotEvictOthers)
{
    cert_manager manager(2);
    server_fingerprint fp;
    std::vector<uint8_t> cert1 = {0x01};
    std::vector<uint8_t> cert2 = {0x02};

    manager.set_certificate("a", cert1, fp, "trace");
    manager.set_certificate("b", cert1, fp, "trace");
    manager.set_certificate("a", cert2, fp, "trace");

    auto entry_a = manager.get_certificate("a");
    ASSERT_TRUE(entry_a.has_value());
    EXPECT_EQ(entry_a->cert_msg, cert2);
    EXPECT_TRUE(manager.get_certificate("b").has_value());
}

}    // namespace reality
