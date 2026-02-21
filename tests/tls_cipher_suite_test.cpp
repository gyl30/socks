
#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
}

#include "tls_cipher_suite.h"

TEST(TlsCipherSuiteTest, KnownTls13Suites)
{
    const auto suite_1301 = reality::select_tls13_suite(0x1301);
    ASSERT_TRUE(suite_1301.has_value());
    EXPECT_EQ(suite_1301->md, EVP_sha256());
    EXPECT_EQ(suite_1301->cipher, EVP_aes_128_gcm());

    const auto suite_1302 = reality::select_tls13_suite(0x1302);
    ASSERT_TRUE(suite_1302.has_value());
    EXPECT_EQ(suite_1302->md, EVP_sha384());
    EXPECT_EQ(suite_1302->cipher, EVP_aes_256_gcm());

    const auto suite_1303 = reality::select_tls13_suite(0x1303);
    ASSERT_TRUE(suite_1303.has_value());
    EXPECT_EQ(suite_1303->md, EVP_sha256());
    EXPECT_EQ(suite_1303->cipher, EVP_chacha20_poly1305());
}

TEST(TlsCipherSuiteTest, UnknownTls13SuiteRejected)
{
    const auto suite = reality::select_tls13_suite(0x1310);
    EXPECT_FALSE(suite.has_value());
}
