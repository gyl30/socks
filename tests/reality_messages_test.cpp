#include <array>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <system_error>

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto_util.h"
#include "reality_core.h"
#include "reality_messages.h"

using reality::message_builder;
namespace tls_consts = reality::tls_consts;

TEST(RealityMessagesTest, RecordHeader)
{
    const auto header = reality::write_record_header(0x16, 0x1234);
    ASSERT_EQ(header.size(), 5);
    EXPECT_EQ(header[0], 0x16);
    EXPECT_EQ(header[1], 0x03);
    EXPECT_EQ(header[2], 0x03);
    EXPECT_EQ(header[3], 0x12);
    EXPECT_EQ(header[4], 0x34);
}

TEST(RealityMessagesTest, ServerHelloRoundTrip)
{
    const std::vector<uint8_t> random(32, 0xAA);
    const std::vector<uint8_t> session_id(32, 0xBB);
    const uint16_t cipher = 0x1301;
    const std::vector<uint8_t> pubkey(32, 0xCC);

    auto sh = reality::construct_server_hello(random, session_id, cipher, pubkey);

    auto extracted_cipher = reality::extract_cipher_suite_from_server_hello(sh);
    ASSERT_TRUE(extracted_cipher.has_value());
    EXPECT_EQ(*extracted_cipher, cipher);

    auto extracted_pub = reality::extract_server_public_key(sh);
    EXPECT_EQ(extracted_pub, pubkey);
}

TEST(RealityMessagesTest, EncryptedExtensionsALPN)
{
    const std::string alpn = "h2";
    auto msg = reality::construct_encrypted_extensions(alpn);

    auto extracted_alpn = reality::extract_alpn_from_encrypted_extensions(msg);
    if (!extracted_alpn.has_value())
    {
        std::cout << "Msg Hex: ";
        for (const auto b : msg)
        {
            printf("%02X ", b);
        }
        std::cout << "\n";
    }
    ASSERT_TRUE(extracted_alpn.has_value());
    EXPECT_EQ(*extracted_alpn, alpn);
}

TEST(RealityMessagesTest, EncryptedExtensionsNoALPN)
{
    auto msg = reality::construct_encrypted_extensions("");
    auto extracted_alpn = reality::extract_alpn_from_encrypted_extensions(msg);

    EXPECT_FALSE(extracted_alpn.has_value());
}

TEST(RealityMessagesTest, ServerHelloInvalid)
{
    const std::vector<uint8_t> short_buf(10, 0x00);
    EXPECT_FALSE(reality::extract_cipher_suite_from_server_hello(short_buf).has_value());
    EXPECT_TRUE(reality::extract_server_public_key(short_buf).empty());
}

TEST(RealityMessagesTest, ClientHelloBuilderFirefox)
{
    auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Firefox_120);
    const std::vector<uint8_t> session_id(32, 0xEE);
    const std::vector<uint8_t> random(32, 0xAA);
    const std::vector<uint8_t> pubkey(32, 0xBB);
    const std::string host = "example.com";

    auto ch = reality::ClientHelloBuilder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);

    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, ClientHelloBuilderChrome)
{
    auto spec = reality::FingerprintFactory::Get(reality::FingerprintType::Chrome_120);
    const std::vector<uint8_t> session_id(32, 0xEE);
    const std::vector<uint8_t> random(32, 0xAA);
    const std::vector<uint8_t> pubkey(32, 0xBB);
    const std::string host = "google.com";

    auto ch = reality::ClientHelloBuilder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);
    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, ExtractServerPublicKeyNoKeyShare)
{
    std::vector<uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    const std::vector<uint8_t> random(32, 0xAA);
    message_builder::push_bytes(hello, random);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0);

    message_builder::push_u16(hello, 0);

    const size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, hello.size());
    message_builder::push_bytes(record, hello);

    auto key = reality::extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, ExtractServerPublicKeyMalformedKeyShare)
{
    std::vector<uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    const std::vector<uint8_t> random(32, 0xAA);
    message_builder::push_bytes(hello, random);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0);

    std::vector<uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::KEY_SHARE);
    message_builder::push_u16(extensions, 2);
    message_builder::push_u16(extensions, 0x001d);

    message_builder::push_u16(hello, extensions.size());
    message_builder::push_bytes(hello, extensions);

    const size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, hello.size());
    message_builder::push_bytes(record, hello);

    auto key = reality::extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, CipherSuiteShort)
{
    const std::vector<uint8_t> buf = {0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0C, 0x03, 0x03};

    EXPECT_FALSE(reality::extract_cipher_suite_from_server_hello(buf).has_value());
}

TEST(RealityMessagesTest, ExtractALPNMalformed)
{
    const std::vector<uint8_t> msg = {0x08, 0x00, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32};

    std::vector<uint8_t> bad_msg;
    bad_msg.push_back(0x08);
    bad_msg.push_back(0);
    bad_msg.push_back(0);
    bad_msg.push_back(10);
    bad_msg.push_back(0);
    bad_msg.push_back(50);

    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(bad_msg).has_value());
}

TEST(RealityMessagesTest, CertificateVerifyParseAndVerify)
{
    std::array<uint8_t, 32> priv{};
    ASSERT_EQ(RAND_bytes(priv.data(), static_cast<int>(priv.size())), 1);

    const reality::openssl_ptrs::evp_pkey_ptr priv_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size()));
    ASSERT_TRUE(priv_key);

    size_t pub_len = 32;
    std::vector<uint8_t> pub(pub_len);
    ASSERT_EQ(EVP_PKEY_get_raw_public_key(priv_key.get(), pub.data(), &pub_len), 1);

    const reality::openssl_ptrs::evp_pkey_ptr pub_key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub_len));
    ASSERT_TRUE(pub_key);

    const std::vector<uint8_t> handshake_hash(32, 0x11);
    auto cv = reality::construct_certificate_verify(priv_key.get(), handshake_hash);
    auto info = reality::parse_certificate_verify(cv);
    ASSERT_TRUE(info.has_value());

    std::error_code ec;
    if (info)
    {
        EXPECT_EQ(info->scheme, 0x0807);
        EXPECT_TRUE(reality::crypto_util::verify_tls13_signature(pub_key.get(), handshake_hash, info->signature, ec));
    }
    EXPECT_FALSE(ec);
}

TEST(RealityMessagesTest, CertificateVerifySchemeSupport)
{
    EXPECT_TRUE(reality::is_supported_certificate_verify_scheme(0x0807));
    EXPECT_FALSE(reality::is_supported_certificate_verify_scheme(0x0804));
}
