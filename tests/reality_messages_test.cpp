#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include <string>
#include "reality_messages.h"

using namespace reality;

TEST(RealityMessagesTest, RecordHeader)
{
    auto header = write_record_header(0x16, 0x1234);
    ASSERT_EQ(header.size(), 5);
    EXPECT_EQ(header[0], 0x16);
    EXPECT_EQ(header[1], 0x03);
    EXPECT_EQ(header[2], 0x03);
    EXPECT_EQ(header[3], 0x12);
    EXPECT_EQ(header[4], 0x34);
}

TEST(RealityMessagesTest, ServerHello_RoundTrip)
{
    std::vector<uint8_t> random(32, 0xAA);
    std::vector<uint8_t> session_id(32, 0xBB);
    uint16_t cipher = 0x1301;
    std::vector<uint8_t> pubkey(32, 0xCC);

    auto sh = construct_server_hello(random, session_id, cipher, pubkey);

    auto extracted_cipher = extract_cipher_suite_from_server_hello(sh);
    ASSERT_TRUE(extracted_cipher.has_value());
    EXPECT_EQ(*extracted_cipher, cipher);

    auto extracted_pub = extract_server_public_key(sh);
    EXPECT_EQ(extracted_pub, pubkey);
}

TEST(RealityMessagesTest, EncryptedExtensions_ALPN)
{
    std::string alpn = "h2";
    auto msg = construct_encrypted_extensions(alpn);

    auto extracted_alpn = extract_alpn_from_encrypted_extensions(msg);
    if (!extracted_alpn.has_value())
    {
        std::cout << "Msg Hex: ";
        for (auto b : msg) printf("%02X ", b);
        std::cout << "\n";
    }
    ASSERT_TRUE(extracted_alpn.has_value());
    EXPECT_EQ(*extracted_alpn, alpn);
}

TEST(RealityMessagesTest, EncryptedExtensions_NoALPN)
{
    auto msg = construct_encrypted_extensions("");
    auto extracted_alpn = extract_alpn_from_encrypted_extensions(msg);

    EXPECT_FALSE(extracted_alpn.has_value());
}

TEST(RealityMessagesTest, ServerHello_Invalid)
{
    std::vector<uint8_t> short_buf(10, 0x00);
    EXPECT_FALSE(extract_cipher_suite_from_server_hello(short_buf).has_value());
    EXPECT_TRUE(extract_server_public_key(short_buf).empty());
}

TEST(RealityMessagesTest, ClientHelloBuilder_Firefox)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Firefox_120);
    std::vector<uint8_t> session_id(32, 0xEE);
    std::vector<uint8_t> random(32, 0xAA);
    std::vector<uint8_t> pubkey(32, 0xBB);
    std::string host = "example.com";

    auto ch = ClientHelloBuilder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);

    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, ClientHelloBuilder_Chrome)
{
    auto spec = FingerprintFactory::Get(FingerprintType::Chrome_120);
    std::vector<uint8_t> session_id(32, 0xEE);
    std::vector<uint8_t> random(32, 0xAA);
    std::vector<uint8_t> pubkey(32, 0xBB);
    std::string host = "google.com";

    auto ch = ClientHelloBuilder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);
    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, ExtractServerPublicKey_NoKeyShare)
{
    std::vector<uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    std::vector<uint8_t> random(32, 0xAA);
    message_builder::push_bytes(hello, random);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0);

    message_builder::push_u16(hello, 0);

    size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, hello.size());
    message_builder::push_bytes(record, hello);

    auto key = extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, ExtractServerPublicKey_MalformedKeyShare)
{
    std::vector<uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    std::vector<uint8_t> random(32, 0xAA);
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

    size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, hello.size());
    message_builder::push_bytes(record, hello);

    auto key = extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, CipherSuite_Short)
{
    std::vector<uint8_t> buf = {0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0C, 0x03, 0x03};

    EXPECT_FALSE(extract_cipher_suite_from_server_hello(buf).has_value());
}

TEST(RealityMessagesTest, ExtractALPN_Malformed)
{
    std::vector<uint8_t> msg = {0x08, 0x00, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32};

    std::vector<uint8_t> bad_msg;
    bad_msg.push_back(0x08);
    bad_msg.push_back(0);
    bad_msg.push_back(0);
    bad_msg.push_back(10);
    bad_msg.push_back(0);
    bad_msg.push_back(50);

    EXPECT_FALSE(extract_alpn_from_encrypted_extensions(bad_msg).has_value());
}
