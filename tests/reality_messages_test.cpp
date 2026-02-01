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
    EXPECT_EQ(header[2], 0x03);    // VER_1_2 is 0x0303
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

    // Test extraction
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
    // Should be nullopt or empty?
    // construct_encrypted_extensions with empty ALPN adds no ALPN extension.
    // extract_alpn... returns nullopt if not found.
    EXPECT_FALSE(extracted_alpn.has_value());
}

TEST(RealityMessagesTest, ServerHello_Invalid)
{
    std::vector<uint8_t> short_buf(10, 0x00);
    EXPECT_FALSE(extract_cipher_suite_from_server_hello(short_buf).has_value());
    EXPECT_TRUE(extract_server_public_key(short_buf).empty());
}
