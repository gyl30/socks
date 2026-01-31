#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "protocol.h"
#include <asio.hpp>

// Test normalize_ip_address
TEST(SocksCodecTest, NormalizeIP) {
    // IPv4 remains same
    auto v4 = asio::ip::make_address("1.2.3.4");
    EXPECT_EQ(socks_codec::normalize_ip_address(v4), v4);

    // IPv6 remains same
    auto v6 = asio::ip::make_address("2001:db8::1");
    EXPECT_EQ(socks_codec::normalize_ip_address(v6), v6);

    // Mapped IPv4 should be converted to IPv4
    auto mapped = asio::ip::make_address("::ffff:192.168.1.1");
    auto normalized = socks_codec::normalize_ip_address(mapped);
    EXPECT_TRUE(normalized.is_v4());
    EXPECT_EQ(normalized.to_string(), "192.168.1.1");
}

// Test UDP Header Encoding/Decoding RoundTrip
TEST(SocksCodecTest, UDPHeader_RoundTrip_IPv4) {
    socks_udp_header input;
    input.frag = 0;
    input.addr = "192.168.0.1";
    input.port = 12345;

    auto buffer = socks_codec::encode_udp_header(input);

    socks_udp_header output;
    bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);
    
    ASSERT_TRUE(success);
    EXPECT_EQ(output.frag, input.frag);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, UDPHeader_RoundTrip_IPv6) {
    socks_udp_header input;
    input.frag = 1;
    input.addr = "2001:db8::1";
    input.port = 80;

    auto buffer = socks_codec::encode_udp_header(input);

    socks_udp_header output;
    bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);
    
    ASSERT_TRUE(success);
    EXPECT_EQ(output.frag, input.frag);
    // Note: asio might normalize string representation, so compare as address objects usually, 
    // but here test expects string consistency or normalized string
    EXPECT_EQ(asio::ip::make_address(output.addr), asio::ip::make_address(input.addr));
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, UDPHeader_RoundTrip_Domain) {
    socks_udp_header input;
    input.frag = 0;
    input.addr = "example.com";
    input.port = 443;

    auto buffer = socks_codec::encode_udp_header(input);
    
    // Manual check of encoding
    // 00 00 frag(00) ATYP(03) len(11) "example.com" port(2)
    // 4 + 1 + 11 + 2 = 18 bytes
    EXPECT_EQ(buffer.size(), 18);
    EXPECT_EQ(buffer[3], 0x03); // ATYP_DOMAIN

    socks_udp_header output;
    bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);
    
    ASSERT_TRUE(success);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
}

// Boundary & Failure Conditions

TEST(SocksCodecTest, Decode_TooShort) {
    std::vector<uint8_t> data = {0x00, 0x00, 0x00}; // Only 3 bytes
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_InvalidATYP) {
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0xFF, 0x00, 0x00}; // ATYP 0xFF
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_TruncatedIPv4) {
    // 00 00 00 01 (IPv4) + 2 bytes (truncated IP)
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x01, 0x7F, 0x00};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_TruncatedIPv6) {
    // 00 00 00 04 (IPv6) + 10 bytes (truncated IP)
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x04};
    data.insert(data.end(), 10, 0x00);
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_TruncatedDomainLen) {
    // 00 00 00 03 (Domain) - missing len byte
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x03};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_TruncatedDomainBody) {
    // 00 00 00 03 (Domain) + len(5) + "abc" (3 bytes, missing 2)
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b', 'c'};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, Decode_Domain_Empty) {
    // Empty domain is technically valid string-wise, let's see logic
    // len=0.
    std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50}; // port 80
    socks_udp_header out;
    EXPECT_TRUE(socks_codec::decode_udp_header(data.data(), data.size(), out));
    EXPECT_EQ(out.addr, "");
    EXPECT_EQ(out.port, 80);
}
