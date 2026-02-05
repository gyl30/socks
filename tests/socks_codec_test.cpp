#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/ip/address.hpp>

#include "protocol.h"

TEST(SocksCodecTest, NormalizeIP)
{
    const auto v4 = asio::ip::make_address("1.2.3.4");
    EXPECT_EQ(socks_codec::normalize_ip_address(v4), v4);

    const auto v6 = asio::ip::make_address("2001:db8::1");
    EXPECT_EQ(socks_codec::normalize_ip_address(v6), v6);

    const auto mapped = asio::ip::make_address("::ffff:192.168.1.1");
    const auto normalized = socks_codec::normalize_ip_address(mapped);
    EXPECT_TRUE(normalized.is_v4());
    EXPECT_EQ(normalized.to_string(), "192.168.1.1");
}

TEST(SocksCodecTest, UDPHeaderRoundTripIPv4)
{
    socks_udp_header input;
    input.frag = 0;
    input.addr = "192.168.0.1";
    input.port = 12345;

    const auto buffer = socks_codec::encode_udp_header(input);

    socks_udp_header output;
    const bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.frag, input.frag);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, UDPHeaderRoundTripIPv6)
{
    socks_udp_header input;
    input.frag = 1;
    input.addr = "2001:db8::1";
    input.port = 80;

    const auto buffer = socks_codec::encode_udp_header(input);

    socks_udp_header output;
    const bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.frag, input.frag);

    EXPECT_EQ(asio::ip::make_address(output.addr), asio::ip::make_address(input.addr));
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, UDPHeaderRoundTripDomain)
{
    socks_udp_header input;
    input.frag = 0;
    input.addr = "example.com";
    input.port = 443;

    const auto buffer = socks_codec::encode_udp_header(input);

    EXPECT_EQ(buffer.size(), 18);
    EXPECT_EQ(buffer[3], 0x03);

    socks_udp_header output;
    const bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, DecodeTooShort)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeInvalidATYP)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0xFF, 0x00, 0x00};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeTruncatedIPv4)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x01, 0x7F, 0x00};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeTruncatedIPv6)
{
    std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x04};
    data.insert(data.end(), 10, 0x00);
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeTruncatedDomainLen)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x03};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeTruncatedDomainBody)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x05, 'a', 'b', 'c'};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeDomainEmpty)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50};
    socks_udp_header out;
    EXPECT_TRUE(socks_codec::decode_udp_header(data.data(), data.size(), out));
    EXPECT_EQ(out.addr, "");
    EXPECT_EQ(out.port, 80);
}
