#include <vector>
#include <string>
#include <cstdint>

#include <gtest/gtest.h>
#include <boost/asio/ip/address.hpp>

#include "protocol.h"

TEST(SocksCodecTest, NormalizeIP)
{
    const auto v4 = boost::asio::ip::make_address("1.2.3.4");
    EXPECT_EQ(socks_codec::normalize_ip_address(v4), v4);

    const auto v6 = boost::asio::ip::make_address("2001:db8::1");
    EXPECT_EQ(socks_codec::normalize_ip_address(v6), v6);

    const auto mapped = boost::asio::ip::make_address("::ffff:192.168.1.1");
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

    EXPECT_EQ(boost::asio::ip::make_address(output.addr), boost::asio::ip::make_address(input.addr));
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

TEST(SocksCodecTest, UDPHeaderRoundTripTooLongDomainTruncatesTo255Bytes)
{
    socks_udp_header input;
    input.frag = 0;
    input.addr = std::string(300, 'a');
    input.port = 53;

    const auto buffer = socks_codec::encode_udp_header(input);

    ASSERT_EQ(buffer[3], socks::kAtypDomain);
    ASSERT_EQ(buffer[4], 0xFF);
    ASSERT_EQ(buffer.size(), 262U);

    socks_udp_header output;
    const bool success = socks_codec::decode_udp_header(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.frag, input.frag);
    EXPECT_EQ(output.addr, std::string(255, 'a'));
    EXPECT_EQ(output.port, input.port);
}

TEST(SocksCodecTest, DecodeTooShort)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeRejectsNonZeroReservedBytes)
{
    const std::vector<std::uint8_t> data = {0x00, 0x01, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50};
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

TEST(SocksCodecTest, DecodeDomainEmptyRejected)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}

TEST(SocksCodecTest, DecodeDomainContainsNulRejected)
{
    const std::vector<std::uint8_t> data = {0x00, 0x00, 0x00, 0x03, 0x04, 't', 'e', 0x00, 't', 0x00, 0x50};
    socks_udp_header out;
    EXPECT_FALSE(socks_codec::decode_udp_header(data.data(), data.size(), out));
}
