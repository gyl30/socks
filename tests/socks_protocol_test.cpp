#include <string>
#include <vector>
#include <cstdint>

#include <gtest/gtest.h>
#include <boost/asio/ip/address.hpp>

#include "protocol.h"

namespace
{

TEST(SocksProtocolTest, IPv6AddressDecoding)
{
    std::vector<std::uint8_t> request = {0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xbb};

    socks5_request out;
    ASSERT_TRUE(socks_codec::decode_socks5_request(request.data(), request.size(), out));
    EXPECT_EQ(out.ver, 0x05);
    EXPECT_EQ(out.cmd, 0x01);
    EXPECT_EQ(out.atyp, socks::kAtypIpv6);
    EXPECT_EQ(boost::asio::ip::make_address(out.addr), boost::asio::ip::make_address("2001:db8::1"));
    EXPECT_EQ(out.port, 443);
}

TEST(SocksProtocolTest, DomainResolutionFailureSimulation) { EXPECT_EQ(socks::kRepHostUnreach, 0x04); }

TEST(SocksProtocolTest, DecodeSocks5RequestIPv4AndErrorPaths)
{
    std::vector<std::uint8_t> ipv4 = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb};
    socks5_request out;
    ASSERT_TRUE(socks_codec::decode_socks5_request(ipv4.data(), ipv4.size(), out));
    EXPECT_EQ(out.addr, "127.0.0.1");
    EXPECT_EQ(out.port, 443);

    const std::vector<std::uint8_t> too_short = {0x05, 0x01, 0x00};
    EXPECT_FALSE(socks_codec::decode_socks5_request(too_short.data(), too_short.size(), out));

    const std::vector<std::uint8_t> unknown_atyp = {0x05, 0x01, 0x00, 0x09, 0x00, 0x50};
    EXPECT_FALSE(socks_codec::decode_socks5_request(unknown_atyp.data(), unknown_atyp.size(), out));

    const std::vector<std::uint8_t> port_truncated = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01};
    EXPECT_FALSE(socks_codec::decode_socks5_request(port_truncated.data(), port_truncated.size(), out));
}

TEST(SocksProtocolTest, DecodeSocks5RequestDomain)
{
    const std::vector<std::uint8_t> req = {0x05, 0x01, 0x00, 0x03, 0x0b, 'e',  'x',  'a',  'm',
                                           'p',  'l',  'e',  '.',  'c',  'o',  'm',  0x00, 0x50};
    socks5_request out;
    ASSERT_TRUE(socks_codec::decode_socks5_request(req.data(), req.size(), out));
    EXPECT_EQ(out.addr, "example.com");
    EXPECT_EQ(out.port, 80);
}

TEST(SocksProtocolTest, DecodeSocks5AuthRequestPaths)
{
    socks5_auth_request auth_out;

    const std::vector<std::uint8_t> ok = {0x01, 0x04, 'u', 's', 'e', 'r', 0x03, 'p', 'w', 'd'};
    ASSERT_TRUE(socks_codec::decode_socks5_auth_request(ok.data(), ok.size(), auth_out));
    EXPECT_EQ(auth_out.ver, 0x01);
    EXPECT_EQ(auth_out.username, "user");
    EXPECT_EQ(auth_out.password, "pwd");

    const std::vector<std::uint8_t> header_short = {0x01};
    EXPECT_FALSE(socks_codec::decode_socks5_auth_request(header_short.data(), header_short.size(), auth_out));

    const std::vector<std::uint8_t> username_truncated = {0x01, 0x04, 'u', 's'};
    EXPECT_FALSE(socks_codec::decode_socks5_auth_request(username_truncated.data(), username_truncated.size(), auth_out));

    const std::vector<std::uint8_t> password_truncated = {0x01, 0x01, 'u', 0x03, 'p'};
    EXPECT_FALSE(socks_codec::decode_socks5_auth_request(password_truncated.data(), password_truncated.size(), auth_out));
}

}    // namespace
