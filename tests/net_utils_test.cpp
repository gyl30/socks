#include <cerrno>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#endif

#include <gtest/gtest.h>

#include "net_utils.h"

namespace mux::net
{

TEST(net_utils_test, endpoint_from_sockaddr_ipv4)
{
    sockaddr_in addr4{};
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(1080);
    addr4.sin_addr.s_addr = htonl(0x7F000001U);

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr4, sizeof(addr4));

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(addr4));
    EXPECT_EQ(endpoint.address().to_string(), "127.0.0.1");
    EXPECT_EQ(endpoint.port(), 1080);
}

TEST(net_utils_test, endpoint_from_sockaddr_ipv6)
{
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(5353);
    addr6.sin6_addr = in6addr_loopback;

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr6, sizeof(addr6));

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(addr6));
    EXPECT_EQ(endpoint.address().to_string(), "::1");
    EXPECT_EQ(endpoint.port(), 5353);
}

TEST(net_utils_test, endpoint_from_sockaddr_ipv4_truncated_len)
{
    sockaddr_in addr4{};
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(1080);
    addr4.sin_addr.s_addr = htonl(0x7F000001U);

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr4, sizeof(addr4));

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(addr4) - 1U);
    EXPECT_TRUE(endpoint.address().is_unspecified());
    EXPECT_EQ(endpoint.port(), 0);
}

TEST(net_utils_test, endpoint_from_sockaddr_ipv6_truncated_len)
{
    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    addr6.sin6_port = htons(5353);
    addr6.sin6_addr = in6addr_loopback;

    sockaddr_storage storage{};
    std::memcpy(&storage, &addr6, sizeof(addr6));

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(addr6) - 1U);
    EXPECT_TRUE(endpoint.address().is_unspecified());
    EXPECT_EQ(endpoint.port(), 0);
}

TEST(net_utils_test, endpoint_from_sockaddr_unknown_family)
{
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(storage));
    EXPECT_TRUE(endpoint.address().is_unspecified());
    EXPECT_EQ(endpoint.port(), 0);
}

TEST(net_utils_test, set_socket_mark_zero_short_circuit)
{
    std::error_code ec = std::make_error_code(std::errc::invalid_argument);
    const bool ok = set_socket_mark(-1, 0, ec);
#ifdef __linux__
    EXPECT_TRUE(ok);
    EXPECT_FALSE(ec);
#else
    EXPECT_FALSE(ok);
    EXPECT_EQ(ec, std::make_error_code(std::errc::not_supported));
#endif
}

TEST(net_utils_test, set_socket_mark_invalid_fd)
{
    std::error_code ec;
    const bool ok = set_socket_mark(-1, 1, ec);
    EXPECT_FALSE(ok);
#ifdef __linux__
    EXPECT_EQ(ec.value(), EBADF);
#else
    EXPECT_EQ(ec, std::make_error_code(std::errc::not_supported));
#endif
}

TEST(net_utils_test, set_socket_transparent_invalid_fd)
{
    std::error_code ec;
    const bool ok = set_socket_transparent(-1, true, ec);
    EXPECT_FALSE(ok);
#ifdef __linux__
    EXPECT_EQ(ec.value(), EBADF);
#else
    EXPECT_EQ(ec, std::make_error_code(std::errc::not_supported));
#endif
}

TEST(net_utils_test, set_socket_recv_origdst_invalid_fd)
{
    std::error_code ec;
    const bool ok = set_socket_recv_origdst(-1, true, ec);
    EXPECT_FALSE(ok);
#ifdef __linux__
    EXPECT_EQ(ec.value(), EBADF);
#else
    EXPECT_EQ(ec, std::make_error_code(std::errc::not_supported));
#endif
}

TEST(net_utils_test, normalize_address_v4_mapped_v6)
{
    const auto mapped = asio::ip::make_address("::ffff:127.0.0.1");
    const auto normalized = normalize_address(mapped);

    EXPECT_TRUE(normalized.is_v4());
    EXPECT_EQ(normalized.to_string(), "127.0.0.1");
}

TEST(net_utils_test, parse_original_dst_no_control_message)
{
    msghdr msg{};
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;

    const auto parsed = parse_original_dst(msg);
    EXPECT_FALSE(parsed.has_value());
}

#ifdef __linux__
TEST(net_utils_test, parse_original_dst_ipv4_success)
{
    std::array<std::byte, CMSG_SPACE(sizeof(sockaddr_in))> control{};
    msghdr msg{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto* cm = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cm, nullptr);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_ORIGDSTADDR;
    cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(0x7F000002U);
    std::memcpy(CMSG_DATA(cm), &addr, sizeof(addr));

    const auto parsed = parse_original_dst(msg);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->address().to_string(), "127.0.0.2");
    EXPECT_EQ(parsed->port(), 5353);
}

TEST(net_utils_test, parse_original_dst_ipv6_success)
{
    std::array<std::byte, CMSG_SPACE(sizeof(sockaddr_in6))> control{};
    msghdr msg{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto* cm = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cm, nullptr);
    cm->cmsg_level = SOL_IPV6;
    cm->cmsg_type = IPV6_ORIGDSTADDR;
    cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in6));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(5353);
    addr.sin6_addr = in6addr_loopback;
    std::memcpy(CMSG_DATA(cm), &addr, sizeof(addr));

    const auto parsed = parse_original_dst(msg);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->address().to_string(), "::1");
    EXPECT_EQ(parsed->port(), 5353);
}

TEST(net_utils_test, parse_original_dst_truncated_control_payload)
{
    std::array<std::byte, CMSG_SPACE(sizeof(sockaddr_in6))> control{};
    msghdr msg{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto* cm = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cm, nullptr);
    cm->cmsg_level = SOL_IPV6;
    cm->cmsg_type = IPV6_ORIGDSTADDR;
    cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in6) - 1U);

    const auto parsed = parse_original_dst(msg);
    EXPECT_FALSE(parsed.has_value());
}

TEST(net_utils_test, parse_original_dst_unknown_control_message)
{
    std::array<std::byte, CMSG_SPACE(sizeof(sockaddr_in))> control{};
    msghdr msg{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto* cm = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cm, nullptr);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in));

    const auto parsed = parse_original_dst(msg);
    EXPECT_FALSE(parsed.has_value());
}
#endif

}    // namespace mux::net
