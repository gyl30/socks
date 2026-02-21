
#include <array>
#include <atomic>
#include <cerrno>
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

extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);    

namespace
{

std::atomic<bool> g_force_linux_first_opt_success{false};
std::atomic<bool> g_fail_setsockopt_once{false};
std::atomic<int> g_fail_level{-1};
std::atomic<int> g_fail_optname{-1};
std::atomic<int> g_fail_errno{EPERM};

void reset_setsockopt_hooks()
{
    g_force_linux_first_opt_success.store(false, std::memory_order_release);
    g_fail_setsockopt_once.store(false, std::memory_order_release);
    g_fail_level.store(-1, std::memory_order_release);
    g_fail_optname.store(-1, std::memory_order_release);
    g_fail_errno.store(EPERM, std::memory_order_release);
}

void fail_setsockopt_once(const int level, const int optname, const int err)
{
    g_fail_level.store(level, std::memory_order_release);
    g_fail_optname.store(optname, std::memory_order_release);
    g_fail_errno.store(err, std::memory_order_release);
    g_fail_setsockopt_once.store(true, std::memory_order_release);
}

bool is_force_success_option(const int level, const int optname)
{
#ifdef __linux__
    return level == SOL_IP && (optname == IP_TRANSPARENT || optname == IP_RECVORIGDSTADDR);
#else
    (void)level;
    (void)optname;
    return false;
#endif
}

}    // namespace

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)    
{
    if (g_fail_setsockopt_once.load(std::memory_order_acquire) && g_fail_level.load(std::memory_order_acquire) == level &&
        g_fail_optname.load(std::memory_order_acquire) == optname)
    {
        g_fail_setsockopt_once.store(false, std::memory_order_release);
        errno = g_fail_errno.load(std::memory_order_acquire);
        return -1;
    }
    if (g_force_linux_first_opt_success.load(std::memory_order_acquire) && is_force_success_option(level, optname))
    {
        return 0;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);    
}

namespace mux::net
{

TEST(NetUtilsTest, EndpointFromSockaddrIpv4)
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

TEST(NetUtilsTest, EndpointFromSockaddrIpv6)
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

TEST(NetUtilsTest, EndpointFromSockaddrIpv4TruncatedLen)
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

TEST(NetUtilsTest, EndpointFromSockaddrIpv6TruncatedLen)
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

TEST(NetUtilsTest, EndpointFromSockaddrUnknownFamily)
{
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;

    const auto endpoint = endpoint_from_sockaddr(storage, sizeof(storage));
    EXPECT_TRUE(endpoint.address().is_unspecified());
    EXPECT_EQ(endpoint.port(), 0);
}

TEST(NetUtilsTest, SetSocketMarkZeroShortCircuit)
{
    const auto result = set_socket_mark(-1, 0);
#ifdef __linux__
    EXPECT_TRUE(result.has_value());
#else
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_supported));
#endif
}

TEST(NetUtilsTest, SetSocketMarkInvalidFd)
{
    const auto result = set_socket_mark(-1, 1);
    EXPECT_FALSE(result.has_value());
#ifdef __linux__
    EXPECT_EQ(result.error().value(), EBADF);
#else
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_supported));
#endif
}

TEST(NetUtilsTest, SetSocketTransparentInvalidFd)
{
    const auto result = set_socket_transparent(-1, true);
    EXPECT_FALSE(result.has_value());
#ifdef __linux__
    EXPECT_EQ(result.error().value(), EBADF);
#else
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_supported));
#endif
}

TEST(NetUtilsTest, SetSocketRecvOrigdstInvalidFd)
{
    const auto result = set_socket_recv_origdst(-1, true);
    EXPECT_FALSE(result.has_value());
#ifdef __linux__
    EXPECT_EQ(result.error().value(), EBADF);
#else
    EXPECT_EQ(result.error(), std::make_error_code(std::errc::not_supported));
#endif
}

TEST(NetUtilsTest, NormalizeAddressV4MappedV6)
{
    const auto mapped = boost::asio::ip::make_address("::ffff:127.0.0.1");
    const auto normalized = normalize_address(mapped);

    EXPECT_TRUE(normalized.is_v4());
    EXPECT_EQ(normalized.to_string(), "127.0.0.1");
}

TEST(NetUtilsTest, ParseOriginalDstNoControlMessage)
{
    msghdr msg{};
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;

    const auto parsed = parse_original_dst(msg);
    EXPECT_FALSE(parsed.has_value());
}

#ifdef __linux__
TEST(NetUtilsTest, ParseOriginalDstIpv4Success)
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

TEST(NetUtilsTest, ParseOriginalDstIpv6Success)
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

TEST(NetUtilsTest, ParseOriginalDstTruncatedControlPayload)
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

TEST(NetUtilsTest, ParseOriginalDstIpv4TruncatedControlPayload)
{
    std::array<std::byte, CMSG_SPACE(sizeof(sockaddr_in))> control{};
    msghdr msg{};
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    auto* cm = CMSG_FIRSTHDR(&msg);
    ASSERT_NE(cm, nullptr);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_ORIGDSTADDR;
    cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in) - 1U);

    const auto parsed = parse_original_dst(msg);
    EXPECT_FALSE(parsed.has_value());
}

TEST(NetUtilsTest, SetSocketTransparentIpv6SecondSetsockoptFailure)
{
    reset_setsockopt_hooks();
    g_force_linux_first_opt_success.store(true, std::memory_order_release);
    fail_setsockopt_once(SOL_IPV6, IPV6_TRANSPARENT, EACCES);

    const auto result = set_socket_transparent(-1, true);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().value(), EACCES);

    reset_setsockopt_hooks();
}

TEST(NetUtilsTest, SetSocketRecvOrigdstIpv6SecondSetsockoptFailure)
{
    reset_setsockopt_hooks();
    g_force_linux_first_opt_success.store(true, std::memory_order_release);
    fail_setsockopt_once(SOL_IPV6, IPV6_RECVORIGDSTADDR, EACCES);

    const auto result = set_socket_recv_origdst(-1, true);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().value(), EACCES);

    reset_setsockopt_hooks();
}

TEST(NetUtilsTest, ParseOriginalDstUnknownControlMessage)
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
