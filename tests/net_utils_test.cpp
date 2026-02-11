#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>

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

}    // namespace mux::net
