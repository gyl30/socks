#include <chrono>
#include <memory>
#include <vector>
#include <cstdint>
#include <atomic>
#include <cerrno>
#include <sys/socket.h>

#include <gtest/gtest.h>
#include <asio/ip/udp.hpp>
#include <asio/io_context.hpp>

#include "test_util.h"
#define private public
#include "tproxy_udp_sender.h"
#undef private

namespace
{

enum class udp_sender_fail_mode
{
    kNone = 0,
    kSocketOnce,
    kSetsockoptAlwaysSuccess,
};

std::atomic<int> g_udp_sender_fail_mode{static_cast<int>(udp_sender_fail_mode::kNone)};

class udp_sender_fail_guard
{
   public:
    explicit udp_sender_fail_guard(const udp_sender_fail_mode mode)
    {
        g_udp_sender_fail_mode.store(static_cast<int>(mode), std::memory_order_release);
    }

    ~udp_sender_fail_guard() { g_udp_sender_fail_mode.store(static_cast<int>(udp_sender_fail_mode::kNone), std::memory_order_release); }
};

bool consume_udp_sender_socket_fail_once()
{
    const auto current = static_cast<udp_sender_fail_mode>(g_udp_sender_fail_mode.load(std::memory_order_acquire));
    if (current != udp_sender_fail_mode::kSocketOnce)
    {
        return false;
    }
    g_udp_sender_fail_mode.store(static_cast<int>(udp_sender_fail_mode::kNone), std::memory_order_release);
    return true;
}

bool force_udp_sender_setsockopt_success()
{
    return static_cast<udp_sender_fail_mode>(g_udp_sender_fail_mode.load(std::memory_order_acquire))
           == udp_sender_fail_mode::kSetsockoptAlwaysSuccess;
}

std::shared_ptr<asio::ip::udp::socket> make_bound_udp_v4_socket(asio::io_context& ctx)
{
    auto sock = std::make_shared<asio::ip::udp::socket>(ctx);
    std::error_code ec;
    sock->open(asio::ip::udp::v4(), ec);
    EXPECT_FALSE(ec);
    sock->bind(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0), ec);
    EXPECT_FALSE(ec);
    return sock;
}

std::shared_ptr<asio::ip::udp::socket> make_open_udp_v6_socket(asio::io_context& ctx)
{
    auto sock = std::make_shared<asio::ip::udp::socket>(ctx);
    std::error_code ec;
    sock->open(asio::ip::udp::v6(), ec);
    EXPECT_FALSE(ec);
    return sock;
}

}    // namespace

extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (consume_udp_sender_socket_fail_once())
    {
        errno = EMFILE;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (force_udp_sender_setsockopt_success())
    {
        return 0;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

TEST(TproxyUdpSenderTest, CacheMaintenanceBranches)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);

    const auto now = static_cast<std::uint64_t>(1'000'000);
    const mux::tproxy_udp_sender::endpoint_key keep_key{asio::ip::make_address("127.0.0.1"), 10001};
    const mux::tproxy_udp_sender::endpoint_key expired_key{asio::ip::make_address("127.0.0.2"), 10002};
    const mux::tproxy_udp_sender::endpoint_key invalid_key{asio::ip::make_address("127.0.0.3"), 10003};

    auto keep_socket = make_bound_udp_v4_socket(ctx);
    auto expired_socket = make_bound_udp_v4_socket(ctx);

    sender.update_cached_socket(keep_key, keep_socket, now);
    sender.update_cached_socket(expired_key, expired_socket, now - 400'000);
    sender.update_cached_socket(invalid_key, nullptr, now);
    sender.prune_sockets(now);

    EXPECT_EQ(sender.sockets_.size(), 1u);
    EXPECT_NE(sender.get_cached_socket(keep_key, now + 1), nullptr);
    EXPECT_EQ(sender.get_cached_socket(invalid_key, now + 1), nullptr);

    const mux::tproxy_udp_sender::endpoint_key k1{asio::ip::make_address("127.0.0.10"), 10100};
    const mux::tproxy_udp_sender::endpoint_key k2{asio::ip::make_address("127.0.0.11"), 10101};
    auto s1 = make_bound_udp_v4_socket(ctx);
    auto s2 = make_bound_udp_v4_socket(ctx);
    sender.update_cached_socket(k1, s1, now + 10);
    sender.update_cached_socket(k2, s2, now + 20);
    sender.evict_oldest_socket();
    EXPECT_EQ(sender.sockets_.size(), 2u);

    sender.sockets_.clear();
    sender.evict_oldest_socket();

    sender.update_cached_socket(k1, s1, now + 30);
    const auto before_ts = sender.sockets_[k1].last_used_ms;
    sender.refresh_cached_socket_timestamp(k1, s1);
    EXPECT_GE(sender.sockets_[k1].last_used_ms, before_ts);

    sender.drop_cached_socket_if_match(k2, s2);
    EXPECT_EQ(sender.sockets_.size(), 1u);
    sender.drop_cached_socket_if_match(k1, s2);
    EXPECT_EQ(sender.sockets_.size(), 1u);
    sender.drop_cached_socket_if_match(k1, s1);
    EXPECT_TRUE(sender.sockets_.empty());
}

TEST(TproxyUdpSenderTest, EndpointKeyEqualCoversTrueAndFalsePaths)
{
    mux::tproxy_udp_sender::endpoint_key_equal eq;

    const mux::tproxy_udp_sender::endpoint_key key{asio::ip::make_address("127.0.0.1"), 10001};
    const mux::tproxy_udp_sender::endpoint_key same_key{asio::ip::make_address("127.0.0.1"), 10001};
    const mux::tproxy_udp_sender::endpoint_key diff_addr{asio::ip::make_address("127.0.0.2"), 10001};
    const mux::tproxy_udp_sender::endpoint_key diff_port{asio::ip::make_address("127.0.0.1"), 10002};

    EXPECT_TRUE(eq(key, same_key));
    EXPECT_FALSE(eq(key, diff_addr));
    EXPECT_FALSE(eq(key, diff_port));
}

TEST(TproxyUdpSenderTest, SocketOptionAndBindBranches)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);
    mux::tproxy_udp_sender sender_marked(ctx, 1234);

    auto unopened = std::make_shared<asio::ip::udp::socket>(ctx);
    EXPECT_FALSE(sender.set_ipv6_dual_stack_option(unopened));
    sender.set_reuse_address_option(unopened);
    EXPECT_FALSE(sender.set_transparent_option(unopened, false));
    sender.apply_socket_mark(unopened);
    sender_marked.apply_socket_mark(unopened);
    EXPECT_FALSE(sender.bind_socket_to_source(unopened, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0)));

    EXPECT_FALSE(sender.prepare_socket_options(unopened, true));
    EXPECT_FALSE(sender.prepare_socket_options(unopened, false));

    auto open_v6 = make_open_udp_v6_socket(ctx);
    (void)sender.set_ipv6_dual_stack_option(open_v6);

    const auto impossible_src = asio::ip::udp::endpoint(asio::ip::make_address("203.0.113.7"), 12345);
    EXPECT_EQ(sender.create_bound_socket(impossible_src, false), nullptr);
}

TEST(TproxyUdpSenderTest, SendToClientSuccessAndErrorPaths)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);

    asio::ip::udp::socket receiver(ctx, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto client_ep = receiver.local_endpoint();
    const asio::ip::udp::endpoint src_ep(asio::ip::make_address("127.0.0.1"), 18080);

    auto src_socket = make_bound_udp_v4_socket(ctx);
    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    sender.update_cached_socket({src_ep.address(), src_ep.port()}, src_socket, now_ms);
    mux::test::run_awaitable_void(ctx, sender.send_to_client(client_ep, src_ep, std::vector<std::uint8_t>{0x01, 0x02, 0x03}));
    EXPECT_EQ(sender.sockets_.size(), 1u);

    const asio::ip::udp::endpoint v6_client_ep(asio::ip::make_address("::1"), client_ep.port());
    mux::test::run_awaitable_void(ctx, sender.send_to_client(v6_client_ep, src_ep, std::vector<std::uint8_t>{0xAA}));
    EXPECT_TRUE(sender.sockets_.empty());
}

TEST(TproxyUdpSenderTest, GetSocketEvictsWhenCacheLooksFull)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);

    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    auto shared_socket = make_bound_udp_v4_socket(ctx);
    for (std::uint16_t port = 10000; port < 11024; ++port)
    {
        sender.update_cached_socket({asio::ip::make_address("127.0.0.1"), port}, shared_socket, now_ms + port);
    }
    ASSERT_GE(sender.sockets_.size(), 1024u);

    const auto bad_src = asio::ip::udp::endpoint(asio::ip::make_address("203.0.113.8"), 23456);
    EXPECT_EQ(sender.get_socket(bad_src), nullptr);
}

TEST(TproxyUdpSenderTest, CreateBoundSocketHandlesOpenFailure)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);
    udp_sender_fail_guard guard(udp_sender_fail_mode::kSocketOnce);

    const auto src_ep = asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0);
    EXPECT_EQ(sender.create_bound_socket(src_ep, false), nullptr);
}

TEST(TproxyUdpSenderTest, CreateBoundSocketBindFailureAfterPrepareSuccess)
{
    asio::io_context ctx;
    mux::tproxy_udp_sender sender(ctx, 0);
    udp_sender_fail_guard guard(udp_sender_fail_mode::kSetsockoptAlwaysSuccess);

    const auto impossible_src = asio::ip::udp::endpoint(asio::ip::make_address("203.0.113.99"), 34567);
    EXPECT_EQ(sender.create_bound_socket(impossible_src, false), nullptr);
}
