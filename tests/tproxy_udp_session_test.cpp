#include <array>
#include <chrono>
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <future>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netfilter_ipv4.h>

#include <gtest/gtest.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "router.h"
#include "ip_matcher.h"
#include "domain_matcher.h"
#include "mux_stream.h"
#include "test_util.h"
#include "context_pool.h"
#define private public
#include "tproxy_udp_session.h"
#include "tproxy_client.h"
#undef private

extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_bind(int sockfd, const sockaddr* addr, socklen_t addrlen);
extern "C" ssize_t __real_recvmsg(int sockfd, msghdr* msg, int flags);
extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_accept(int sockfd, sockaddr* addr, socklen_t* addrlen);
extern "C" int __real_accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags);
extern "C" int __real_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen);
extern "C" int __real_close(int fd);

namespace
{

enum class wrapped_recvmsg_mode
{
    kReal = 0,
    kEagain,
    kError,
    kMissingOrigdst,
    kSyntheticValid
};

std::atomic<bool> g_force_tproxy_sockopt_success{false};
std::atomic<bool> g_fail_setsockopt_once{false};
std::atomic<int> g_fail_setsockopt_level{-1};
std::atomic<int> g_fail_setsockopt_optname{-1};
std::atomic<int> g_fail_setsockopt_errno{EPERM};
std::atomic<bool> g_fail_socket_once{false};
std::atomic<int> g_fail_socket_errno{EMFILE};
std::atomic<bool> g_fail_bind_once{false};
std::atomic<int> g_fail_bind_errno{EADDRINUSE};
std::atomic<bool> g_fail_accept_once{false};
std::atomic<int> g_fail_accept_errno{EIO};
std::atomic<bool> g_fail_getsockname_once{false};
std::atomic<int> g_fail_getsockname_errno{ENOTSOCK};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};
std::atomic<int> g_recvmsg_mode{static_cast<int>(wrapped_recvmsg_mode::kReal)};

void reset_socket_wrappers()
{
    g_force_tproxy_sockopt_success.store(false, std::memory_order_release);
    g_fail_setsockopt_once.store(false, std::memory_order_release);
    g_fail_setsockopt_level.store(-1, std::memory_order_release);
    g_fail_setsockopt_optname.store(-1, std::memory_order_release);
    g_fail_setsockopt_errno.store(EPERM, std::memory_order_release);
    g_fail_socket_once.store(false, std::memory_order_release);
    g_fail_socket_errno.store(EMFILE, std::memory_order_release);
    g_fail_bind_once.store(false, std::memory_order_release);
    g_fail_bind_errno.store(EADDRINUSE, std::memory_order_release);
    g_fail_accept_once.store(false, std::memory_order_release);
    g_fail_accept_errno.store(EIO, std::memory_order_release);
    g_fail_getsockname_once.store(false, std::memory_order_release);
    g_fail_getsockname_errno.store(ENOTSOCK, std::memory_order_release);
    g_fail_close_once.store(false, std::memory_order_release);
    g_fail_close_errno.store(EIO, std::memory_order_release);
    g_recvmsg_mode.store(static_cast<int>(wrapped_recvmsg_mode::kReal), std::memory_order_release);
}

void force_tproxy_setsockopt_success(const bool enable) { g_force_tproxy_sockopt_success.store(enable, std::memory_order_release); }

void fail_setsockopt_once(const int level, const int optname, const int err = EPERM)
{
    g_fail_setsockopt_level.store(level, std::memory_order_release);
    g_fail_setsockopt_optname.store(optname, std::memory_order_release);
    g_fail_setsockopt_errno.store(err, std::memory_order_release);
    g_fail_setsockopt_once.store(true, std::memory_order_release);
}

void fail_socket_once(const int err = EMFILE)
{
    g_fail_socket_errno.store(err, std::memory_order_release);
    g_fail_socket_once.store(true, std::memory_order_release);
}

void fail_bind_once(const int err = EADDRINUSE)
{
    g_fail_bind_errno.store(err, std::memory_order_release);
    g_fail_bind_once.store(true, std::memory_order_release);
}

void fail_next_accept(const int err = EIO)
{
    g_fail_accept_errno.store(err, std::memory_order_release);
    g_fail_accept_once.store(true, std::memory_order_release);
}

void fail_next_getsockname(const int err = ENOTSOCK)
{
    g_fail_getsockname_errno.store(err, std::memory_order_release);
    g_fail_getsockname_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err = EIO)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

void set_recvmsg_mode_once(const wrapped_recvmsg_mode mode) { g_recvmsg_mode.store(static_cast<int>(mode), std::memory_order_release); }

bool is_tproxy_setsockopt(const int level, const int optname)
{
    if (level == SOL_IP)
    {
#ifdef IP_TRANSPARENT
        if (optname == IP_TRANSPARENT)
        {
            return true;
        }
#endif
#ifdef IP_RECVORIGDSTADDR
        if (optname == IP_RECVORIGDSTADDR)
        {
            return true;
        }
#endif
    }
    if (level == SOL_IPV6)
    {
#ifdef IPV6_TRANSPARENT
        if (optname == IPV6_TRANSPARENT)
        {
            return true;
        }
#endif
#ifdef IPV6_RECVORIGDSTADDR
        if (optname == IPV6_RECVORIGDSTADDR)
        {
            return true;
        }
#endif
    }
    if (level == SOL_SOCKET)
    {
#ifdef SO_MARK
        if (optname == SO_MARK)
        {
            return true;
        }
#endif
    }
    return false;
}

template <typename Func>
auto run_on_io_context(asio::io_context& io_context, Func&& fn) -> decltype(fn())
{
    using result_type = decltype(fn());
    std::promise<result_type> promise;
    auto future = promise.get_future();
    asio::post(io_context,
               [func = std::forward<Func>(fn), promise = std::move(promise)]() mutable
               {
                   promise.set_value(func());
               });
    return future.get();
}

bool tcp_acceptor_is_open(asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->tcp_acceptor_.is_open(); });
}

bool udp_socket_is_open(asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->udp_socket_.is_open(); });
}

void emplace_udp_session(asio::io_context& io_context,
                         const std::shared_ptr<mux::tproxy_client>& client,
                         const std::string& key,
                         const std::shared_ptr<mux::tproxy_udp_session>& session)
{
    run_on_io_context(io_context,
                      [client, key, session]()
                      {
                          client->udp_sessions_.emplace(key, session);
                          return true;
                      });
}

std::size_t udp_session_count(asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->udp_sessions_.size(); });
}

class direct_router : public mux::router
{
   public:
    direct_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();

        direct_ip_matcher()->add_rule("0.0.0.0/0");
        direct_ip_matcher()->add_rule("::/0");
        direct_ip_matcher()->optimize();
    }
};

class proxy_router final : public mux::router
{
   public:
    proxy_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();
    }
};

class failing_load_router final : public mux::router
{
   public:
    bool load() override { return false; }
};

std::uint64_t now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::uint16_t pick_free_tcp_port()
{
    asio::io_context io_context;
    asio::ip::tcp::acceptor acceptor(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    return acceptor.local_endpoint().port();
}

}    // namespace

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (g_fail_setsockopt_once.exchange(false, std::memory_order_acq_rel) && g_fail_setsockopt_level.load(std::memory_order_acquire) == level
        && g_fail_setsockopt_optname.load(std::memory_order_acquire) == optname)
    {
        errno = g_fail_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }

    if (g_force_tproxy_sockopt_success.load(std::memory_order_acquire) && is_tproxy_setsockopt(level, optname))
    {
        return 0;
    }

    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (g_fail_socket_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_socket_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_accept(int sockfd, sockaddr* addr, socklen_t* addrlen)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept(sockfd, addr, addrlen);
}

extern "C" int __wrap_accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept4(sockfd, addr, addrlen, flags);
}

extern "C" int __wrap_getsockname(int sockfd, sockaddr* addr, socklen_t* addrlen)
{
    if (g_fail_getsockname_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_getsockname_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_getsockname(sockfd, addr, addrlen);
}

extern "C" int __wrap_close(int fd)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);
}

extern "C" int __wrap_bind(int sockfd, const sockaddr* addr, socklen_t addrlen)
{
    if (g_fail_bind_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_bind_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_bind(sockfd, addr, addrlen);
}

extern "C" ssize_t __wrap_recvmsg(int sockfd, msghdr* msg, int flags)
{
    const auto mode = static_cast<wrapped_recvmsg_mode>(g_recvmsg_mode.exchange(static_cast<int>(wrapped_recvmsg_mode::kReal), std::memory_order_acq_rel));
    if (mode == wrapped_recvmsg_mode::kReal)
    {
        return __real_recvmsg(sockfd, msg, flags);
    }
    if (mode == wrapped_recvmsg_mode::kEagain)
    {
        errno = EAGAIN;
        return -1;
    }
    if (mode == wrapped_recvmsg_mode::kError)
    {
        errno = EIO;
        return -1;
    }

    if (msg == nullptr || msg->msg_iov == nullptr || msg->msg_iovlen == 0 || msg->msg_iov[0].iov_base == nullptr || msg->msg_iov[0].iov_len == 0)
    {
        errno = EFAULT;
        return -1;
    }

    static const std::array<std::uint8_t, 4> payload = {0xde, 0xad, 0xbe, 0xef};
    const auto n = std::min<std::size_t>(msg->msg_iov[0].iov_len, payload.size());
    std::memcpy(msg->msg_iov[0].iov_base, payload.data(), n);

    if (msg->msg_name != nullptr && msg->msg_namelen >= sizeof(sockaddr_in))
    {
        auto* src = reinterpret_cast<sockaddr_in*>(msg->msg_name);
        std::memset(src, 0, sizeof(sockaddr_in));
        src->sin_family = AF_INET;
        src->sin_port = htons(46000);
        src->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        msg->msg_namelen = sizeof(sockaddr_in);
    }
    if (mode == wrapped_recvmsg_mode::kMissingOrigdst)
    {
        msg->msg_controllen = 0;
        return static_cast<ssize_t>(n);
    }

    if (msg->msg_control != nullptr && msg->msg_controllen >= CMSG_SPACE(sizeof(sockaddr_in)))
    {
        std::memset(msg->msg_control, 0, msg->msg_controllen);
        msg->msg_controllen = CMSG_SPACE(sizeof(sockaddr_in));
        auto* cm = CMSG_FIRSTHDR(msg);
        cm->cmsg_level = SOL_IP;
        cm->cmsg_type = IP_ORIGDSTADDR;
        cm->cmsg_len = CMSG_LEN(sizeof(sockaddr_in));
        auto* dst = reinterpret_cast<sockaddr_in*>(CMSG_DATA(cm));
        std::memset(dst, 0, sizeof(sockaddr_in));
        dst->sin_family = AF_INET;
        dst->sin_port = htons(5353);
        dst->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    else
    {
        msg->msg_controllen = 0;
    }
    return static_cast<ssize_t>(n);
}

TEST(TproxyUdpSessionTest, IdleDetection)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 1;

    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 1, cfg, client_ep);
    session->start();

    const asio::ip::udp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 53);
    std::array<std::uint8_t, 1> data = {0};
    asio::co_spawn(
        ctx,
        [session, dst_ep, data]() -> asio::awaitable<void> { co_await session->handle_packet(dst_ep, data.data(), data.size()); },
        asio::detached);

    for (int i = 0; i < 5; ++i)
    {
        ctx.poll();
    }

    const auto now = now_ms();
    EXPECT_FALSE(session->is_idle(now, 1000));
    EXPECT_TRUE(session->is_idle(now + 2000, 1000));

    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, IdleTimeoutZeroNeverExpires)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.timeout.idle = 1;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 2, cfg, client_ep);

    EXPECT_FALSE(session->is_idle(now_ms(), 0));
}

TEST(TproxyUdpSessionTest, InternalGuardBranches)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12346);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 3, cfg, client_ep);

    asio::ip::udp::endpoint src_ep;
    std::vector<std::uint8_t> payload;
    EXPECT_FALSE(session->decode_proxy_packet({0x00, 0x01}, src_ep, payload));

    socks_udp_header h;
    h.addr = "not-an-ip";
    h.port = 5353;
    auto pkt = socks_codec::encode_udp_header(h);
    pkt.push_back(0x42);
    EXPECT_FALSE(session->decode_proxy_packet(pkt, src_ep, payload));

    session->maybe_start_proxy_reader(false);

    bool should_start_reader = false;
    session->stream_ =
        std::make_shared<mux::mux_stream>(1, 1, "trace", std::shared_ptr<mux::mux_connection>{}, ctx);
    EXPECT_FALSE(session->install_proxy_stream(nullptr, nullptr, should_start_reader));
}

TEST(TproxyUdpSessionTest, StartHandlesAlreadyOpenedSocket)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12401);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 5, cfg, client_ep);

    std::error_code ec;
    session->direct_socket_.open(asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);

    session->start();
    EXPECT_TRUE(session->direct_socket_.is_open());
    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, StartCoversV6OnlyAndMarkFailure)
{
    auto run_once = [](const mux::config& cfg)
    {
        asio::io_context ctx;
        auto router = std::make_shared<direct_router>();
        const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12402);
        auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 6, cfg, client_ep);
        session->start();
        session->stop();
        ctx.poll();
    };

    reset_socket_wrappers();
#ifdef IPV6_V6ONLY
    mux::config v6_cfg;
    v6_cfg.tproxy.mark = 0;
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    run_once(v6_cfg);
#endif

    reset_socket_wrappers();
    mux::config mark_cfg;
    mark_cfg.tproxy.mark = 123;
#ifdef SO_MARK
    fail_setsockopt_once(SOL_SOCKET, SO_MARK, EPERM);
#endif
    run_once(mark_cfg);
    reset_socket_wrappers();
}

TEST(TproxyUdpSessionTest, SendDirectIPv6AndCloseResetBranches)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12403);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 7, cfg, client_ep);
    session->start();

    bool done = false;
    const std::array<std::uint8_t, 2> payload = {0x41, 0x42};
    const asio::ip::udp::endpoint dst_ep(asio::ip::make_address("::1"), 5353);
    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            co_await session->send_direct(dst_ep, payload.data(), payload.size());
            done = true;
            co_return;
        },
        asio::detached);
    for (int i = 0; i < 50 && !done; ++i)
    {
        ctx.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_TRUE(done);
    ctx.restart();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 100);
    auto stream = std::make_shared<mux::mux_stream>(9, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->on_close();
    ctx.poll();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->on_reset();
    ctx.poll();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, StartCoversBindFailureBranch)
{
    reset_socket_wrappers();

    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12404);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 8, cfg, client_ep);

    fail_bind_once(EADDRINUSE);
    session->start();
    EXPECT_TRUE(session->direct_socket_.is_open());

    session->stop();
    ctx.poll();
    reset_socket_wrappers();
}

TEST(TproxyUdpSessionTest, StopAndOnCloseCoverPartialStateBranches)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12405);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 9, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 101);
    auto stream = std::make_shared<mux::mux_stream>(13, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    session->tunnel_ = tunnel;
    session->stream_.reset();
    session->stop();
    ctx.run();
    ctx.restart();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    session->stream_ = stream;
    session->tunnel_.reset();
    session->on_close();
    ctx.run();
    ctx.restart();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, ProxyStreamLifecycleCoversInstallCleanupAndReaderStart)
{
    asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12406);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 10, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<asio::ip::tcp::socket>>(
        asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 102);
    auto stream = std::make_shared<mux::mux_stream>(14, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    bool should_start_reader = false;
    EXPECT_TRUE(session->install_proxy_stream(tunnel, stream, should_start_reader));
    EXPECT_TRUE(should_start_reader);

    session->stream_.reset();
    session->tunnel_.reset();
    session->proxy_reader_started_ = true;
    should_start_reader = false;
    EXPECT_TRUE(session->install_proxy_stream(tunnel, stream, should_start_reader));
    EXPECT_FALSE(should_start_reader);

    session->recv_channel_.close();
    session->maybe_start_proxy_reader(true);
    ctx.poll();
    ctx.restart();

    mux::test::run_awaitable_void(ctx, session->cleanup_proxy_stream(tunnel, stream));
}

TEST(TproxyClientTest, DisabledStartSetsStopFlag)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = false;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, InvalidRealityAuthConfigStopsEarly)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.reality.fingerprint = "invalid-fingerprint";
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, TcpPortZeroStopsEarlyAndEndpointKeyWorks)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.tcp_port = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_EQ(client->endpoint_key(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 5353)), "127.0.0.1:5353");
    client->stop();
}

TEST(TproxyClientTest, UdpPortFallsBackToTcpPortWhenConfiguredZero)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = 31081;
    cfg.tproxy.udp_port = 0;

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_EQ(client->udp_port(), cfg.tproxy.tcp_port);
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, AcceptAndUdpLoopReturnOnInvalidListenHost)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "invalid host value";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = 31091;
    cfg.tproxy.udp_port = 31092;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    pool.stop();
    runner.join();
}

TEST(TproxyClientTest, AcceptLoopSetupFailsWhenPortInUse)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    asio::ip::tcp::acceptor occupied(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto used_port = occupied.local_endpoint().port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = used_port;
    cfg.tproxy.udp_port = static_cast<std::uint16_t>(used_port + 1);
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopHandlesPacketAndCleanupPrunesIdleSessions)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    const auto udp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    cfg.timeout.idle = 1;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);
    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_cleanup_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    if (!udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "udp transparent socket unavailable in current environment";
    }

    asio::io_context sender_ctx;
    asio::ip::udp::socket sender(sender_ctx);
    sender.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    sender.send_to(asio::buffer(payload), asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), udp_port), 0, ec);
    ASSERT_FALSE(ec);

    const asio::ip::udp::endpoint session_src(asio::ip::make_address("127.0.0.1"), static_cast<std::uint16_t>(udp_port + 10));
    auto idle_session = std::make_shared<mux::tproxy_udp_session>(
        pool.get_io_context(), client->tunnel_pool_, client->router_, client->sender_, 77, cfg, session_src);
    idle_session->start();
    emplace_udp_session(pool.get_io_context(), client, client->endpoint_key(session_src), idle_session);

    std::this_thread::sleep_for(std::chrono::milliseconds(1400));
    EXPECT_LE(udp_session_count(pool.get_io_context(), client), 1U);

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StartMutatedUdpPortFallsBackToTcpPort)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = tcp_port;

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->udp_port_ = 0;

    std::thread runner([&pool]() { pool.run(); });
    client->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    EXPECT_EQ(client->udp_port(), client->tcp_port());

    client->stop();
    pool.stop();
    runner.join();
}

TEST(TproxyClientTest, RouterLoadFailureStopsEarly)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<failing_load_router>();
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, StopExtractsAndStopsUdpSessions)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 19001);
    auto live_session =
        std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), client->tunnel_pool_, client->router_, client->sender_, 42, cfg, client_ep);

    client->udp_sessions_.emplace("null-entry", nullptr);
    client->udp_sessions_.emplace("live-entry", live_session);

    std::thread runner([&pool]() { pool.run(); });
    client->stop();
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 0U);

    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(TproxyClientTest, AcceptLoopStopsWhenStopFlagSetAfterPendingAccept)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    const auto udp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !tcp_acceptor_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tcp_acceptor_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tcp transparent socket unavailable in current environment";
    }

    client->stop_.store(true, std::memory_order_release);

    asio::io_context dial_ctx;
    asio::ip::tcp::socket dial_socket(dial_ctx);
    dial_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), tcp_port), ec);
    if (ec)
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tcp listener not reachable in current environment";
    }
    dial_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    dial_socket.close(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopBreaksWhenReadableAndStopFlagAlreadySet)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    const auto udp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "udp transparent socket unavailable in current environment";
    }

    client->stop_.store(true, std::memory_order_release);

    asio::io_context sender_ctx;
    asio::ip::udp::socket sender(sender_ctx);
    sender.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const std::array<std::uint8_t, 1> payload = {0x7f};
    sender.send_to(asio::buffer(payload), asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), udp_port), 0, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopRetriesWhenSocketClosedUnexpectedly)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    const auto udp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "udp transparent socket unavailable in current environment";
    }

    asio::post(pool.get_io_context(),
               [client]()
               {
                   std::error_code close_ec;
                   client->udp_socket_.close(close_ec);
               });
    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, WrappedSetsockoptCoversSetupFailureBranches)
{
    auto run_accept_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->accept_tcp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->udp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;

    reset_socket_wrappers();
    fail_setsockopt_once(SOL_SOCKET, SO_REUSEADDR, EPERM);
    run_accept_loop_once(cfg);

    reset_socket_wrappers();
#ifdef IPV6_V6ONLY
    cfg.tproxy.listen_host = "::1";
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    run_accept_loop_once(cfg);
#endif

    reset_socket_wrappers();
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.udp_port = pick_free_tcp_port();
    fail_setsockopt_once(SOL_SOCKET, SO_REUSEADDR, EPERM);
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
#ifdef IP_RECVORIGDSTADDR
    fail_setsockopt_once(SOL_IP, IP_RECVORIGDSTADDR, EPERM);
#endif
    cfg.tproxy.udp_port = pick_free_tcp_port();
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
#ifdef IPV6_V6ONLY
    cfg.tproxy.listen_host = "::1";
    cfg.tproxy.udp_port = pick_free_tcp_port();
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    run_udp_loop_once(cfg);
#endif

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 123;
#ifdef SO_MARK
    fail_setsockopt_once(SOL_SOCKET, SO_MARK, EPERM);
#endif
    cfg.tproxy.udp_port = pick_free_tcp_port();
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.mark = 0;
    cfg.tproxy.udp_port = pick_free_tcp_port();
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
}

TEST(TproxyClientTest, SocketOpenFailureCoversSetupBranches)
{
    auto run_accept_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->accept_tcp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->udp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;

    reset_socket_wrappers();
    fail_socket_once();
    run_accept_loop_once(cfg);

    reset_socket_wrappers();
    fail_socket_once();
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopReusesExistingSessionForSameSource)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "udp socket unavailable in current environment";
    }

    asio::io_context sender_ctx;
    asio::ip::udp::socket sender(sender_ctx);
    sender.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    const asio::ip::udp::endpoint dst(asio::ip::make_address("127.0.0.1"), cfg.tproxy.udp_port);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);

    for (int i = 0; i < 50 && udp_session_count(pool.get_io_context(), client) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, WrappedRecvmsgCoversUdpReadErrorBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(udp_socket_is_open(pool.get_io_context(), client));

    asio::io_context sender_ctx;
    asio::ip::udp::socket sender(sender_ctx);
    sender.open(asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 3> payload = {0x01, 0x02, 0x03};
    const asio::ip::udp::endpoint dst(asio::ip::make_address("127.0.0.1"), cfg.tproxy.udp_port);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kEagain);
    sender.send_to(asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kMissingOrigdst);
    sender.send_to(asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kError);
    sender.send_to(asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopRetriesOnAcceptErrorBranch)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    fail_next_accept(EIO);
    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !tcp_acceptor_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tcp_acceptor_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tcp transparent socket unavailable in current environment";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1150));
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopCoversNoDelayAndLocalEndpointFailureBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    fail_setsockopt_once(IPPROTO_TCP, TCP_NODELAY, EPERM);
    fail_next_getsockname(EIO);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !tcp_acceptor_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tcp_acceptor_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tcp transparent socket unavailable in current environment";
    }

    asio::io_context dial_ctx;
    asio::ip::tcp::socket dial_socket(dial_ctx);
    dial_socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), cfg.tproxy.tcp_port), ec);
    if (ec)
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tcp listener not reachable in current environment";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    dial_socket.close(ec);

    client->stop();
    pool.stop();
    runner.join();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopCoversRetryBranchAfterNativeFdInvalidation)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "udp transparent socket unavailable in current environment";
    }

    asio::post(pool.get_io_context(),
               [client]()
               {
                   const int fd = client->udp_socket_.native_handle();
                   if (fd >= 0)
                   {
                       (void)__real_close(fd);
                   }
               });

    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, SetupCoversEmptyHostV6OnlyRecvOrigdstAndMarkFailureBranches)
{
    auto run_accept_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->accept_tcp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        std::error_code ec;
        mux::io_context_pool pool(1, ec);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        asio::co_spawn(pool.get_io_context(),
                       [client]() -> asio::awaitable<void>
                       {
                           co_await client->udp_loop();
                           co_return;
                       },
                       asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        client->stop();
        pool.stop();
        runner.join();
    };

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;
    run_accept_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.listen_host = "::1";
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    run_accept_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.listen_host = "::1";
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    fail_setsockopt_once(SOL_IP, IP_RECVORIGDSTADDR, EPERM);
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    cfg.tproxy.mark = 123;
    fail_setsockopt_once(SOL_SOCKET, SO_MARK, EPERM);
    run_udp_loop_once(cfg);

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopCoversCloseErrorLogBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });
    client->start();
    for (int i = 0; i < 50 && (!tcp_acceptor_is_open(pool.get_io_context(), client) || !udp_socket_is_open(pool.get_io_context(), client)); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tcp_acceptor_is_open(pool.get_io_context(), client) && !udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tproxy sockets unavailable in current environment";
    }

    fail_next_close(EIO);
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopIgnoresBadDescriptorCloseBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });
    client->start();
    for (int i = 0; i < 50 && (!tcp_acceptor_is_open(pool.get_io_context(), client) || !udp_socket_is_open(pool.get_io_context(), client)); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!tcp_acceptor_is_open(pool.get_io_context(), client) && !udp_socket_is_open(pool.get_io_context(), client))
    {
        client->stop();
        pool.stop();
        runner.join();
        GTEST_SKIP() << "tproxy sockets unavailable in current environment";
    }

    run_on_io_context(pool.get_io_context(),
                      [client]()
                      {
                          std::error_code close_ec;
                          client->tcp_acceptor_.close(close_ec);
                          client->udp_socket_.close(close_ec);
                          return true;
                      });

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopIgnoresBadDescriptorCloseBranchWithoutRuntimeSetup)
{
    reset_socket_wrappers();

    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });

    const bool opened = run_on_io_context(pool.get_io_context(),
                                          [client]()
                                          {
                                              std::error_code open_ec;
                                              client->tcp_acceptor_.open(asio::ip::tcp::v4(), open_ec);
                                              if (open_ec)
                                              {
                                                  return false;
                                              }
                                              client->udp_socket_.open(asio::ip::udp::v4(), open_ec);
                                              return !open_ec;
                                          });
    ASSERT_TRUE(opened);

    fail_next_close(EBADF);
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpCleanupLoopCoversNullSessionBranch)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.timeout.idle = 1;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->udp_sessions_.emplace("null-session", std::shared_ptr<mux::tproxy_udp_session>{});

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_cleanup_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    client->stop_.store(true, std::memory_order_release);
    pool.stop();
    runner.join();
}
