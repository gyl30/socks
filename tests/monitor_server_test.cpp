
#include <array>
#include <tuple>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <charconv>
#include <optional>
#include <unistd.h>
#include <string_view>
#include <sys/socket.h>
#include <system_error>

#include <gtest/gtest.h>
#include <boost/asio/post.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/socket_base.hpp>

#include "statistics.h"
#include "tproxy_client.h"

#define private public
#include "monitor_server.h"

#undef private

namespace
{

enum class monitor_fail_mode : std::uint8_t
{
    kNone = 0,
    kSocket,
    kSocketAlways,
    kReuseAddr,
    kReuseAddrAlways,
    kListen,
    kListenAlways,
};

std::atomic<monitor_fail_mode> g_monitor_fail_mode{monitor_fail_mode::kNone};
std::atomic<bool> g_fail_accept_once{false};
std::atomic<int> g_fail_accept_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

void reset_monitor_failure_injections()
{
    g_monitor_fail_mode.store(monitor_fail_mode::kNone, std::memory_order_release);
    g_fail_accept_once.store(false, std::memory_order_release);
    g_fail_accept_errno.store(EIO, std::memory_order_release);
    g_fail_close_once.store(false, std::memory_order_release);
    g_fail_close_errno.store(EIO, std::memory_order_release);
}

class monitor_fail_reset_listener : public ::testing::EmptyTestEventListener
{
   public:
    void OnTestStart(const ::testing::TestInfo&) override { reset_monitor_failure_injections(); }

    void OnTestEnd(const ::testing::TestInfo&) override { reset_monitor_failure_injections(); }
};

const bool g_monitor_fail_reset_listener_registered = []()
{
    ::testing::UnitTest::GetInstance()->listeners().Append(new monitor_fail_reset_listener());
    return true;
}();

class monitor_fail_guard
{
   public:
    explicit monitor_fail_guard(const monitor_fail_mode mode) { g_monitor_fail_mode.store(mode, std::memory_order_release); }

    ~monitor_fail_guard() { g_monitor_fail_mode.store(monitor_fail_mode::kNone, std::memory_order_release); }
};

bool should_fail_monitor_mode(const monitor_fail_mode once_mode, const monitor_fail_mode always_mode)
{
    const auto current = g_monitor_fail_mode.load(std::memory_order_acquire);
    if (current == always_mode)
    {
        return true;
    }
    if (current == once_mode)
    {
        g_monitor_fail_mode.store(monitor_fail_mode::kNone, std::memory_order_release);
        return true;
    }
    return false;
}

void fail_next_accept(const int err)
{
    g_fail_accept_errno.store(err, std::memory_order_release);
    g_fail_accept_once.store(true, std::memory_order_release);
}

void fail_next_close(const int err)
{
    g_fail_close_errno.store(err, std::memory_order_release);
    g_fail_close_once.store(true, std::memory_order_release);
}

constexpr std::string_view k_metrics_get_request =
    "GET /metrics HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: close\r\n"
    "\r\n";

constexpr std::uint32_t k_bind_retry_attempts = 120;
const auto k_bind_retry_delay = std::chrono::milliseconds(25);

bool open_ephemeral_loopback_acceptor(boost::asio::ip::tcp::acceptor& acceptor)
{
    boost::system::error_code ec;
    static_cast<void>(acceptor.open(boost::asio::ip::tcp::v4(), ec));
    if (ec)
    {
        return false;
    }

    static_cast<void>(acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec));
    if (ec)
    {
        return false;
    }

    for (std::uint32_t attempt = 0; attempt < k_bind_retry_attempts; ++attempt)
    {
        static_cast<void>(acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec));
        if (!ec)
        {
            break;
        }
        if (ec != boost::asio::error::address_in_use || (attempt + 1) >= k_bind_retry_attempts)
        {
            return false;
        }
        std::this_thread::sleep_for(k_bind_retry_delay);
    }

    static_cast<void>(acceptor.listen(boost::asio::socket_base::max_listen_connections, ec));
    if (ec)
    {
        return false;
    }
    return true;
}

std::string read_response(std::uint16_t port,
                          const std::string& request,
                          const std::string& remote_host = "127.0.0.1",
                          const std::string& local_host = "")
{
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    boost::system::error_code ec;
    const auto remote_addr = boost::asio::ip::make_address(remote_host, ec);
    if (ec)
    {
        return {};
    }
    if (!local_host.empty())
    {
        const auto local_addr = boost::asio::ip::make_address(local_host, ec);
        if (ec)
        {
            return {};
        }
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        static_cast<void>(socket.open(local_addr.is_v6() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4(), ec));
        if (ec)
        {
            return {};
        }
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        static_cast<void>(socket.bind(boost::asio::ip::tcp::endpoint(local_addr, 0), ec));
        if (ec)
        {
            return {};
        }
    }
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    static_cast<void>(socket.connect(boost::asio::ip::tcp::endpoint(remote_addr, port), ec));
    if (ec)
    {
        return {};
    }

    boost::asio::write(socket, boost::asio::buffer(request), ec);
    if (ec)
    {
        return {};
    }

    std::string out;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(boost::asio::buffer(buffer), ec);
        if (n > 0)
        {
            out.append(buffer.data(), n);
        }
        if (ec == boost::asio::error::eof)
        {
            break;
        }
        if (ec)
        {
            return out;
        }
    }
    return out;
}

std::string request_with_retry(std::uint16_t port, const std::string& request)
{
    for (int i = 0; i < 30; ++i)
    {
        const auto resp = read_response(port, request);
        if (!resp.empty())
        {
            return resp;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return read_response(port, request);
}

void drain_io_context(boost::asio::io_context& io_context, const int rounds = 32)
{
    io_context.restart();
    for (int i = 0; i < rounds; ++i)
    {
        if (io_context.poll() == 0)
        {
            break;
        }
    }
}

std::string request_metrics_with_retry(const std::uint16_t port) { return request_with_retry(port, std::string(k_metrics_get_request)); }

std::optional<std::uint64_t> parse_metric_value(const std::string& response, const std::string_view metric_name)
{
    const std::string prefix = std::string(metric_name) + " ";
    std::size_t pos = 0;
    while (pos < response.size())
    {
        std::size_t line_end = response.find('\n', pos);
        if (line_end == std::string::npos)
        {
            line_end = response.size();
        }
        const std::string_view line(response.data() + pos, line_end - pos);
        if (line.starts_with(prefix))
        {
            std::uint64_t value = 0;
            const char* first = line.data() + prefix.size();
            const char* last = line.data() + line.size();
            const auto parsed = std::from_chars(first, last, value);
            if (parsed.ec == std::errc())
            {
                return value;
            }
            return std::nullopt;
        }
        if (line_end == response.size())
        {
            break;
        }
        pos = line_end + 1;
    }
    return std::nullopt;
}

void connect_and_close_without_payload(const std::uint16_t port)
{
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    static_cast<void>(socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port), ec));
    if (ec)
    {
        return;
    }
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    socket.close(ec);
}

class monitor_server_env
{
   public:
    template <typename... Args>
    explicit monitor_server_env(Args&&... args)
    {
        reset_monitor_failure_injections();
        auto ctor_args = std::make_tuple(std::forward<Args>(args)...);
        for (std::uint32_t attempt = 0; attempt < 120; ++attempt)
        {
            server_ = std::apply([this](auto&&... unpacked) { return std::make_shared<mux::monitor_server>(ioc_, unpacked...); }, ctor_args);
            if (server_ != nullptr && server_->start() == 0 && server_->acceptor_.is_open())
            {
                thread_ = std::thread([this]() { ioc_.run(); });
                return;
            }
            server_.reset();
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
    }

    [[nodiscard]] std::uint16_t port() const
    {
        if (server_ == nullptr || !server_->acceptor_.is_open())
        {
            return 0;
        }
        boost::system::error_code ec;
        const auto endpoint = server_->acceptor_.local_endpoint(ec);
        if (ec)
        {
            return 0;
        }
        return endpoint.port();
    }

    ~monitor_server_env()
    {
        if (server_ != nullptr)
        {
            server_->stop();
        }
        ioc_.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
        reset_monitor_failure_injections();
    }

   private:
    boost::asio::io_context ioc_;
    std::shared_ptr<mux::monitor_server> server_;
    std::thread thread_;
};

}    // namespace

// NOLINTBEGIN(bugprone-reserved-identifier)
// GNU ld --wrap requires __real_ / __wrap_ symbol names.
extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __real_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);
extern "C" int __real_listen(int sockfd, int backlog);
extern "C" int __real_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
extern "C" int __real_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags);
extern "C" int __real_close(int fd);

extern "C" int __wrap_socket(int domain, int type, int protocol)
{
    if (should_fail_monitor_mode(monitor_fail_mode::kSocket, monitor_fail_mode::kSocketAlways))
    {
        errno = EMFILE;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
{
    if (level == SOL_SOCKET && optname == SO_REUSEADDR &&
        should_fail_monitor_mode(monitor_fail_mode::kReuseAddr, monitor_fail_mode::kReuseAddrAlways))
    {
        errno = EPERM;
        return -1;
    }
    return __real_setsockopt(sockfd, level, optname, optval, optlen);
}

extern "C" int __wrap_listen(int sockfd, int backlog)
{
    if (should_fail_monitor_mode(monitor_fail_mode::kListen, monitor_fail_mode::kListenAlways))
    {
        errno = EACCES;
        return -1;
    }
    return __real_listen(sockfd, backlog);
}

extern "C" int __wrap_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept(sockfd, addr, addrlen);
}

extern "C" int __wrap_accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    if (g_fail_accept_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_accept_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_accept4(sockfd, addr, addrlen, flags);
}

extern "C" int __wrap_close(int fd)
{
    if (g_fail_close_once.exchange(false, std::memory_order_acq_rel))
    {
        const int injected_errno = g_fail_close_errno.load(std::memory_order_acquire);
        // Keep fd lifecycle realistic while still surfacing close failure to caller.
        (void)__real_close(fd);
        errno = injected_errno;
        return -1;
    }
    return __real_close(fd);
}
// NOLINTEND(bugprone-reserved-identifier)

namespace mux
{

TEST(MonitorServerTest, GetMetricsReturnsHttpPayload)
{
    statistics::instance().inc_total_connections();

    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_metrics_with_retry(port);
    EXPECT_EQ(resp.rfind("HTTP/1.1 200 OK\r\n", 0), 0U);
    EXPECT_NE(resp.find("\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n"), std::string::npos);
    EXPECT_NE(resp.find("\r\nContent-Length: "), std::string::npos);
    EXPECT_NE(resp.find("\r\n\r\nsocks_uptime_seconds "), std::string::npos);
    EXPECT_NE(resp.find("socks_total_connections "), std::string::npos);
}

TEST(MonitorServerTest, SupportsMetricsPathQueryString)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_with_retry(port,
                                         "GET /metrics?debug=1 HTTP/1.1\r\n"
                                         "Host: 127.0.0.1\r\n"
                                         "Connection: close\r\n"
                                         "\r\n");
    EXPECT_EQ(resp.rfind("HTTP/1.1 200 OK\r\n", 0), 0U);
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, RejectsNonGetMethod)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_with_retry(port,
                                         "POST /metrics HTTP/1.1\r\n"
                                         "Host: 127.0.0.1\r\n"
                                         "Connection: close\r\n"
                                         "\r\n");
    EXPECT_EQ(resp.rfind("HTTP/1.1 404 ", 0), 0U);
}

TEST(MonitorServerTest, RejectsNonMetricsPath)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_with_retry(port,
                                         "GET /status HTTP/1.1\r\n"
                                         "Host: 127.0.0.1\r\n"
                                         "Connection: close\r\n"
                                         "\r\n");
    EXPECT_EQ(resp.rfind("HTTP/1.1 404 ", 0), 0U);
}

TEST(MonitorServerTest, SupportsFragmentedHttpRequest)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    static_cast<void>(socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port), ec));
    ASSERT_FALSE(ec);

    const std::string first_chunk = "GET /metrics HTTP/1.1\r\n";
    boost::asio::write(socket, boost::asio::buffer(first_chunk), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const std::string second_chunk = "Host: 127.0.0.1\r\nConnection: close\r\n\r\n";
    boost::asio::write(socket, boost::asio::buffer(second_chunk), ec);
    ASSERT_FALSE(ec);

    std::string resp;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(boost::asio::buffer(buffer), ec);
        if (n > 0)
        {
            resp.append(buffer.data(), n);
        }
        if (ec == boost::asio::error::eof)
        {
            break;
        }
        if (ec)
        {
            break;
        }
    }

    EXPECT_EQ(resp.rfind("HTTP/1.1 200 OK\r\n", 0), 0U);
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, TproxyUdpDispatchDropMetricReflectsDroppedPackets)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    boost::asio::io_context ioc;
    mux::tproxy_udp_dispatch_channel dispatch_channel(ioc, 1);

    mux::tproxy_udp_dispatch_item preload_packet;
    preload_packet.src_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 53111);
    preload_packet.dst_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
    preload_packet.payload.assign(8, 0x7f);
    ASSERT_TRUE(dispatch_channel.try_send(boost::system::error_code{}, std::move(preload_packet)));

    auto& stats = statistics::instance();
    const auto before = stats.tproxy_udp_dispatch_dropped();
    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 53112);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0xca, 0xfe, 0xba, 0xbe};
    constexpr std::size_t k_drop_attempts = 64;

    std::size_t dropped = 0;
    for (std::size_t i = 0; i < k_drop_attempts; ++i)
    {
        if (!tproxy_client::enqueue_udp_packet(dispatch_channel, src_ep, dst_ep, payload, payload.size()))
        {
            ++dropped;
        }
    }
    ASSERT_EQ(dropped, k_drop_attempts);

    const auto resp = request_metrics_with_retry(port);
    const auto metric_value = parse_metric_value(resp, "socks_tproxy_udp_dispatch_dropped_total");
    ASSERT_TRUE(metric_value.has_value());
    if (!metric_value.has_value())
    {
        return;
    }
    EXPECT_GE(*metric_value, before + dropped);

    dispatch_channel.close();
}

TEST(MonitorServerTest, TproxyUdpDispatchMetricsCanDeriveDropRatio)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    boost::asio::io_context ioc;
    mux::tproxy_udp_dispatch_channel dispatch_channel(ioc, 4);

    auto& stats = statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();
    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 53221);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0xde, 0xad, 0xbe, 0xef};

    std::size_t enqueued = 0;
    for (std::size_t i = 0; i < 4; ++i)
    {
        if (tproxy_client::enqueue_udp_packet(dispatch_channel, src_ep, dst_ep, payload, payload.size()))
        {
            ++enqueued;
        }
    }
    ASSERT_EQ(enqueued, 4U);

    std::size_t dropped = 0;
    for (std::size_t i = 0; i < 3; ++i)
    {
        if (!tproxy_client::enqueue_udp_packet(dispatch_channel, src_ep, dst_ep, payload, payload.size()))
        {
            ++dropped;
        }
    }
    ASSERT_EQ(dropped, 3U);

    const auto resp = request_metrics_with_retry(port);
    const auto enqueued_metric = parse_metric_value(resp, "socks_tproxy_udp_dispatch_enqueued_total");
    const auto dropped_metric = parse_metric_value(resp, "socks_tproxy_udp_dispatch_dropped_total");
    ASSERT_TRUE(enqueued_metric.has_value());
    ASSERT_TRUE(dropped_metric.has_value());
    if (!enqueued_metric.has_value() || !dropped_metric.has_value())
    {
        return;
    }
    ASSERT_GE(*enqueued_metric, enqueued_before);
    ASSERT_GE(*dropped_metric, dropped_before);

    const auto delta_enqueued = *enqueued_metric - enqueued_before;
    const auto delta_dropped = *dropped_metric - dropped_before;
    EXPECT_GE(delta_enqueued, enqueued);
    EXPECT_GE(delta_dropped, dropped);

    const auto denominator = delta_enqueued + delta_dropped;
    ASSERT_GT(denominator, 0U);
    const double drop_ratio = static_cast<double>(delta_dropped) / static_cast<double>(denominator);
    EXPECT_GT(drop_ratio, 0.0);
    EXPECT_LT(drop_ratio, 1.0);

    dispatch_channel.close();
}

TEST(MonitorServerTest, EscapesPrometheusLabels)
{
    auto& stats = statistics::instance();
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "line1\"x\\y\nline2");

    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_metrics_with_retry(port);
    EXPECT_NE(resp.find("reason=\"short_id\""), std::string::npos);
    EXPECT_NE(resp.find("sni=\"line1\\\"x\\\\y\\nline2\""), std::string::npos);
}

TEST(MonitorServerTest, StartFailsWhenPortAlreadyInUse)
{
    boost::asio::io_context guard_ioc;
    boost::asio::ip::tcp::acceptor guard(guard_ioc);
    ASSERT_TRUE(open_ephemeral_loopback_acceptor(guard));
    boost::system::error_code ec;
    const auto port = guard.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(server->start(), -1);
}

TEST(MonitorServerTest, StartHandlesInvalidBindHost)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);
    ASSERT_TRUE(server->acceptor_.is_open());
    boost::system::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);
    server->stop();
    drain_io_context(ioc);
    auto bad_server = std::make_shared<monitor_server>(ioc, std::string("bad host"), port);
    ASSERT_NE(bad_server, nullptr);
    EXPECT_EQ(bad_server->start(), -1);
    EXPECT_FALSE(bad_server->acceptor_.is_open());
}

TEST(MonitorServerTest, StartHandlesOpenFailure)
{
    boost::asio::io_context ioc;
    monitor_fail_guard const guard(monitor_fail_mode::kSocketAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(server->start(), -1);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StartHandlesReuseAddressFailure)
{
    boost::asio::io_context ioc;
    monitor_fail_guard const guard(monitor_fail_mode::kReuseAddrAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(server->start(), -1);
}

TEST(MonitorServerTest, StartHandlesListenFailure)
{
    boost::asio::io_context ioc;
    monitor_fail_guard const guard(monitor_fail_mode::kListenAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(server->start(), -1);
}

TEST(MonitorServerTest, StartAndStopLifecycle)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());

    EXPECT_EQ(server->start(), 0);
    EXPECT_TRUE(server->acceptor_.is_open());

    server->stop();
    drain_io_context(ioc);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StartWhileRunningReturnsError)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);
    EXPECT_TRUE(server->acceptor_.is_open());

    EXPECT_EQ(server->start(), -1);
    EXPECT_TRUE(server->acceptor_.is_open());

    boost::system::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    std::thread runner([&ioc]() { ioc.run(); });
    const auto response = request_metrics_with_retry(port);
    EXPECT_NE(response.find("socks_uptime_seconds "), std::string::npos);

    server->stop();
    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, StopClosesAcceptorAndRejectsNewConnections)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);
    boost::system::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    std::thread runner([&ioc]() { ioc.run(); });

    const auto before_stop = request_metrics_with_retry(port);
    EXPECT_NE(before_stop.find("socks_uptime_seconds "), std::string::npos);

    server->stop();

    bool rejected = false;
    for (int i = 0; i < 30; ++i)
    {
        if (read_response(port, std::string(k_metrics_get_request)).empty())
        {
            rejected = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    EXPECT_TRUE(rejected);

    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, StopRunsInlineWhenIoContextStopped)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);
    ASSERT_TRUE(server->acceptor_.is_open());

    ioc.stop();
    server->stop();
    EXPECT_TRUE(server->acceptor_.is_open());
    drain_io_context(ioc);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StopRunsWhenIoQueueBlocked)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(ioc,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread runner([&ioc]() { ioc.run(); });
    for (int i = 0; i < 100 && !blocker_started.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(blocker_started.load(std::memory_order_acquire));

    server->stop();
    EXPECT_TRUE(server->acceptor_.is_open());

    release_blocker.store(true, std::memory_order_release);
    if (runner.joinable())
    {
        runner.join();
    }
    drain_io_context(ioc);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StopRunsWhenIoContextNotRunning)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);
    ASSERT_TRUE(server->acceptor_.is_open());

    server->stop();
    EXPECT_TRUE(server->acceptor_.is_open());
    drain_io_context(ioc);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StopLogsAcceptorCloseFailureBranch)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    ASSERT_EQ(server->start(), 0);

    std::thread runner([&ioc]() { ioc.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    fail_next_close(EIO);
    server->stop();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, AcceptFailureThenStopIsSafe)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    fail_next_accept(EIO);
    connect_and_close_without_payload(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    SUCCEED();
}

TEST(MonitorServerTest, SessionReadErrorPathStillAcceptsNextClient)
{
    monitor_server_env const env(0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    connect_and_close_without_payload(port);
    const auto resp = request_metrics_with_retry(port);
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, StopBeforeStartIsSafe)
{
    boost::asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());

    server->stop();
    drain_io_context(ioc);
    EXPECT_FALSE(server->acceptor_.is_open());
}

}    // namespace mux
