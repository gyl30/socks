#include <array>
#include <chrono>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <sys/socket.h>
#include <unistd.h>

#include <asio.hpp>
#include <gtest/gtest.h>

#define private public
#include "monitor_server.h"
#undef private
#include "statistics.h"

namespace
{

enum class monitor_fail_mode
{
    kNone = 0,
    kSocket,
    kSocketAlways,
    kReuseAddr,
    kReuseAddrAlways,
    kListen,
    kListenAlways,
};

std::atomic<int> g_monitor_fail_mode{static_cast<int>(monitor_fail_mode::kNone)};
std::atomic<bool> g_fail_accept_once{false};
std::atomic<int> g_fail_accept_errno{EIO};
std::atomic<bool> g_fail_close_once{false};
std::atomic<int> g_fail_close_errno{EIO};

class monitor_fail_guard
{
   public:
    explicit monitor_fail_guard(const monitor_fail_mode mode)
    {
        g_monitor_fail_mode.store(static_cast<int>(mode), std::memory_order_release);
    }

    ~monitor_fail_guard() { g_monitor_fail_mode.store(static_cast<int>(monitor_fail_mode::kNone), std::memory_order_release); }
};

bool should_fail_monitor_mode(const monitor_fail_mode once_mode, const monitor_fail_mode always_mode)
{
    const auto current = static_cast<monitor_fail_mode>(g_monitor_fail_mode.load(std::memory_order_acquire));
    if (current == always_mode)
    {
        return true;
    }
    if (current == once_mode)
    {
        g_monitor_fail_mode.store(static_cast<int>(monitor_fail_mode::kNone), std::memory_order_release);
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

std::string read_response(std::uint16_t port,
                          const std::string& request,
                          const std::string& remote_host = "127.0.0.1",
                          const std::string& local_host = "")
{
    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    const auto remote_addr = asio::ip::make_address(remote_host, ec);
    if (ec)
    {
        return {};
    }
    if (!local_host.empty())
    {
        const auto local_addr = asio::ip::make_address(local_host, ec);
        if (ec)
        {
            return {};
        }
        socket.open(local_addr.is_v6() ? asio::ip::tcp::v6() : asio::ip::tcp::v4(), ec);
        if (ec)
        {
            return {};
        }
        socket.bind(asio::ip::tcp::endpoint(local_addr, 0), ec);
        if (ec)
        {
            return {};
        }
    }
    socket.connect(asio::ip::tcp::endpoint(remote_addr, port), ec);
    if (ec)
    {
        return {};
    }

    asio::write(socket, asio::buffer(request), ec);
    if (ec)
    {
        return {};
    }

    std::string out;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(asio::buffer(buffer), ec);
        if (n > 0)
        {
            out.append(buffer.data(), n);
        }
        if (ec == asio::error::eof)
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

void connect_and_close_without_payload(const std::uint16_t port)
{
    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec)
    {
        return;
    }
    socket.close(ec);
}

std::string random_identifier(std::mt19937& rng, const std::size_t min_len, const std::size_t max_len)
{
    static constexpr std::string_view kAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<std::size_t> len_dist(min_len, max_len);
    const std::size_t len = len_dist(rng);
    std::string out;
    out.reserve(len);
    std::uniform_int_distribution<std::size_t> char_dist(0, kAlphabet.size() - 1);
    for (std::size_t i = 0; i < len; ++i)
    {
        out.push_back(kAlphabet[char_dist(rng)]);
    }
    return out;
}

std::string mutate_token_value(std::mt19937& rng, const std::string& token)
{
    std::string out = token;
    std::uniform_int_distribution<int> op_dist(0, 2);
    const int op = op_dist(rng);
    if (op == 0 || out.empty())
    {
        if (out.empty())
        {
            out.push_back('x');
            return out;
        }
        std::uniform_int_distribution<std::size_t> pos_dist(0, out.size() - 1);
        const std::size_t pos = pos_dist(rng);
        out[pos] = out[pos] == 'x' ? 'y' : 'x';
    }
    else if (op == 1)
    {
        out.push_back('x');
    }
    else if (out.size() > 1)
    {
        std::uniform_int_distribution<std::size_t> pos_dist(0, out.size() - 1);
        out.erase(pos_dist(rng), 1);
    }
    else
    {
        out = "xx";
    }
    if (out == token)
    {
        out.push_back('x');
    }
    return out;
}

class monitor_server_env
{
   public:
    template <typename... Args>
    explicit monitor_server_env(Args&&... args)
    {
        auto ctor_args = std::make_tuple(std::forward<Args>(args)...);
        for (std::uint32_t attempt = 0; attempt < 120; ++attempt)
        {
            server_ = std::apply(
                [this](auto&&... unpacked)
                {
                    return std::make_shared<mux::monitor_server>(ioc_, unpacked...);
                },
                ctor_args);
            server_->start();
            if (server_->acceptor_.is_open())
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
        std::error_code ec;
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
    }

   private:
    asio::io_context ioc_;
    std::shared_ptr<mux::monitor_server> server_;
    std::thread thread_;
};

}    // namespace

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
    if (level == SOL_SOCKET && optname == SO_REUSEADDR
        && should_fail_monitor_mode(monitor_fail_mode::kReuseAddr, monitor_fail_mode::kReuseAddrAlways))
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
        errno = g_fail_close_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_close(fd);
}

namespace mux
{

TEST(MonitorServerTest, EmptyTokenReturnsMetrics)
{
    statistics::instance().inc_total_connections();

    monitor_server_env env(0, std::string());
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
    EXPECT_NE(resp.find("socks_total_connections "), std::string::npos);
    EXPECT_NE(resp.find("socks_auth_failures_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_connection_limit_rejected_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_stream_limit_rejected_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_monitor_auth_failures_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_monitor_rate_limited_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_fallback_no_target_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_fallback_resolve_failures_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_fallback_connect_failures_total "), std::string::npos);
    EXPECT_NE(resp.find("socks_fallback_write_failures_total "), std::string::npos);
}

TEST(MonitorServerTest, TokenRequiredAndRateLimit)
{
    auto& stats = statistics::instance();
    const auto monitor_auth_before = stats.monitor_auth_failures();
    const auto monitor_rate_before = stats.monitor_rate_limited();

    monitor_server_env env(0, std::string("secret"), 500);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto warmup = request_with_retry(port, "metrics?token=secret\n");
    EXPECT_NE(warmup.find("socks_total_connections "), std::string::npos);

    std::this_thread::sleep_for(std::chrono::milliseconds(550));

    const auto unauth = read_response(port, "metrics\n");
    EXPECT_TRUE(unauth.empty());

    const auto authed = read_response(port, "metrics?token=secret\n");
    EXPECT_NE(authed.find("socks_total_connections "), std::string::npos);

    const auto limited = read_response(port, "metrics?token=secret\n");
    EXPECT_TRUE(limited.empty());
    EXPECT_GT(stats.monitor_rate_limited(), monitor_rate_before);
    EXPECT_GT(stats.monitor_auth_failures(), monitor_auth_before);

    std::this_thread::sleep_for(std::chrono::milliseconds(550));
    const auto after_window = read_response(port, "metrics?token=secret\n");
    EXPECT_NE(after_window.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, UnauthorizedRequestDoesNotConsumeRateLimitWindow)
{
    monitor_server_env env(0, std::string("secret"), 500);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto first_authed = request_with_retry(port, "metrics?token=secret\n");
    EXPECT_NE(first_authed.find("socks_total_connections "), std::string::npos);

    std::this_thread::sleep_for(std::chrono::milliseconds(550));

    const auto unauth = read_response(port, "metrics\n");
    EXPECT_TRUE(unauth.empty());

    const auto authed_after_unauth = read_response(port, "metrics?token=secret\n");
    EXPECT_NE(authed_after_unauth.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, RateLimitIsolatedBySourceAddress)
{
    monitor_rate_state rate_state;
    constexpr std::uint32_t k_min_interval_ms = 500;
    const auto now = std::chrono::steady_clock::now();

    EXPECT_TRUE(detail::allow_monitor_request_by_source(rate_state, "127.0.0.1", k_min_interval_ms, now));
    EXPECT_FALSE(detail::allow_monitor_request_by_source(
        rate_state, "127.0.0.1", k_min_interval_ms, now + std::chrono::milliseconds(100)));
    EXPECT_TRUE(detail::allow_monitor_request_by_source(
        rate_state, "127.0.0.2", k_min_interval_ms, now + std::chrono::milliseconds(100)));

    std::lock_guard<std::mutex> lock(rate_state.mutex);
    EXPECT_EQ(rate_state.last_request_time_by_source.count("127.0.0.1"), 1U);
    EXPECT_EQ(rate_state.last_request_time_by_source.count("127.0.0.2"), 1U);
}

TEST(MonitorServerTest, RateLimitBySourceDisabledWhenMinIntervalZero)
{
    monitor_rate_state rate_state;
    const auto now = std::chrono::steady_clock::now();

    EXPECT_TRUE(detail::allow_monitor_request_by_source(rate_state, "127.0.0.1", 0, now));

    std::lock_guard<std::mutex> lock(rate_state.mutex);
    EXPECT_TRUE(rate_state.last_request_time_by_source.empty());
}

TEST(MonitorServerTest, RateLimitStateStaysBounded)
{
    constexpr std::size_t k_state_limit = 4096;

    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("secret"), 10);
    ASSERT_NE(server, nullptr);
    server->start();

    std::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    const auto stale_time = std::chrono::steady_clock::now() - std::chrono::hours(1);
    for (std::size_t i = 0; i < k_state_limit + 256; ++i)
    {
        server->rate_state_->last_request_time_by_source.emplace("stale-" + std::to_string(i), stale_time);
    }
    ASSERT_GT(server->rate_state_->last_request_time_by_source.size(), k_state_limit);

    std::thread runner([&ioc]() { ioc.run(); });
    const auto response = request_with_retry(port, "metrics?token=secret\n");
    EXPECT_NE(response.find("socks_uptime_seconds "), std::string::npos);

    server->stop();
    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }

    EXPECT_LE(server->rate_state_->last_request_time_by_source.size(), k_state_limit);
    EXPECT_NE(server->rate_state_->last_request_time_by_source.find("127.0.0.1"),
              server->rate_state_->last_request_time_by_source.end());
}

TEST(MonitorServerTest, RateLimitPruneSkipsEvictionWhenSourceAlreadyTrackedAtCapacity)
{
    constexpr std::size_t k_state_limit = 4096;

    monitor_rate_state rate_state;
    const auto now = std::chrono::steady_clock::now();
    rate_state.last_request_time_by_source.emplace("hot-source", now - std::chrono::seconds(1));
    for (std::size_t i = 0; i < k_state_limit - 1; ++i)
    {
        rate_state.last_request_time_by_source.emplace("src-" + std::to_string(i), now);
    }
    ASSERT_EQ(rate_state.last_request_time_by_source.size(), k_state_limit);

    EXPECT_TRUE(detail::allow_monitor_request_by_source(rate_state, "hot-source", 500, now));

    std::lock_guard<std::mutex> lock(rate_state.mutex);
    EXPECT_EQ(rate_state.last_request_time_by_source.size(), k_state_limit);
    EXPECT_EQ(rate_state.last_request_time_by_source.count("hot-source"), 1U);
}

TEST(MonitorServerTest, RateLimitPruneEvictsOldestSourceWhenCapacityReached)
{
    constexpr std::size_t k_state_limit = 4096;

    monitor_rate_state rate_state;
    const auto now = std::chrono::steady_clock::now();
    rate_state.last_request_time_by_source.emplace("oldest-source", now - std::chrono::seconds(30));
    for (std::size_t i = 0; i < k_state_limit - 1; ++i)
    {
        rate_state.last_request_time_by_source.emplace("src-" + std::to_string(i), now);
    }
    ASSERT_EQ(rate_state.last_request_time_by_source.size(), k_state_limit);

    EXPECT_TRUE(detail::allow_monitor_request_by_source(rate_state, "new-source", 500, now));

    std::lock_guard<std::mutex> lock(rate_state.mutex);
    EXPECT_EQ(rate_state.last_request_time_by_source.size(), k_state_limit);
    EXPECT_EQ(rate_state.last_request_time_by_source.count("oldest-source"), 0U);
    EXPECT_EQ(rate_state.last_request_time_by_source.count("new-source"), 1U);
}

TEST(MonitorServerTest, RejectsTokenSubstringBypass)
{
    monitor_server_env env(0, std::string("secret"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto contains_secret_without_token_key = read_response(port, "metrics?foo=secret\n");
    EXPECT_TRUE(contains_secret_without_token_key.empty());

    const auto prefixed_token_key = read_response(port, "metrics?xtoken=secret\n");
    EXPECT_TRUE(prefixed_token_key.empty());

    const auto wrong_token_value = read_response(port, "metrics?token=secretx\n");
    EXPECT_TRUE(wrong_token_value.empty());

    const auto authed = request_with_retry(port, "metrics?token=secret\n");
    EXPECT_NE(authed.find("socks_total_connections "), std::string::npos);
}

TEST(MonitorServerTest, SupportsMultiParamTokenWithTrimmedLineAndUrlDecoding)
{
    monitor_server_env env(0, std::string("a ~"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto authed = request_with_retry(port, "metrics?foo=1&token=a+%7e   \n");
    EXPECT_NE(authed.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, EnforcesPathAndSupportsHttpUrlDecodedToken)
{
    monitor_server_env env(0, std::string("s+e/c"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto invalid_path = read_response(port, "GET /status?token=s%2Be%2Fc HTTP/1.1\r\n\r\n");
    EXPECT_TRUE(invalid_path.empty());

    const auto invalid_method = read_response(port, "POST /metrics?token=s%2Be%2Fc HTTP/1.1\r\n\r\n");
    EXPECT_TRUE(invalid_method.empty());

    const auto authed = request_with_retry(port, "GET /metrics?token=s%2Be%2Fc HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    EXPECT_NE(authed.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, SupportsFragmentedHttpRequestLine)
{
    monitor_server_env env(0, std::string("secret"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    ASSERT_FALSE(ec);

    asio::write(socket, asio::buffer("GET /metrics?token=secret HT"), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    asio::write(socket, asio::buffer("TP/1.1\r\nHost: 127.0.0.1\r\n\r\n"), ec);
    ASSERT_FALSE(ec);

    std::string resp;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(asio::buffer(buffer), ec);
        if (n > 0)
        {
            resp.append(buffer.data(), n);
        }
        if (ec == asio::error::eof)
        {
            break;
        }
        if (ec)
        {
            break;
        }
    }

    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, RejectsInvalidPercentEncodingToken)
{
    monitor_server_env env(0, std::string("secret"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto invalid = read_response(port, "GET /metrics?token=sec%2xret HTTP/1.1\r\n\r\n");
    EXPECT_TRUE(invalid.empty());

    const auto valid = request_with_retry(port, "GET /metrics?token=secret HTTP/1.1\r\n\r\n");
    EXPECT_NE(valid.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, RejectsMalformedHttpRequestLine)
{
    monitor_server_env env(0, std::string("secret"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto malformed = read_response(port, "GET    HTTP/1.1\r\n\r\n");
    EXPECT_TRUE(malformed.empty());

    const auto valid = request_with_retry(port, "GET /metrics?token=secret HTTP/1.1\r\n\r\n");
    EXPECT_NE(valid.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, EmptyLineRequestWithEmptyTokenIsRejected)
{
    auto& stats = statistics::instance();
    const auto auth_failures_before = stats.monitor_auth_failures();

    monitor_server_env env(0, std::string());
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const auto resp = read_response(port, "\n");
    EXPECT_TRUE(resp.empty());
    EXPECT_GT(stats.monitor_auth_failures(), auth_failures_before);
}

TEST(MonitorServerTest, RejectsOversizedRequestLineAndKeepsServing)
{
    monitor_server_env env(0, std::string("secret"));
    const auto port = env.port();
    ASSERT_NE(port, 0);

    const std::string oversized_line = "GET /metrics?token=secret" + std::string(5000, 'a') + " HTTP/1.1\r\n\r\n";
    const auto oversized = read_response(port, oversized_line);
    EXPECT_TRUE(oversized.empty());

    const auto valid = request_with_retry(port, "GET /metrics?token=secret HTTP/1.1\r\n\r\n");
    EXPECT_NE(valid.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, PropertyFuzzAuthBypassNearMissesAreRejected)
{
    constexpr std::string_view kToken = "secret";
    monitor_server_env env(0, std::string(kToken), 0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    std::mt19937 rng(20260217u);
    const std::array<std::string_view, 4> bad_methods = {"POST", "PUT", "HEAD", "GETT"};
    const std::array<std::string_view, 4> bad_paths = {"/status", "/metricsx", "metricsx", "/"};
    const std::array<std::string_view, 4> bad_keys = {"foo", "xtoken", "tokenx", "t0ken"};

    for (std::size_t i = 0; i < 160; ++i)
    {
        std::string request;
        const auto variant = i % 5;
        if (variant == 0)
        {
            std::uniform_int_distribution<std::size_t> dist(0, bad_methods.size() - 1);
            request = std::string(bad_methods[dist(rng)]) + " /metrics?token=secret HTTP/1.1\r\n\r\n";
        }
        else if (variant == 1)
        {
            std::uniform_int_distribution<std::size_t> dist(0, bad_paths.size() - 1);
            request = "GET " + std::string(bad_paths[dist(rng)]) + "?token=secret HTTP/1.1\r\n\r\n";
        }
        else if (variant == 2)
        {
            std::uniform_int_distribution<std::size_t> dist(0, bad_keys.size() - 1);
            request = "GET /metrics?" + std::string(bad_keys[dist(rng)]) + "=secret HTTP/1.1\r\n\r\n";
        }
        else if (variant == 3)
        {
            request = "GET /metrics?token=%2xsecret HTTP/1.1\r\n\r\n";
        }
        else
        {
            request = "GET /metrics?token=" + mutate_token_value(rng, std::string(kToken)) + " HTTP/1.1\r\n\r\n";
        }

        const auto resp = read_response(port, request);
        EXPECT_TRUE(resp.empty()) << "unexpected authorized request: " << request;
    }

    const auto valid = request_with_retry(port, "GET /metrics?token=secret HTTP/1.1\r\n\r\n");
    EXPECT_NE(valid.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, PropertyFuzzMalformedLinesDoNotPoisonServerState)
{
    monitor_server_env env(0, std::string("secret"), 0);
    const auto port = env.port();
    ASSERT_NE(port, 0);

    std::mt19937 rng(1337u);
    for (std::size_t i = 0; i < 120; ++i)
    {
        std::string request_line = random_identifier(rng, 1, 40);
        if (i % 3 == 0)
        {
            request_line = "GET" + random_identifier(rng, 1, 30);
        }
        else if (i % 3 == 1)
        {
            request_line = "GET " + random_identifier(rng, 1, 20) + " HTTP/1.1";
        }
        else
        {
            request_line = random_identifier(rng, 1, 10) + " /metrics?token=secret HTTP/1.1";
        }
        const auto resp = read_response(port, request_line + "\r\n\r\n");
        EXPECT_TRUE(resp.empty()) << "malformed line unexpectedly succeeded: " << request_line;
    }

    const auto valid = request_with_retry(port, "GET /metrics?token=secret HTTP/1.1\r\n\r\n");
    EXPECT_NE(valid.find("socks_total_connections "), std::string::npos);
}

TEST(MonitorServerTest, EscapesPrometheusLabels)
{
    auto& stats = statistics::instance();
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "line1\"x\\y\nline2");

    monitor_server_env env(0, std::string());
    const auto port = env.port();
    ASSERT_NE(port, 0);
    const auto resp = request_with_retry(port, "metrics\n");

    EXPECT_NE(resp.find("reason=\"short_id\""), std::string::npos);
    EXPECT_NE(resp.find("sni=\"line1\\\"x\\\\y\\nline2\""), std::string::npos);
}

TEST(MonitorServerTest, ConstructWhenPortAlreadyInUse)
{
    asio::io_context guard_ioc;
    asio::ip::tcp::acceptor guard(guard_ioc);
    asio::error_code ec;
    guard.open(asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    guard.set_option(asio::socket_base::reuse_address(true), ec);
    ASSERT_FALSE(ec);
    guard.bind(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    guard.listen(asio::socket_base::max_listen_connections, ec);
    ASSERT_FALSE(ec);
    const auto port = guard.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, port, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, ConstructorHandlesInvalidBindHost)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    ASSERT_TRUE(server->acceptor_.is_open());
    std::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);
    auto bad_server = std::make_shared<monitor_server>(ioc, std::string("bad host"), port, std::string("token"), 10);
    ASSERT_NE(bad_server, nullptr);
    EXPECT_FALSE(bad_server->acceptor_.is_open());
    bad_server->start();
    ioc.poll();
}

TEST(MonitorServerTest, ConstructorHandlesOpenFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kSocketAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, ConstructorHandlesReuseAddressFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kReuseAddrAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, ConstructorHandlesListenFailure)
{
    asio::io_context ioc;
    monitor_fail_guard guard(monitor_fail_mode::kListenAlways);
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string("token"), 10);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, RunningReflectsStartAndStopLifecycle)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    EXPECT_FALSE(server->running());

    server->start();
    EXPECT_TRUE(server->running());

    server->stop();
    EXPECT_FALSE(server->running());
}

TEST(MonitorServerTest, StartWhileRunningIsIgnored)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();
    EXPECT_TRUE(server->running());

    server->start();
    EXPECT_TRUE(server->running());

    std::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    std::thread runner([&ioc]() { ioc.run(); });
    const auto response = request_with_retry(port, "metrics\n");
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
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();
    std::error_code ec;
    const auto port = server->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(port, 0);

    std::thread runner([&ioc]() { ioc.run(); });

    const auto before_stop = request_with_retry(port, "metrics\n");
    EXPECT_NE(before_stop.find("socks_uptime_seconds "), std::string::npos);

    server->stop();

    bool rejected = false;
    for (int i = 0; i < 30; ++i)
    {
        if (read_response(port, "metrics\n").empty())
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
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    ASSERT_TRUE(server->acceptor_.is_open());

    ioc.stop();
    server->stop();
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StopRunsWhenIoQueueBlocked)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    asio::post(
        ioc,
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
    EXPECT_FALSE(server->acceptor_.is_open());

    release_blocker.store(true, std::memory_order_release);
    ioc.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(MonitorServerTest, StopRunsWhenIoContextNotRunning)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    ASSERT_TRUE(server->acceptor_.is_open());

    server->stop();
    EXPECT_FALSE(server->acceptor_.is_open());
}

TEST(MonitorServerTest, StopLogsAcceptorCloseFailureBranch)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    server->start();

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

TEST(MonitorServerTest, AcceptFailureRetriesAndServesRequest)
{
    monitor_server_env env(0, std::string());
    const auto port = env.port();
    ASSERT_NE(port, 0);

    fail_next_accept(EIO);
    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, SessionReadErrorPathStillAcceptsNextClient)
{
    monitor_server_env env(0, std::string());
    const auto port = env.port();
    ASSERT_NE(port, 0);

    connect_and_close_without_payload(port);
    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, DoAcceptReturnsImmediatelyWhenStopped)
{
    asio::io_context ioc;
    auto server = std::make_shared<monitor_server>(ioc, 0, std::string(), 10);
    ASSERT_NE(server, nullptr);
    ASSERT_TRUE(server->acceptor_.is_open());

    server->stop_.store(true, std::memory_order_release);
    server->do_accept();
    ioc.poll();

    EXPECT_TRUE(server->acceptor_.is_open());
}

}    // namespace mux
