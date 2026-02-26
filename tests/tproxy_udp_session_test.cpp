#include <array>
#include <mutex>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <cstring>
#include <charconv>
#include <optional>
#include <algorithm>
#include <string_view>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/spdlog.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <spdlog/sinks/base_sink.h>
#include <boost/asio/io_context.hpp>

extern "C"
{
#include <openssl/evp.h>
}

#include "router.h"
#include "protocol.h"
#include "mux_codec.h"
#include "test_util.h"
#include "ip_matcher.h"
#include "mux_stream.h"
#include "statistics.h"
#include "context_pool.h"
#include "domain_matcher.h"

#define private public
#include "tproxy_client.h"
#include "monitor_server.h"
#include "tproxy_udp_session.h"

#undef private
#include "mock_mux_connection.h"

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
    kOrigdstTruncated,
    kPayloadTruncated,
    kSyntheticValid,
    kSyntheticValidSticky
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
std::atomic<bool> g_recvmsg_mode_sticky{false};
std::atomic<bool> g_force_ipv6_socket_compat{false};
std::atomic<int> g_socket_delay_ms{0};
std::atomic<int> g_socket_delay_entered{0};

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
    g_recvmsg_mode_sticky.store(false, std::memory_order_release);
    g_force_ipv6_socket_compat.store(false, std::memory_order_release);
    g_socket_delay_ms.store(0, std::memory_order_release);
    g_socket_delay_entered.store(0, std::memory_order_release);
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

void set_recvmsg_mode_once(const wrapped_recvmsg_mode mode)
{
    g_recvmsg_mode_sticky.store(false, std::memory_order_release);
    g_recvmsg_mode.store(static_cast<int>(mode), std::memory_order_release);
}

void set_recvmsg_mode_sticky(const wrapped_recvmsg_mode mode)
{
    g_recvmsg_mode.store(static_cast<int>(mode), std::memory_order_release);
    g_recvmsg_mode_sticky.store(true, std::memory_order_release);
}
void force_ipv6_socket_compat(const bool enable) { g_force_ipv6_socket_compat.store(enable, std::memory_order_release); }

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
auto run_on_io_context(boost::asio::io_context& io_context, Func&& fn) -> decltype(fn())
{
    using result_type = decltype(fn());
    std::promise<result_type> promise;
    auto future = promise.get_future();
    boost::asio::post(io_context, [func = std::forward<Func>(fn), promise = std::move(promise)]() mutable { promise.set_value(func()); });
    return future.get();
}

bool tcp_acceptor_is_open(boost::asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->tcp_acceptor_.is_open(); });
}

bool udp_socket_is_open(boost::asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(io_context, [client]() { return client->udp_socket_.is_open(); });
}

bool tcp_acceptor_local_is_v4(boost::asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(
        io_context,
        [client]()
        {
            if (!client->tcp_acceptor_.is_open())
            {
                return false;
            }
            boost::system::error_code ec;
            const auto ep = client->tcp_acceptor_.local_endpoint(ec);
            return !ec && ep.address().is_v4();
        });
}

bool udp_socket_local_is_v4(boost::asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    return run_on_io_context(
        io_context,
        [client]()
        {
            if (!client->udp_socket_.is_open())
            {
                return false;
            }
            boost::system::error_code ec;
            const auto ep = client->udp_socket_.local_endpoint(ec);
            return !ec && ep.address().is_v4();
        });
}

std::shared_ptr<mux::tproxy_client::udp_session_map_t> snapshot_udp_sessions(const std::shared_ptr<mux::tproxy_client>& client)
{
    auto snapshot = std::atomic_load_explicit(&client->udp_sessions_, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<mux::tproxy_client::udp_session_map_t>();
}

std::shared_ptr<mux::mux_connection::stream_map_t> snapshot_connection_streams(const std::shared_ptr<mux::mux_connection>& conn)
{
    auto snapshot = std::atomic_load_explicit(&conn->streams_, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<mux::mux_connection::stream_map_t>();
}

bool connection_has_stream(const std::shared_ptr<mux::mux_connection>& conn, const std::uint32_t id)
{
    const auto snapshot = snapshot_connection_streams(conn);
    return snapshot->find(id) != snapshot->end();
}

void emplace_udp_session(boost::asio::io_context& io_context,
                         const std::shared_ptr<mux::tproxy_client>& client,
                         const std::string& key,
                         const std::shared_ptr<mux::tproxy_udp_session>& session)
{
    (void)io_context;
    for (;;)
    {
        auto current = snapshot_udp_sessions(client);
        auto updated = std::make_shared<mux::tproxy_client::udp_session_map_t>(*current);
        (*updated)[key] = session;
        if (std::atomic_compare_exchange_weak_explicit(
                &client->udp_sessions_, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

std::size_t udp_session_count(boost::asio::io_context& io_context, const std::shared_ptr<mux::tproxy_client>& client)
{
    (void)io_context;
    return snapshot_udp_sessions(client)->size();
}

bool udp_sessions_empty(const std::shared_ptr<mux::tproxy_client>& client) { return snapshot_udp_sessions(client)->empty(); }

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

class block_router final : public mux::router
{
   public:
    block_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();

        block_ip_matcher()->add_rule("0.0.0.0/0");
        block_ip_matcher()->add_rule("::/0");
        block_ip_matcher()->optimize();
    }
};

class failing_load_router final : public mux::router
{
   public:
    bool load() override { return false; }
};

class always_load_router final : public mux::router
{
   public:
    bool load() override { return true; }
};

std::uint64_t now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool open_ephemeral_tcp_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                                 const std::uint32_t max_attempts = 120,
                                 const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (acceptor.is_open())
        {
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)acceptor.close(ec);
        }
        ec = acceptor.open(boost::asio::ip::tcp::v4(), ec);
        if (!ec)
        {
            ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        }
        if (!ec)
        {
            ec = acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0), ec);
        }
        if (!ec)
        {
            ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

bool open_ephemeral_udp_socket(boost::asio::ip::udp::socket& socket,
                               const std::uint32_t max_attempts = 120,
                               const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (socket.is_open())
        {
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)socket.close(ec);
        }
        ec = socket.open(boost::asio::ip::udp::v4(), ec);
        if (!ec)
        {
            ec = socket.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

bool open_ephemeral_udp_socket_v6(boost::asio::ip::udp::socket& socket,
                                  const std::uint32_t max_attempts = 120,
                                  const std::chrono::milliseconds backoff = std::chrono::milliseconds(25))
{
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        boost::system::error_code ec;
        if (socket.is_open())
        {
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            (void)socket.close(ec);
        }
        ec = socket.open(boost::asio::ip::udp::v6(), ec);
        if (!ec)
        {
            ec = socket.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::loopback(), 0), ec);
        }
        if (!ec)
        {
            return true;
        }
        std::this_thread::sleep_for(backoff);
    }
    return false;
}

std::uint16_t pick_free_tcp_port()
{
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(io_context);
    if (!open_ephemeral_tcp_acceptor(acceptor))
    {
        return 0;
    }
    return acceptor.local_endpoint().port();
}

std::uint16_t pick_free_udp_port()
{
    boost::asio::io_context io_context;
    boost::asio::ip::udp::socket socket(io_context);
    if (!open_ephemeral_udp_socket(socket))
    {
        return 0;
    }
    return socket.local_endpoint().port();
}

std::string read_monitor_response(const std::uint16_t port, const std::string& request)
{
    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket socket(ioc);
    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port), ec);
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

std::string request_monitor_response_with_retry(const std::uint16_t port, const std::string& request)
{
    for (int i = 0; i < 30; ++i)
    {
        const auto response = read_monitor_response(port, request);
        if (!response.empty())
        {
            return response;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return read_monitor_response(port, request);
}

std::optional<std::uint64_t> parse_metric_counter(const std::string& response, const std::string_view metric_name)
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
        if (line.size() >= prefix.size() && line.substr(0, prefix.size()) == prefix)
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

template <typename Mutex>
class drop_log_sink : public spdlog::sinks::base_sink<Mutex>
{
   public:
    [[nodiscard]] std::size_t drop_warn_count() const { return drop_warn_count_.load(std::memory_order_acquire); }

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        const std::string_view payload(msg.payload.data(), msg.payload.size());
        if (payload.find("tproxy udp dispatch queue full dropping packet") != std::string_view::npos)
        {
            drop_warn_count_.fetch_add(1, std::memory_order_acq_rel);
        }
    }

    void flush_() override {}

   private:
    std::atomic<std::size_t> drop_warn_count_{0};
};

using drop_log_sink_t = drop_log_sink<std::mutex>;

template <typename Mutex>
class text_match_log_sink : public spdlog::sinks::base_sink<Mutex>
{
   public:
    explicit text_match_log_sink(std::string text) : text_(std::move(text)) {}

    [[nodiscard]] std::size_t match_count() const { return match_count_.load(std::memory_order_acquire); }

   protected:
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        const std::string_view payload(msg.payload.data(), msg.payload.size());
        if (!text_.empty() && payload.find(text_) != std::string_view::npos)
        {
            match_count_.fetch_add(1, std::memory_order_acq_rel);
        }
    }

    void flush_() override {}

   private:
    std::string text_;
    std::atomic<std::size_t> match_count_{0};
};

using text_match_log_sink_t = text_match_log_sink<std::mutex>;

class scoped_default_logger_override
{
   public:
    explicit scoped_default_logger_override(std::shared_ptr<spdlog::logger> logger) : previous_(spdlog::default_logger())
    {
        spdlog::set_default_logger(std::move(logger));
    }

    ~scoped_default_logger_override() { spdlog::set_default_logger(previous_); }

   private:
    std::shared_ptr<spdlog::logger> previous_;
};

}    // namespace

extern "C" int __wrap_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)    
{
    const bool level_match = (g_fail_setsockopt_level.load(std::memory_order_acquire) == level);
    const bool optname_match = (g_fail_setsockopt_optname.load(std::memory_order_acquire) == optname);
    if (level_match && optname_match && g_fail_setsockopt_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_setsockopt_errno.load(std::memory_order_acquire);
        return -1;
    }

    if (g_force_tproxy_sockopt_success.load(std::memory_order_acquire) && is_tproxy_setsockopt(level, optname))
    {
        return 0;
    }

    if (g_force_ipv6_socket_compat.load(std::memory_order_acquire) && (level == SOL_IPV6 || level == IPPROTO_IPV6) && optname == IPV6_V6ONLY)
    {
        return 0;
    }

    return __real_setsockopt(sockfd, level, optname, optval, optlen);    
}

extern "C" int __wrap_socket(int domain, int type, int protocol)    
{
    const auto delay_ms = g_socket_delay_ms.load(std::memory_order_acquire);
    if (delay_ms > 0)
    {
        g_socket_delay_entered.fetch_add(1, std::memory_order_acq_rel);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    if (g_force_ipv6_socket_compat.load(std::memory_order_acquire) && domain == AF_INET6)
    {
        return __real_socket(AF_INET, type, protocol);    
    }
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
    if (g_force_ipv6_socket_compat.load(std::memory_order_acquire) && addr != nullptr && addr->sa_family == AF_INET6)
    {
        return 0;
    }
    if (g_fail_bind_once.exchange(false, std::memory_order_acq_rel))
    {
        errno = g_fail_bind_errno.load(std::memory_order_acquire);
        return -1;
    }
    return __real_bind(sockfd, addr, addrlen);    
}

extern "C" ssize_t __wrap_recvmsg(int sockfd, msghdr* msg, int flags)    
{
    const wrapped_recvmsg_mode mode =
        g_recvmsg_mode_sticky.load(std::memory_order_acquire)
            ? static_cast<wrapped_recvmsg_mode>(g_recvmsg_mode.load(std::memory_order_acquire))
            : static_cast<wrapped_recvmsg_mode>(g_recvmsg_mode.exchange(static_cast<int>(wrapped_recvmsg_mode::kReal), std::memory_order_acq_rel));
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
    msg->msg_flags = 0;

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
    if (mode == wrapped_recvmsg_mode::kOrigdstTruncated)
    {
        msg->msg_flags |= MSG_CTRUNC;
        return static_cast<ssize_t>(n);
    }
    if (mode == wrapped_recvmsg_mode::kPayloadTruncated)
    {
        msg->msg_flags |= MSG_TRUNC;
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
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 1;

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 1, cfg, client_ep);
    session->start();

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    std::array<std::uint8_t, 1> const data = {0};
    boost::asio::co_spawn(
        ctx,
        [session, dst_ep, data]() -> boost::asio::awaitable<void> { co_await session->handle_packet(dst_ep, data.data(), data.size()); },
        boost::asio::detached);

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

TEST(TproxyUdpSessionTest, HandlePacketIncrementsRoutingBlockedWhenRouteBlocked)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<block_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    auto& stats = mux::statistics::instance();
    const auto blocked_before = stats.routing_blocked();

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12346);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 4, cfg, client_ep);

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    const std::array<std::uint8_t, 1> data = {0x00};
    boost::asio::co_spawn(
        ctx,
        [session, dst_ep, data]() -> boost::asio::awaitable<void> { co_await session->handle_packet(dst_ep, data.data(), data.size()); },
        boost::asio::detached);

    ctx.run();

    EXPECT_EQ(stats.routing_blocked(), blocked_before + 1);
}

TEST(TproxyUdpSessionTest, HandlePacketRejectsInvalidTargetEndpointBeforeRouting)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<block_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    auto& stats = mux::statistics::instance();
    const auto blocked_before = stats.routing_blocked();

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12366);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 38, cfg, client_ep);

    const std::array<std::uint8_t, 1> data = {0x00};
    const boost::asio::ip::udp::endpoint invalid_unspecified(boost::asio::ip::make_address("0.0.0.0"), 53);
    const boost::asio::ip::udp::endpoint invalid_port_zero(boost::asio::ip::make_address("127.0.0.1"), 0);

    boost::asio::co_spawn(
        ctx,
        [session, invalid_unspecified, data]() -> boost::asio::awaitable<void>
        {
            co_await session->handle_packet(invalid_unspecified, data.data(), data.size());
            co_return;
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        ctx,
        [session, invalid_port_zero, data]() -> boost::asio::awaitable<void>
        {
            co_await session->handle_packet(invalid_port_zero, data.data(), data.size());
            co_return;
        },
        boost::asio::detached);

    ctx.run();

    EXPECT_EQ(stats.routing_blocked(), blocked_before);
}

TEST(TproxyUdpSessionTest, HandlePacketPointerOverloadRejectsNullPayload)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12367);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 39, cfg, client_ep);

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    mux::test::run_awaitable_void(ctx, session->handle_packet(dst_ep, nullptr, 8));

    EXPECT_FALSE(session->terminated());
}

TEST(TproxyUdpSessionTest, HandlePacketPointerOverloadDropsEmptyPayloadBeforeRouting)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<block_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    auto& stats = mux::statistics::instance();
    const auto blocked_before = stats.routing_blocked();

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12368);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 40, cfg, client_ep);

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    const std::array<std::uint8_t, 1> data = {0x11};
    mux::test::run_awaitable_void(ctx, session->handle_packet(dst_ep, data.data(), 0));

    EXPECT_EQ(stats.routing_blocked(), blocked_before);
    EXPECT_FALSE(session->terminated());
}

TEST(TproxyUdpSessionTest, HandlePacketVectorOverloadDropsEmptyPayloadBeforeRouting)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<block_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    auto& stats = mux::statistics::instance();
    const auto blocked_before = stats.routing_blocked();

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12369);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 41, cfg, client_ep);

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    mux::test::run_awaitable_void(ctx, session->handle_packet(dst_ep, std::vector<std::uint8_t>{}));

    EXPECT_EQ(stats.routing_blocked(), blocked_before);
    EXPECT_FALSE(session->terminated());
}

TEST(TproxyUdpSessionTest, HandlePacketStopsWhenRouterMissing)
{
    boost::asio::io_context ctx;

    mux::config cfg;
    cfg.tproxy.mark = 0;

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12347);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, nullptr, nullptr, 35, cfg, client_ep);

    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53);
    const std::array<std::uint8_t, 1> data = {0x01};
    boost::asio::co_spawn(
        ctx,
        [session, dst_ep, data]() -> boost::asio::awaitable<void> { co_await session->handle_packet(dst_ep, data.data(), data.size()); },
        boost::asio::detached);

    ctx.run();

    EXPECT_TRUE(session->terminated());
}

TEST(TproxyUdpSessionTest, ProxyReadLoopDropsPacketWhenSenderMissing)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12348);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 36, cfg, client_ep);

    socks_udp_header header;
    header.addr = "127.0.0.1";
    header.port = 53;
    auto packet = socks_codec::encode_udp_header(header);
    packet.push_back(0x42);
    ASSERT_TRUE(session->recv_channel_.try_send(boost::system::error_code{}, std::move(packet)));
    session->recv_channel_.close();

    mux::test::run_awaitable_void(ctx, session->proxy_read_loop());
    EXPECT_FALSE(session->terminated());
}

TEST(TproxyUdpSessionTest, DirectReadLoopDropsPacketWhenSenderMissing)
{
    reset_socket_wrappers();
    set_recvmsg_mode_sticky(wrapped_recvmsg_mode::kSyntheticValidSticky);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12349);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 37, cfg, client_ep);
    ASSERT_TRUE(session->start());

    boost::asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::milliseconds(50));
    timer.async_wait(
        [session](const boost::system::error_code& wait_ec)
        {
            (void)wait_ec;
            session->stop();
        });

    ctx.run();
    EXPECT_TRUE(session->terminated());
    reset_socket_wrappers();
}

TEST(TproxyUdpSessionTest, IdleTimeoutZeroNeverExpires)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.timeout.idle = 1;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 2, cfg, client_ep);

    EXPECT_FALSE(session->is_idle(now_ms(), 0));
}

TEST(TproxyUdpSessionTest, InternalGuardBranches)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config const cfg;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12346);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 3, cfg, client_ep);

    boost::asio::ip::udp::endpoint src_ep;
    std::size_t payload_offset = 0;
    EXPECT_FALSE(session->decode_proxy_packet({0x00, 0x01}, src_ep, payload_offset));

    socks_udp_header fragmented_h;
    fragmented_h.frag = 0x01;
    fragmented_h.addr = "127.0.0.1";
    fragmented_h.port = 5353;
    auto fragmented_pkt = socks_codec::encode_udp_header(fragmented_h);
    fragmented_pkt.push_back(0x24);
    EXPECT_FALSE(session->decode_proxy_packet(fragmented_pkt, src_ep, payload_offset));

    socks_udp_header h;
    h.addr = "not-an-ip";
    h.port = 5353;
    auto pkt = socks_codec::encode_udp_header(h);
    pkt.push_back(0x42);
    EXPECT_FALSE(session->decode_proxy_packet(pkt, src_ep, payload_offset));

    socks_udp_header port_zero;
    port_zero.addr = "127.0.0.1";
    port_zero.port = 0;
    auto port_zero_pkt = socks_codec::encode_udp_header(port_zero);
    port_zero_pkt.push_back(0x43);
    EXPECT_FALSE(session->decode_proxy_packet(port_zero_pkt, src_ep, payload_offset));

    socks_udp_header unspecified_source;
    unspecified_source.addr = "0.0.0.0";
    unspecified_source.port = 5353;
    auto unspecified_source_pkt = socks_codec::encode_udp_header(unspecified_source);
    unspecified_source_pkt.push_back(0x44);
    EXPECT_FALSE(session->decode_proxy_packet(unspecified_source_pkt, src_ep, payload_offset));

    session->maybe_start_proxy_reader(false);

    bool should_start_reader = false;
    session->stream_ = std::make_shared<mux::mux_stream>(1, 1, "trace", std::shared_ptr<mux::mux_connection>{}, ctx);
    EXPECT_FALSE(session->install_proxy_stream(nullptr, nullptr, should_start_reader));
}

TEST(TproxyUdpSessionTest, StartHandlesAlreadyOpenedSocket)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12401);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 5, cfg, client_ep);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v6(), ec);
    ASSERT_FALSE(ec);

    EXPECT_TRUE(session->start());
    EXPECT_TRUE(session->direct_socket_.is_open());
    EXPECT_FALSE(session->direct_socket_use_v6_);
    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, StartCoversV6OnlyAndMarkFailure)
{
    auto run_once = [](const mux::config& cfg) -> bool
    {
        boost::asio::io_context ctx;
        auto router = std::make_shared<direct_router>();
        const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12402);
        auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 6, cfg, client_ep);
        const bool started = session->start();
        session->stop();
        ctx.poll();
        return started;
    };

    reset_socket_wrappers();
#ifdef IPV6_V6ONLY
    mux::config v6_cfg;
    v6_cfg.tproxy.mark = 0;
    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    EXPECT_TRUE(run_once(v6_cfg));
#endif

    reset_socket_wrappers();
    mux::config mark_cfg;
    mark_cfg.tproxy.mark = 123;
#ifdef SO_MARK
    fail_setsockopt_once(SOL_SOCKET, SO_MARK, EPERM);
#endif
    EXPECT_TRUE(run_once(mark_cfg));
    reset_socket_wrappers();
}

TEST(TproxyUdpSessionTest, StartKeepsIpv6ModeWhenDualStackUnavailableForIpv6Client)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("::1"), 12402);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 6, cfg, client_ep);

    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    EXPECT_TRUE(session->start());
    EXPECT_TRUE(session->direct_socket_.is_open());
    EXPECT_TRUE(session->direct_socket_use_v6_);
    EXPECT_FALSE(session->direct_socket_dual_stack_);

    session->stop();
    ctx.poll();
    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyUdpSessionTest, StartPrefersIpv4SocketForIpv4ClientWhenDualStackUnavailable)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12411);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 9, cfg, client_ep);

    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    EXPECT_TRUE(session->start());
    EXPECT_TRUE(session->direct_socket_.is_open());
    EXPECT_FALSE(session->direct_socket_use_v6_);

    boost::system::error_code ec;
    const auto local_ep = session->direct_socket_.local_endpoint(ec);
    ASSERT_FALSE(ec);
    EXPECT_TRUE(local_ep.address().is_v4());

    session->stop();
    ctx.poll();
    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyUdpSessionTest, SendDirectIPv6AndCloseResetBranches)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12403);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 7, cfg, client_ep);
    session->start();

    bool done = false;
    const std::array<std::uint8_t, 2> payload = {0x41, 0x42};
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("::1"), 5353);
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            co_await session->send_direct(dst_ep, payload.data(), payload.size());
            done = true;
            co_return;
        },
        boost::asio::detached);
    for (int i = 0; i < 50 && !done; ++i)
    {
        ctx.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_TRUE(done);
    ctx.restart();

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 100);
    auto stream = std::make_shared<mux::mux_stream>(9, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->on_close();
    ctx.poll();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    auto reset_session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 8, cfg, client_ep);
    reset_session->stream_ = stream;
    reset_session->tunnel_ = tunnel;
    reset_session->on_reset();
    ctx.poll();
    EXPECT_EQ(reset_session->stream_, nullptr);
    EXPECT_TRUE(reset_session->tunnel_.expired());

    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, SendDirectSwitchesToIpv4WhenSocketIsIpv6Only)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("::1"), 12412);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 12, cfg, client_ep);

    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    ASSERT_TRUE(session->start());
    ASSERT_TRUE(session->direct_socket_use_v6_);
    ASSERT_FALSE(session->direct_socket_dual_stack_);

    boost::asio::ip::udp::socket receiver(ctx);
    ASSERT_TRUE(open_ephemeral_udp_socket(receiver));
    receiver.non_blocking(true);
    const auto dst_ep = receiver.local_endpoint();
    const std::array<std::uint8_t, 3> payload = {0x31, 0x32, 0x33};

    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            co_await session->send_direct(dst_ep, payload.data(), payload.size());
            done = true;
            co_return;
        },
        boost::asio::detached);

    for (int i = 0; i < 60 && !done; ++i)
    {
        ctx.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(done);
    EXPECT_FALSE(session->direct_socket_use_v6_);

    std::array<std::uint8_t, 16> recv_buf = {0};
    boost::asio::ip::udp::endpoint from_ep;
    boost::system::error_code ec;
    std::size_t n = 0;
    for (int i = 0; i < 60; ++i)
    {
        n = receiver.receive_from(boost::asio::buffer(recv_buf), from_ep, 0, ec);
        if (!ec)
        {
            break;
        }
        if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_FALSE(ec);
    ASSERT_EQ(n, payload.size());
    EXPECT_EQ(recv_buf[0], payload[0]);
    EXPECT_EQ(recv_buf[1], payload[1]);
    EXPECT_EQ(recv_buf[2], payload[2]);

    session->stop();
    ctx.poll();
    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyUdpSessionTest, SendDirectSwitchesToIpv6WhenSocketIsIpv4)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12413);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 13, cfg, client_ep);

    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    ASSERT_TRUE(session->start());
    ASSERT_FALSE(session->direct_socket_use_v6_);
    force_ipv6_socket_compat(false);

    boost::asio::ip::udp::socket receiver(ctx);
    if (!open_ephemeral_udp_socket_v6(receiver))
    {
        session->stop();
        ctx.poll();
        force_ipv6_socket_compat(false);
        reset_socket_wrappers();
        GTEST_SKIP() << "ipv6 udp loopback unavailable";
    }
    receiver.non_blocking(true);
    const auto dst_ep = receiver.local_endpoint();
    const std::array<std::uint8_t, 4> payload = {0x41, 0x42, 0x43, 0x44};

    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            co_await session->send_direct(dst_ep, payload.data(), payload.size());
            done = true;
            co_return;
        },
        boost::asio::detached);

    for (int i = 0; i < 60 && !done; ++i)
    {
        ctx.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(done);
    EXPECT_TRUE(session->direct_socket_use_v6_);

    std::array<std::uint8_t, 16> recv_buf = {0};
    boost::asio::ip::udp::endpoint from_ep;
    boost::system::error_code ec;
    std::size_t n = 0;
    for (int i = 0; i < 60; ++i)
    {
        n = receiver.receive_from(boost::asio::buffer(recv_buf), from_ep, 0, ec);
        if (!ec)
        {
            break;
        }
        if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_FALSE(ec);
    ASSERT_EQ(n, payload.size());
    EXPECT_EQ(recv_buf[0], payload[0]);
    EXPECT_EQ(recv_buf[1], payload[1]);
    EXPECT_EQ(recv_buf[2], payload[2]);
    EXPECT_EQ(recv_buf[3], payload[3]);

    session->stop();
    ctx.poll();
    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyUdpSessionTest, SwitchDirectSocketToIpv4FailureRestoresPreviousIpv6OnlySocket)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("::1"), 12414);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 14, cfg, client_ep);

    fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
    ASSERT_TRUE(session->start());
    ASSERT_TRUE(session->direct_socket_.is_open());
    ASSERT_TRUE(session->direct_socket_use_v6_);
    ASSERT_FALSE(session->direct_socket_dual_stack_);

    force_ipv6_socket_compat(false);

    fail_socket_once(EMFILE);
    EXPECT_FALSE(session->switch_direct_socket_to_v4());
    EXPECT_TRUE(session->direct_socket_.is_open());
    EXPECT_TRUE(session->direct_socket_use_v6_);
    EXPECT_FALSE(session->direct_socket_dual_stack_);

    boost::asio::ip::udp::socket receiver(ctx);
    if (!open_ephemeral_udp_socket_v6(receiver))
    {
        session->stop();
        ctx.poll();
        force_ipv6_socket_compat(false);
        reset_socket_wrappers();
        GTEST_SKIP() << "ipv6 udp loopback unavailable";
    }
    receiver.non_blocking(true);

    const auto dst_ep = receiver.local_endpoint();
    const std::array<std::uint8_t, 3> payload = {0x55, 0x56, 0x57};
    bool done = false;
    boost::asio::co_spawn(
        ctx,
        [&]() -> boost::asio::awaitable<void>
        {
            co_await session->send_direct(dst_ep, payload.data(), payload.size());
            done = true;
            co_return;
        },
        boost::asio::detached);

    for (int i = 0; i < 60 && !done; ++i)
    {
        ctx.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(done);

    std::array<std::uint8_t, 16> recv_buf = {0};
    boost::asio::ip::udp::endpoint from_ep;
    boost::system::error_code ec;
    std::size_t n = 0;
    for (int i = 0; i < 60; ++i)
    {
        n = receiver.receive_from(boost::asio::buffer(recv_buf), from_ep, 0, ec);
        if (!ec)
        {
            break;
        }
        if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_FALSE(ec);
    ASSERT_EQ(n, payload.size());
    EXPECT_EQ(recv_buf[0], payload[0]);
    EXPECT_EQ(recv_buf[1], payload[1]);
    EXPECT_EQ(recv_buf[2], payload[2]);

    session->stop();
    ctx.poll();
    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyUdpSessionTest, StartCoversBindFailureBranch)
{
    reset_socket_wrappers();

    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12404);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 8, cfg, client_ep);

    fail_bind_once(EADDRINUSE);
    EXPECT_TRUE(session->start());
    EXPECT_TRUE(session->direct_socket_.is_open());
    EXPECT_FALSE(session->direct_socket_use_v6_);

    session->stop();
    ctx.poll();
    reset_socket_wrappers();
}

TEST(TproxyUdpSessionTest, OnDataRunsStopWhenIoQueueBlocked)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12420);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 20, cfg, client_ep);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());
    session->recv_channel_.close();

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(ctx,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { ctx.run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        ctx.stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    session->on_data({0x55});
    EXPECT_FALSE(session->direct_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    ctx.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(TproxyUdpSessionTest, OnDataRunsStopWhenIoContextStopped)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12421);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 21, cfg, client_ep);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());
    session->recv_channel_.close();

    ctx.stop();
    session->on_data({0x55});
    EXPECT_FALSE(session->direct_socket_.is_open());
}

TEST(TproxyUdpSessionTest, OnDataRunsStopWhenIoContextNotRunning)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12422);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 22, cfg, client_ep);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());
    session->recv_channel_.close();

    session->on_data({0x55});
    EXPECT_FALSE(session->direct_socket_.is_open());
}

TEST(TproxyUdpSessionTest, StopAndOnCloseCoverPartialStateBranches)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12405);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 9, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 101);
    auto stream = std::make_shared<mux::mux_stream>(13, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    session->tunnel_ = tunnel;
    session->stream_.reset();
    session->stop();
    ctx.run();
    ctx.restart();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    auto close_only_session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 10, cfg, client_ep);
    close_only_session->stream_ = stream;
    close_only_session->tunnel_.reset();
    close_only_session->on_close();
    ctx.run();
    ctx.restart();
    EXPECT_EQ(close_only_session->stream_, nullptr);
    EXPECT_TRUE(close_only_session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, StopAndOnCloseRunInlineWhenIoContextStopped)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12411);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 12, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 105);
    auto stream = std::make_shared<mux::mux_stream>(17, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    session->stream_ = stream;
    session->tunnel_ = tunnel;

    ctx.stop();
    session->stop();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(session->direct_socket_.is_open());

    session->on_close();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(session->direct_socket_.is_open());
}

TEST(TproxyUdpSessionTest, StopAndOnCloseRunWhenIoQueueBlocked)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12416);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 16, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 109);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(21, 109, "trace", mock_conn, ctx);

    EXPECT_CALL(*mock_conn, remove_stream(21)).Times(1);
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).Times(0);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    session->stream_ = stream;
    session->tunnel_ = tunnel;

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(ctx,
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread io_thread([&]() { ctx.run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        ctx.stop();
        if (io_thread.joinable())
        {
            io_thread.join();
        }
        FAIL();
    }

    session->stop();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(session->direct_socket_.is_open());

    session->on_close();
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(session->direct_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    ctx.stop();
    if (io_thread.joinable())
    {
        io_thread.join();
    }
}

TEST(TproxyUdpSessionTest, OnCloseRunsWhenIoContextNotRunning)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12417);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 17, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 110);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(22, 110, "trace", mock_conn, ctx);

    EXPECT_CALL(*mock_conn, remove_stream(22)).Times(1);
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).Times(0);

    boost::system::error_code ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->on_close();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(session->direct_socket_.is_open());
}

TEST(TproxyUdpSessionTest, StopRemovesStreamWhenIoContextNotRunning)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12412);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 13, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 106);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(18, 106, "trace", mock_conn, ctx);

    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(18)).Times(1);

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->stop();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, StopRemovesStreamWhenIoContextNotRunningWithStartedConnection)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12413);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 14, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 107);
    auto conn = tunnel->connection();
    ASSERT_NE(conn, nullptr);

    auto stream = std::make_shared<mux::mux_stream>(19, conn->id(), "trace", conn, ctx);
    ASSERT_TRUE(conn->register_stream(19, stream));
    ASSERT_TRUE(connection_has_stream(conn, 19));

    conn->started_.store(true, std::memory_order_release);
    conn->connection_state_.store(mux::mux_connection_state::kConnected, std::memory_order_release);
    ASSERT_FALSE(ctx.stopped());

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->stop();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
    EXPECT_FALSE(connection_has_stream(conn, 19));
}

TEST(TproxyUdpSessionTest, StopResetsProxyStreamWhenIoContextStopped)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12414);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 15, cfg, client_ep);

    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(20, 108, "trace", mock_conn, ctx);
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).Times(0);

    session->stream_ = stream;
    session->tunnel_.reset();

    ctx.stop();
    session->stop();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());

    ctx.restart();
    const std::array<std::uint8_t, 1> payload = {0x42};
    const auto ec = mux::test::run_awaitable(ctx, stream->async_write_some(payload.data(), payload.size()));
    EXPECT_EQ(ec, boost::asio::error::operation_aborted);
}

TEST(TproxyUdpSessionTest, StopClosesProxyStreamBeforeRemovingStream)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12407);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 10, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 103);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(15, 103, "trace", mock_conn, ctx);

    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, mock_send_async(15, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(15)).Times(1);

    session->stream_ = stream;
    session->tunnel_ = tunnel;
    session->stop();
    ctx.run();
    ctx.restart();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, StopClosesProxyStreamWhenTunnelExpired)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<direct_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12408);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 11, cfg, client_ep);

    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    auto stream = std::make_shared<mux::mux_stream>(16, 104, "trace", mock_conn, ctx);

    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, mock_send_async(16, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(0);

    session->stream_ = stream;
    session->tunnel_.reset();
    session->stop();
    ctx.run();
    ctx.restart();

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, ProxyStreamLifecycleCoversInstallCleanupAndReaderStart)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12406);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 10, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 102);
    auto stream = std::make_shared<mux::mux_stream>(14, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);

    bool should_start_reader = false;
    EXPECT_TRUE(session->install_proxy_stream(tunnel, stream, should_start_reader));
    EXPECT_TRUE(should_start_reader);

    mux::test::run_awaitable_void(ctx, session->cleanup_proxy_stream(tunnel, stream));

    session->stream_.reset();
    session->tunnel_.reset();
    session->proxy_reader_started_ = true;
    auto stream_reinstalled = std::make_shared<mux::mux_stream>(15, tunnel->connection()->id(), "trace", tunnel->connection(), ctx);
    should_start_reader = false;
    EXPECT_TRUE(session->install_proxy_stream(tunnel, stream_reinstalled, should_start_reader));
    EXPECT_FALSE(should_start_reader);

    session->recv_channel_.close();
    session->maybe_start_proxy_reader(true);
    ctx.poll();
    ctx.restart();

    mux::test::run_awaitable_void(ctx, session->cleanup_proxy_stream(tunnel, stream_reinstalled));
}

TEST(TproxyUdpSessionTest, InstallProxyStreamRejectsWhenSessionAlreadyTerminated)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12407);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 11, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 103);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(15, 103, "trace", mock_conn, ctx);

    session->terminated_.store(true, std::memory_order_release);

    bool should_start_reader = false;
    EXPECT_CALL(*mock_conn, register_stream(testing::_, testing::_)).Times(0);
    EXPECT_FALSE(session->install_proxy_stream(tunnel, stream, should_start_reader));
    EXPECT_FALSE(should_start_reader);
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, InstallProxyStreamRejectsWhenTerminatedDuringRegister)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12408);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 12, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 104);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(16, 104, "trace", mock_conn, ctx);

    EXPECT_CALL(*mock_conn, register_stream(16, testing::_))
        .WillOnce(
            [session](const std::uint32_t /*id*/, const std::shared_ptr<mux::mux_stream_interface>& /*stream*/)
            {
                session->terminated_.store(true, std::memory_order_release);
                return true;
            });

    bool should_start_reader = false;
    EXPECT_FALSE(session->install_proxy_stream(tunnel, stream, should_start_reader));
    EXPECT_FALSE(should_start_reader);
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, SendProxyWriteFailureClearsInstalledStream)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12409);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 13, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 105);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(17, 105, "trace", mock_conn, ctx);

    session->stream_ = stream;
    session->tunnel_ = tunnel;

    EXPECT_CALL(*mock_conn, mock_send_async(17, mux::kCmdDat, testing::_)).WillOnce(testing::Return(boost::asio::error::broken_pipe));
    EXPECT_CALL(*mock_conn, mock_send_async(17, mux::kCmdFin, std::vector<std::uint8_t>{})).WillOnce(testing::Return(boost::system::error_code{}));
    EXPECT_CALL(*mock_conn, remove_stream(17)).Times(1);

    const std::array<std::uint8_t, 4> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto target_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
    mux::test::run_awaitable_void(ctx, session->send_proxy(target_ep, payload.data(), payload.size()));

    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, SendProxyDropsMessageSizeWithoutClearingStream)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12410);
    auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 14, cfg, client_ep);

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 106);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    auto stream = std::make_shared<mux::mux_stream>(18, 106, "trace", mock_conn, ctx);

    session->stream_ = stream;
    session->tunnel_ = tunnel;

    EXPECT_CALL(*mock_conn, mock_send_async(18, mux::kCmdDat, testing::_)).WillOnce(testing::Return(boost::asio::error::message_size));
    EXPECT_CALL(*mock_conn, mock_send_async(18, mux::kCmdFin, testing::_)).Times(0);
    EXPECT_CALL(*mock_conn, remove_stream(18)).Times(0);

    std::vector<std::uint8_t> payload(64, 0xab);
    const auto target_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
    mux::test::run_awaitable_void(ctx, session->send_proxy(target_ep, payload.data(), payload.size()));

    EXPECT_EQ(session->stream_, stream);
    EXPECT_EQ(session->tunnel_.lock(), tunnel);
}

TEST(TproxyUdpSessionTest, EnsureProxyStreamReturnsFalseWhenTunnelPoolMissing)
{
    boost::asio::io_context ctx;
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.tproxy.mark = 0;
    auto session = std::make_shared<mux::tproxy_udp_session>(
        ctx, nullptr, router, nullptr, 31, cfg, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12436));

    const auto ensure_ok = mux::test::run_awaitable(ctx, session->ensure_proxy_stream());
    EXPECT_FALSE(ensure_ok);
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, EnsureProxyStreamReturnsFalseOnInvalidAckPayload)
{
    boost::asio::io_context ctx;
    mux::io_context_pool pool(1);
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.timeout.idle = 3;
    cfg.tproxy.mark = 0;

    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    auto session = std::make_shared<mux::tproxy_udp_session>(
        ctx, tunnel_pool, router, nullptr, 32, cfg, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12437));

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 131);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    tunnel_pool->tunnel_pool_.resize(1);
    tunnel_pool->tunnel_pool_[0] = tunnel;

    std::shared_ptr<mux::mux_stream> handshake_stream;
    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(131));
    ON_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillByDefault(
            [&handshake_stream](const std::uint32_t /*id*/, const std::shared_ptr<mux::mux_stream_interface>& stream)
            {
                if (const auto mux_stream = std::dynamic_pointer_cast<mux::mux_stream>(stream))
                {
                    handshake_stream = mux_stream;
                }
                return true;
            });
    ON_CALL(*mock_conn, remove_stream(testing::_)).WillByDefault([](const std::uint32_t /*id*/) {});
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);

    bool ensure_ok = true;
    boost::asio::co_spawn(
        ctx, [session, &ensure_ok]() -> boost::asio::awaitable<void> { ensure_ok = co_await session->ensure_proxy_stream(); }, boost::asio::detached);

    for (int i = 0; i < 200 && handshake_stream == nullptr; ++i)
    {
        ctx.poll_one();
    }
    ASSERT_NE(handshake_stream, nullptr);

    handshake_stream->on_data(std::vector<std::uint8_t>{0x01, 0x00});
    ctx.run();

    EXPECT_FALSE(ensure_ok);
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, EnsureProxyStreamReturnsFalseOnAckTimeoutUsesConnectTimeout)
{
    boost::asio::io_context ctx;
    mux::io_context_pool pool(1);
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.timeout.read = 8;
    cfg.timeout.connect = 1;
    cfg.timeout.idle = 3;
    cfg.tproxy.mark = 0;

    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    auto session = std::make_shared<mux::tproxy_udp_session>(
        ctx, tunnel_pool, router, nullptr, 33, cfg, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12438));

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 132);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    tunnel_pool->tunnel_pool_.resize(1);
    tunnel_pool->tunnel_pool_[0] = tunnel;

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(132));
    ON_CALL(*mock_conn, register_stream(testing::_, testing::_)).WillByDefault(testing::Return(true));
    ON_CALL(*mock_conn, remove_stream(testing::_)).WillByDefault([](const std::uint32_t /*id*/) {});
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_)).WillByDefault(testing::Return(boost::system::error_code{}));

    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdSyn, testing::_)).Times(1);
    EXPECT_CALL(*mock_conn, mock_send_async(testing::_, mux::kCmdFin, std::vector<std::uint8_t>{})).Times(0);
    EXPECT_CALL(*mock_conn, remove_stream(testing::_)).Times(1);

    bool ensure_ok = true;
    const auto start = std::chrono::steady_clock::now();
    boost::asio::co_spawn(
        ctx, [session, &ensure_ok]() -> boost::asio::awaitable<void> { ensure_ok = co_await session->ensure_proxy_stream(); }, boost::asio::detached);
    ctx.run();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    EXPECT_FALSE(ensure_ok);
    EXPECT_GE(elapsed.count(), 900);
    EXPECT_LT(elapsed.count(), 4000);
    EXPECT_EQ(session->stream_, nullptr);
    EXPECT_TRUE(session->tunnel_.expired());
}

TEST(TproxyUdpSessionTest, EnsureProxyStreamSucceedsWhenConcurrentInstallAlreadyCompleted)
{
    boost::asio::io_context ctx;
    mux::io_context_pool pool(1);
    auto router = std::make_shared<proxy_router>();
    mux::config cfg;
    cfg.reality.public_key = std::string(64, 'a');
    cfg.timeout.idle = 3;
    cfg.tproxy.mark = 0;

    auto tunnel_pool = std::make_shared<mux::client_tunnel_pool>(pool, cfg, 0);
    auto session = std::make_shared<mux::tproxy_udp_session>(
        ctx, tunnel_pool, router, nullptr, 30, cfg, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12435));

    auto tunnel = std::make_shared<mux::mux_tunnel_impl<boost::asio::ip::tcp::socket>>(
        boost::asio::ip::tcp::socket(ctx), ctx, mux::reality_engine{{}, {}, {}, {}, EVP_aes_128_gcm()}, true, 130);
    auto mock_conn = std::make_shared<mux::mock_mux_connection>(ctx);
    tunnel->connection_ = mock_conn;
    tunnel_pool->tunnel_pool_.resize(1);
    tunnel_pool->tunnel_pool_[0] = tunnel;

    std::shared_ptr<mux::mux_stream> handshake_stream;
    std::atomic<bool> syn_sent{false};

    ON_CALL(*mock_conn, id()).WillByDefault(testing::Return(130));
    ON_CALL(*mock_conn, register_stream(testing::_, testing::_))
        .WillByDefault(
            [&handshake_stream](const std::uint32_t /*id*/, const std::shared_ptr<mux::mux_stream_interface>& stream)
            {
                if (const auto mux_stream = std::dynamic_pointer_cast<mux::mux_stream>(stream))
                {
                    handshake_stream = mux_stream;
                }
                return true;
            });
    ON_CALL(*mock_conn, remove_stream(testing::_)).WillByDefault([](const std::uint32_t /*id*/) {});
    ON_CALL(*mock_conn, mock_send_async(testing::_, testing::_, testing::_))
        .WillByDefault(
            [&syn_sent](const std::uint32_t /*id*/, const std::uint8_t cmd, const std::vector<std::uint8_t>& /*payload*/)
            {
                if (cmd == mux::kCmdSyn)
                {
                    syn_sent.store(true, std::memory_order_release);
                }
                return boost::system::error_code{};
            });

    bool ensure_ok = false;
    boost::asio::co_spawn(
        ctx, [session, &ensure_ok]() -> boost::asio::awaitable<void> { ensure_ok = co_await session->ensure_proxy_stream(); }, boost::asio::detached);

    for (int i = 0; i < 200 && !syn_sent.load(std::memory_order_acquire); ++i)
    {
        ctx.poll_one();
    }
    ASSERT_TRUE(syn_sent.load(std::memory_order_acquire));
    ASSERT_NE(handshake_stream, nullptr);

    auto preinstalled_stream = std::make_shared<mux::mux_stream>(999, 130, "existing", mock_conn, ctx);
    session->stream_ = preinstalled_stream;
    session->tunnel_ = tunnel;

    mux::ack_payload const ack{.socks_rep = socks::kRepSuccess, .bnd_addr = "0.0.0.0", .bnd_port = 0};
    std::vector<std::uint8_t> ack_data;
    (void)mux::mux_codec::encode_ack(ack, ack_data);
    handshake_stream->on_data(std::move(ack_data));

    ctx.run();

    EXPECT_TRUE(ensure_ok);
    EXPECT_EQ(session->stream_, preinstalled_stream);
}

TEST(TproxyClientTest, DisabledStartSetsStopFlag)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = false;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, StartWithNullTunnelPoolStopsEarly)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->tunnel_pool_ = nullptr;

    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, StartWithNullRouterStopsEarly)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = nullptr;

    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, StartWhileRunningIsIgnored)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    client->started_.store(true, std::memory_order_release);
    client->stop_.store(false, std::memory_order_release);
    client->start();

    EXPECT_TRUE(client->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, RunningRequiresStartedFlag)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    EXPECT_FALSE(client->running());

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    EXPECT_FALSE(client->running());

    client->started_.store(true, std::memory_order_release);
    client->stop_.store(false, std::memory_order_release);
    EXPECT_TRUE(client->running());

    client->stop_.store(true, std::memory_order_release);
    EXPECT_FALSE(client->running());

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->tcp_acceptor_.close(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.close(ec);
    pool.stop();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpDispatchQueueIsBounded)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    constexpr std::size_t k_max_probe = 10000;
    std::size_t accepted = 0;
    for (; accepted < k_max_probe; ++accepted)
    {
        mux::tproxy_udp_dispatch_item packet;
        packet.src_ep =
            boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), static_cast<std::uint16_t>(10000 + (accepted % 2000)));
        packet.dst_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
        packet.payload.assign(8, 0x7f);
        if (!client->udp_dispatch_channel_->try_send(boost::system::error_code{}, std::move(packet)))
        {
            break;
        }
    }

    EXPECT_LT(accepted, k_max_probe);
    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchQueueFullDropsAreCountedUnderSustainedPressure)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    for (;;)
    {
        mux::tproxy_udp_dispatch_item packet;
        packet.src_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 11001);
        packet.dst_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
        packet.payload.assign(8, 0x7f);
        if (!client->udp_dispatch_channel_->try_send(boost::system::error_code{}, std::move(packet)))
        {
            break;
        }
    }

    const auto before = mux::statistics::instance().tproxy_udp_dispatch_dropped();
    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 11002);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0xde, 0xad, 0xbe, 0xef};
    constexpr std::size_t k_drop_attempts = 512;

    std::size_t dropped = 0;
    for (std::size_t i = 0; i < k_drop_attempts; ++i)
    {
        if (!mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, payload.size()))
        {
            ++dropped;
        }
    }

    ASSERT_EQ(dropped, k_drop_attempts);
    const auto after = mux::statistics::instance().tproxy_udp_dispatch_dropped();
    EXPECT_EQ(after - before, k_drop_attempts);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchEnqueueAndDropMetricsAreSeparated)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    auto& stats = mux::statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 11901);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04};

    ASSERT_TRUE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, payload.size()));

    for (;;)
    {
        mux::tproxy_udp_dispatch_item packet;
        packet.src_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 11902);
        packet.dst_ep = dst_ep;
        packet.payload.assign(8, 0x7f);
        if (!client->udp_dispatch_channel_->try_send(boost::system::error_code{}, std::move(packet)))
        {
            break;
        }
    }

    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, payload.size()));

    const auto enqueued_after = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_after = stats.tproxy_udp_dispatch_dropped();
    EXPECT_EQ(enqueued_after - enqueued_before, 1U);
    EXPECT_EQ(dropped_after - dropped_before, 1U);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchRejectsOversizedPayloadLength)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    auto& stats = mux::statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 11911);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33, 0x44};

    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, payload.size() + 1));

    const auto enqueued_after = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_after = stats.tproxy_udp_dispatch_dropped();
    EXPECT_EQ(enqueued_after - enqueued_before, 0U);
    EXPECT_EQ(dropped_after - dropped_before, 1U);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchRejectsEmptyPayloadLength)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    auto& stats = mux::statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 11916);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33, 0x44};

    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, 0));

    const auto enqueued_after = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_after = stats.tproxy_udp_dispatch_dropped();
    EXPECT_EQ(enqueued_after - enqueued_before, 0U);
    EXPECT_EQ(dropped_after - dropped_before, 1U);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchRejectsInvalidEndpoints)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    auto& stats = mux::statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();

    const std::vector<std::uint8_t> payload = {0x11, 0x22, 0x33, 0x44};
    const boost::asio::ip::udp::endpoint valid_src(boost::asio::ip::make_address("127.0.0.1"), 11921);
    const boost::asio::ip::udp::endpoint valid_dst(boost::asio::ip::make_address("1.1.1.1"), 53);
    const boost::asio::ip::udp::endpoint invalid_src_port(boost::asio::ip::make_address("127.0.0.1"), 0);
    const boost::asio::ip::udp::endpoint invalid_dst_port(boost::asio::ip::make_address("1.1.1.1"), 0);
    const boost::asio::ip::udp::endpoint invalid_dst_addr(boost::asio::ip::make_address("0.0.0.0"), 53);

    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, invalid_src_port, valid_dst, payload, payload.size()));
    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, valid_src, invalid_dst_port, payload, payload.size()));
    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, valid_src, invalid_dst_addr, payload, payload.size()));

    const auto enqueued_after = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_after = stats.tproxy_udp_dispatch_dropped();
    EXPECT_EQ(enqueued_after - enqueued_before, 0U);
    EXPECT_EQ(dropped_after - dropped_before, 3U);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpDispatchQueueFullDropLogIsSampled)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_NE(client->udp_dispatch_channel_, nullptr);

    for (;;)
    {
        mux::tproxy_udp_dispatch_item packet;
        packet.src_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12001);
        packet.dst_ep = boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("1.1.1.1"), 53);
        packet.payload.assign(8, 0x7f);
        if (!client->udp_dispatch_channel_->try_send(boost::system::error_code{}, std::move(packet)))
        {
            break;
        }
    }

    auto sink = std::make_shared<drop_log_sink_t>();
    auto logger = std::make_shared<spdlog::logger>("tproxy-drop-sampled", sink);
    logger->set_level(spdlog::level::warn);
    scoped_default_logger_override const logger_guard(logger);

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 12002);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("1.1.1.1"), 53);
    const std::vector<std::uint8_t> payload = {0xca, 0xfe, 0xba, 0xbe};
    constexpr std::size_t k_drop_attempts = 1024;

    std::size_t dropped = 0;
    for (std::size_t i = 0; i < k_drop_attempts; ++i)
    {
        if (!mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, payload, payload.size()))
        {
            ++dropped;
        }
    }

    ASSERT_EQ(dropped, k_drop_attempts);
    const auto warn_logs = sink->drop_warn_count();
    EXPECT_GT(warn_logs, 0U);
    EXPECT_LT(warn_logs, k_drop_attempts / 8);

    client->udp_dispatch_channel_->close();
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, UdpLoopQueueBackpressureIncrementsDropMetric)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    boost::asio::io_context port_ioc;
    boost::asio::ip::udp::socket port_probe(port_ioc);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto udp_port = port_probe.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(udp_port, 0);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.close(ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = udp_port;
    cfg.tproxy.udp_port = udp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // Prevent dispatch workers from draining queue so udp_loop backpressure is deterministic.
    client->udp_dispatch_started_.store(true, std::memory_order_release);
    set_recvmsg_mode_sticky(wrapped_recvmsg_mode::kSyntheticValidSticky);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });

    boost::asio::io_context sender_ioc;
    boost::asio::ip::udp::socket sender(sender_ioc);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    EXPECT_FALSE(ec);
    const boost::asio::ip::udp::endpoint target(boost::asio::ip::make_address("127.0.0.1"), udp_port);
    const std::array<std::uint8_t, 1> payload = {0x01};

    auto& stats = mux::statistics::instance();
    const auto before = stats.tproxy_udp_dispatch_dropped();
    bool metric_grew = false;
    for (int i = 0; i < 200; ++i)
    {
        (void)sender.send_to(boost::asio::buffer(payload), target, 0, ec);
        if (ec)
        {
            ec.clear();
        }
        const auto after = stats.tproxy_udp_dispatch_dropped();
        if (after > before)
        {
            metric_grew = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(metric_grew);

    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopBackpressureMetricsVisibleViaMonitorEndpoint)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    boost::asio::io_context port_ioc;
    boost::asio::ip::udp::socket port_probe(port_ioc);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto udp_port = port_probe.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(udp_port, 0);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)port_probe.close(ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = udp_port;
    cfg.tproxy.udp_port = udp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // Keep dispatch queue undrained so udp_loop can deterministically hit both enqueue and drop paths.
    client->udp_dispatch_started_.store(true, std::memory_order_release);
    set_recvmsg_mode_sticky(wrapped_recvmsg_mode::kSyntheticValidSticky);

    boost::asio::io_context monitor_ioc;
    std::shared_ptr<mux::monitor_server> monitor;
    for (int attempt = 0; attempt < 8; ++attempt)
    {
        monitor = std::make_shared<mux::monitor_server>(monitor_ioc, 0);
        if (monitor != nullptr && monitor->acceptor_.is_open())
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    ASSERT_NE(monitor, nullptr);
    ASSERT_TRUE(monitor->acceptor_.is_open());
    monitor->start();
    const auto monitor_port = monitor->acceptor_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(monitor_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread pool_runner([&pool]() { pool.run(); });
    std::thread monitor_runner([&monitor_ioc]() { monitor_ioc.run(); });

    boost::asio::io_context sender_ioc;
    boost::asio::ip::udp::socket sender(sender_ioc);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    EXPECT_FALSE(ec);
    const boost::asio::ip::udp::endpoint target(boost::asio::ip::make_address("127.0.0.1"), udp_port);
    const std::array<std::uint8_t, 1> payload = {0x01};

    auto& stats = mux::statistics::instance();
    const auto enqueued_before = stats.tproxy_udp_dispatch_enqueued();
    const auto dropped_before = stats.tproxy_udp_dispatch_dropped();

    bool observed_enqueued = false;
    bool observed_dropped = false;
    for (int i = 0; i < 300; ++i)
    {
        (void)sender.send_to(boost::asio::buffer(payload), target, 0, ec);
        if (ec)
        {
            ec.clear();
        }
        observed_enqueued = stats.tproxy_udp_dispatch_enqueued() > enqueued_before;
        observed_dropped = stats.tproxy_udp_dispatch_dropped() > dropped_before;
        if (observed_enqueued && observed_dropped)
        {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    set_recvmsg_mode_sticky(wrapped_recvmsg_mode::kReal);
    const auto response = request_monitor_response_with_retry(monitor_port,
                                                              "GET /metrics HTTP/1.1\r\n"
                                                              "Host: 127.0.0.1\r\n"
                                                              "Connection: close\r\n"
                                                              "\r\n");
    const auto enqueued_metric = parse_metric_counter(response, "socks_tproxy_udp_dispatch_enqueued_total");
    const auto dropped_metric = parse_metric_counter(response, "socks_tproxy_udp_dispatch_dropped_total");

    bool metrics_valid = enqueued_metric.has_value() && dropped_metric.has_value();
    std::uint64_t delta_enqueued = 0;
    std::uint64_t delta_dropped = 0;
    if (metrics_valid)
    {
        if (*enqueued_metric < enqueued_before || *dropped_metric < dropped_before)
        {
            metrics_valid = false;
        }
        else
        {
            delta_enqueued = *enqueued_metric - enqueued_before;
            delta_dropped = *dropped_metric - dropped_before;
        }
    }

    client->stop();
    pool.stop();
    if (pool_runner.joinable())
    {
        pool_runner.join();
    }

    monitor->stop();
    monitor_ioc.stop();
    if (monitor_runner.joinable())
    {
        monitor_runner.join();
    }

    EXPECT_TRUE(observed_enqueued);
    EXPECT_TRUE(observed_dropped);
    EXPECT_TRUE(metrics_valid);
    EXPECT_GT(delta_enqueued, 0U);
    EXPECT_GT(delta_dropped, 0U);
    const auto total = delta_enqueued + delta_dropped;
    EXPECT_GT(total, 0U);
    if (total > 0U)
    {
        const double drop_ratio = static_cast<double>(delta_dropped) / static_cast<double>(total);
        EXPECT_GT(drop_ratio, 0.0);
        EXPECT_LT(drop_ratio, 1.0);
    }

    reset_socket_wrappers();
}

TEST(TproxyClientTest, InvalidRealityAuthConfigStopsEarly)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
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
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.tcp_port = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_EQ(client->endpoint_key(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 5353)), "127.0.0.1:5353");
    client->stop();
}

TEST(TproxyClientTest, TcpPortZeroStopsAfterPassingAuthAndRouterChecks)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = 0;
    cfg.tproxy.udp_port = 0;
    cfg.reality.public_key = std::string(64, 'a');

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<always_load_router>();
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));
    client->stop();
    pool.stop();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpPortFallsBackToTcpPortWhenConfiguredZero)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = 0;

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_EQ(client->udp_port(), cfg.tproxy.tcp_port);
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, AcceptAndUdpLoopReturnOnInvalidListenHost)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "invalid host value";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    pool.stop();
    runner.join();
}

TEST(TproxyClientTest, AcceptLoopSetupFailsWhenPortInUse)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    boost::asio::ip::tcp::acceptor occupied(pool.get_io_context());
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(occupied));
    const auto used_port = occupied.local_endpoint().port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = used_port;
    cfg.tproxy.udp_port = static_cast<std::uint16_t>(used_port + 1);
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopHandlesPacketAndCleanupPrunesIdleSessions)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.timeout.idle = 1;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto listen_port = client->udp_socket_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_cleanup_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    sender.send_to(boost::asio::buffer(payload), boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), listen_port), 0, ec);
    ASSERT_FALSE(ec);

    const boost::asio::ip::udp::endpoint session_src(boost::asio::ip::make_address("127.0.0.1"), 19001);
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
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = tcp_port;
    cfg.reality.public_key = std::string(64, 'a');

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
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
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

TEST(TproxyClientTest, RouterLoadFailureBranchHitAfterValidAuth)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;
    cfg.reality.public_key = std::string(64, 'a');

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<failing_load_router>();
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));
    client->stop();
    pool.stop();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpSetupFailureAfterTcpSetupStopsClient)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    ASSERT_NE(tcp_port, 0);
    const auto udp_port = pick_free_udp_port();
    ASSERT_NE(udp_port, 0);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    cfg.reality.public_key = std::string(64, 'a');

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<always_load_router>();

#ifdef IP_RECVORIGDSTADDR
    fail_setsockopt_once(SOL_IP, IP_RECVORIGDSTADDR, EPERM);
#else
    GTEST_SKIP() << "IP_RECVORIGDSTADDR not available";
#endif

    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->tcp_acceptor_.is_open());
    EXPECT_FALSE(client->udp_socket_.is_open());
    client->stop();
    pool.stop();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopExtractsAndStopsUdpSessions)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = cfg.tproxy.tcp_port;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 19001);
    auto live_session =
        std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), client->tunnel_pool_, client->router_, client->sender_, 42, cfg, client_ep);

    emplace_udp_session(pool.get_io_context(), client, "null-entry", nullptr);
    emplace_udp_session(pool.get_io_context(), client, "live-entry", live_session);

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

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    ASSERT_TRUE(open_ephemeral_tcp_acceptor(client->tcp_acceptor_));
    const auto listen_port = client->tcp_acceptor_.local_endpoint().port();
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });

    client->stop_.store(true, std::memory_order_release);

    boost::asio::io_context dial_ctx;
    boost::asio::ip::tcp::socket dial_socket(dial_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dial_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), listen_port), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dial_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dial_socket.close(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopSkipsSetupWhenStopAlreadySet)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->stop_.store(true, std::memory_order_release);

    std::atomic<bool> finished{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client, &finished]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            finished.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !finished.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(finished.load(std::memory_order_acquire));

    pool.stop();
    runner.join();
    EXPECT_FALSE(client->tcp_acceptor_.is_open());

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopReturnsWhenTunnelPoolMissing)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->tunnel_pool_ = nullptr;
    client->stop_.store(false, std::memory_order_release);
    client->started_.store(true, std::memory_order_release);

    std::atomic<bool> finished{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client, &finished]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            finished.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !finished.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(finished.load(std::memory_order_acquire));
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));

    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
}

TEST(TproxyClientTest, UdpLoopBreaksWhenReadableAndStopFlagAlreadySet)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto listen_port = client->udp_socket_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    client->stop_.store(true, std::memory_order_release);

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    const std::array<std::uint8_t, 1> payload = {0x7f};
    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), listen_port), 0, ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopSkipsSetupWhenStopAlreadySet)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->stop_.store(true, std::memory_order_release);

    std::atomic<bool> finished{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client, &finished]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            finished.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !finished.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(finished.load(std::memory_order_acquire));

    pool.stop();
    runner.join();
    EXPECT_FALSE(client->udp_socket_.is_open());

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopRetriesWhenSocketClosedUnexpectedly)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::post(pool.get_io_context(),
                      [client]()
                      {
                          boost::system::error_code close_ec;
                          // NOLINTNEXTLINE(bugprone-unused-return-value)
                          (void)client->udp_socket_.close(close_ec);
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
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

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

TEST(TproxyClientTest, SetupFailureClosesAcceptTcpLoopAcceptor)
{
    reset_socket_wrappers();

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    fail_setsockopt_once(SOL_SOCKET, SO_REUSEADDR, EPERM);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    EXPECT_FALSE(tcp_acceptor_is_open(pool.get_io_context(), client));

    client->stop();
    pool.stop();
    runner.join();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, SetupFailureClosesUdpLoopSocket)
{
    reset_socket_wrappers();

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    fail_bind_once(EADDRINUSE);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    EXPECT_FALSE(udp_socket_is_open(pool.get_io_context(), client));

    client->stop();
    pool.stop();
    runner.join();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, SocketOpenFailureCoversSetupBranches)
{
    auto run_accept_loop_once = [](const mux::config& cfg)
    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

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

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto listen_port = client->udp_socket_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    const boost::asio::ip::udp::endpoint dst(boost::asio::ip::make_address("127.0.0.1"), listen_port);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);

    for (int i = 0; i < 50 && udp_session_count(pool.get_io_context(), client) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopReplacesStoppedSessionForSameSource)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto listen_port = client->udp_socket_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    const boost::asio::ip::udp::endpoint dst(boost::asio::ip::make_address("127.0.0.1"), listen_port);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);

    for (int i = 0; i < 50 && udp_session_count(pool.get_io_context(), client) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    auto snapshot_before = snapshot_udp_sessions(client);
    ASSERT_EQ(snapshot_before->size(), 1U);
    const auto session_it = snapshot_before->begin();
    const auto source_key = session_it->first;
    auto old_session = session_it->second;
    ASSERT_NE(old_session, nullptr);

    old_session->stop();
    for (int i = 0; i < 50 && !old_session->terminated(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(old_session->terminated());

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);

    bool replaced = false;
    for (int i = 0; i < 50; ++i)
    {
        const auto snapshot_after = snapshot_udp_sessions(client);
        const auto it = snapshot_after->find(source_key);
        if (it != snapshot_after->end() && it->second != nullptr && it->second != old_session)
        {
            replaced = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_TRUE(replaced);

    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopSessionStartFailureDoesNotCacheBrokenSession)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);
    const auto listen_port = client->udp_socket_.local_endpoint(ec).port();
    ASSERT_FALSE(ec);
    ASSERT_NE(listen_port, 0);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 4> payload = {0x01, 0x02, 0x03, 0x04};
    const boost::asio::ip::udp::endpoint dst(boost::asio::ip::make_address("127.0.0.1"), listen_port);

    fail_socket_once();
    fail_bind_once(EADDRINUSE);
    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    EXPECT_EQ(udp_session_count(pool.get_io_context(), client), 0U);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kSyntheticValid);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    for (int i = 0; i < 50 && udp_session_count(pool.get_io_context(), client) == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
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

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    auto& stats = mux::statistics::instance();
    const auto origdst_truncated_before = stats.tproxy_udp_origdst_truncated();
    const auto payload_truncated_before = stats.tproxy_udp_payload_truncated();

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !udp_socket_is_open(pool.get_io_context(), client); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(udp_socket_is_open(pool.get_io_context(), client));

    boost::asio::io_context sender_ctx;
    boost::asio::ip::udp::socket sender(sender_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)sender.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);

    const std::array<std::uint8_t, 3> payload = {0x01, 0x02, 0x03};
    const boost::asio::ip::udp::endpoint dst(boost::asio::ip::make_address("127.0.0.1"), cfg.tproxy.udp_port);

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kEagain);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kMissingOrigdst);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kOrigdstTruncated);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kPayloadTruncated);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    set_recvmsg_mode_once(wrapped_recvmsg_mode::kError);
    sender.send_to(boost::asio::buffer(payload), dst, 0, ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));

    client->stop();
    pool.stop();
    runner.join();

    EXPECT_GE(stats.tproxy_udp_origdst_truncated(), origdst_truncated_before + 1);
    EXPECT_GE(stats.tproxy_udp_payload_truncated(), payload_truncated_before + 1);

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopRetriesOnAcceptErrorBranch)
{
    reset_socket_wrappers();

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    ASSERT_TRUE(open_ephemeral_tcp_acceptor(client->tcp_acceptor_));

    fail_next_accept(EIO);
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(1150));
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, AcceptLoopCoversNoDelayAndLocalEndpointFailureBranches)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    ASSERT_TRUE(open_ephemeral_tcp_acceptor(client->tcp_acceptor_));
    const auto listen_port = client->tcp_acceptor_.local_endpoint().port();
    ASSERT_NE(listen_port, 0);

    fail_setsockopt_once(IPPROTO_TCP, TCP_NODELAY, EPERM);
    fail_next_getsockname(EIO);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->accept_tcp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });

    boost::asio::io_context dial_ctx;
    boost::asio::ip::tcp::socket dial_socket(dial_ctx);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dial_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), listen_port), ec);
    ASSERT_FALSE(ec);

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)dial_socket.close(ec);

    client->stop();
    pool.stop();
    runner.join();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpLoopCoversRetryBranchAfterNativeFdInvalidation)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0), ec);
    ASSERT_FALSE(ec);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !client->udp_dispatch_started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(client->udp_dispatch_started_.load(std::memory_order_acquire));

    boost::asio::post(pool.get_io_context(),
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
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        client->stop();
        pool.stop();
        runner.join();
    };

    auto run_udp_loop_once = [](const mux::config& cfg)
    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

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

TEST(TproxyClientTest, SetupCoversV6DualStackSuccessBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "::1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;

    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool tcp_opened = false;
        for (int i = 0; i < 50 && !(tcp_opened = tcp_acceptor_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        EXPECT_TRUE(tcp_opened);

        client->stop();
        pool.stop();
        runner.join();
    }

    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool udp_opened = false;
        for (int i = 0; i < 50 && !(udp_opened = udp_socket_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        EXPECT_TRUE(udp_opened);

        client->stop();
        pool.stop();
        runner.join();
    }

    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
}

TEST(TproxyClientTest, SetupDoesNotRequireDualStackForSpecificIpv6Host)
{
#ifndef IPV6_V6ONLY
    GTEST_SKIP() << "IPV6_V6ONLY unsupported";
#else
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "::1";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;

    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool tcp_opened = false;
        for (int i = 0; i < 50 && !(tcp_opened = tcp_acceptor_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ASSERT_TRUE(tcp_opened);
        EXPECT_TRUE(g_fail_setsockopt_once.load(std::memory_order_acquire));

        client->stop();
        pool.stop();
        runner.join();
    }

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);
    force_ipv6_socket_compat(true);

    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool udp_opened = false;
        for (int i = 0; i < 50 && !(udp_opened = udp_socket_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ASSERT_TRUE(udp_opened);
        EXPECT_TRUE(g_fail_setsockopt_once.load(std::memory_order_acquire));

        client->stop();
        pool.stop();
        runner.join();
    }

    force_ipv6_socket_compat(false);
    reset_socket_wrappers();
#endif
}

TEST(TproxyClientTest, SetupFallsBackToIpv4WhenUnspecifiedIpv6DualStackUnavailable)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "";
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    cfg.tproxy.mark = 0;

#ifdef IPV6_V6ONLY
    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->accept_tcp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool tcp_opened = false;
        for (int i = 0; i < 50 && !(tcp_opened = tcp_acceptor_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ASSERT_TRUE(tcp_opened);
        EXPECT_TRUE(tcp_acceptor_local_is_v4(pool.get_io_context(), client));

        client->stop();
        pool.stop();
        runner.join();
    }

    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    {
        boost::system::error_code const ec;
        mux::io_context_pool pool(1);
        ASSERT_FALSE(ec);
        auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

        fail_setsockopt_once(SOL_IPV6, IPV6_V6ONLY, EPERM);
        boost::asio::co_spawn(
            pool.get_io_context(),
            [client]() -> boost::asio::awaitable<void>
            {
                co_await client->udp_loop();
                co_return;
            },
            boost::asio::detached);

        std::thread runner([&pool]() { pool.run(); });
        bool udp_opened = false;
        for (int i = 0; i < 50 && !(udp_opened = udp_socket_is_open(pool.get_io_context(), client)); ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        ASSERT_TRUE(udp_opened);
        EXPECT_TRUE(udp_socket_local_is_v4(pool.get_io_context(), client));

        client->stop();
        pool.stop();
        runner.join();
    }
#endif

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopCoversCloseErrorLogBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });
    const bool opened = run_on_io_context(pool.get_io_context(),
                                          [client]()
                                          {
                                              boost::system::error_code open_ec;
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), open_ec);
                                              if (open_ec)
                                              {
                                                  return false;
                                              }
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), open_ec);
                                              return !open_ec;
                                          });
    ASSERT_TRUE(opened);

    fail_next_close(EIO);
    client->stop();
    for (int i = 0; i < 50 && g_fail_close_once.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_FALSE(g_fail_close_once.load(std::memory_order_acquire));
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopIgnoresBadDescriptorCloseBranches)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = pick_free_tcp_port();
    cfg.tproxy.udp_port = pick_free_tcp_port();
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });
    const bool opened = run_on_io_context(pool.get_io_context(),
                                          [client]()
                                          {
                                              boost::system::error_code open_ec;
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), open_ec);
                                              if (open_ec)
                                              {
                                                  return false;
                                              }
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), open_ec);
                                              return !open_ec;
                                          });
    ASSERT_TRUE(opened);

    run_on_io_context(pool.get_io_context(),
                      [client]()
                      {
                          boost::system::error_code close_ec;
                          // NOLINTNEXTLINE(bugprone-unused-return-value)
                          (void)client->tcp_acceptor_.close(close_ec);
                          // NOLINTNEXTLINE(bugprone-unused-return-value)
                          (void)client->udp_socket_.close(close_ec);
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

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    std::thread runner([&pool]() { pool.run(); });

    const bool opened = run_on_io_context(pool.get_io_context(),
                                          [client]()
                                          {
                                              boost::system::error_code open_ec;
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), open_ec);
                                              if (open_ec)
                                              {
                                                  return false;
                                              }
                                              // NOLINTNEXTLINE(bugprone-unused-return-value)
                                              (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), open_ec);
                                              return !open_ec;
                                          });
    ASSERT_TRUE(opened);

    fail_next_close(EBADF);
    client->stop();
    pool.stop();
    runner.join();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopRunsInlineWhenIoContextStopped)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->tcp_acceptor_.is_open());
    ASSERT_TRUE(client->udp_socket_.is_open());

    pool.stop();
    client->stop();
    EXPECT_FALSE(client->tcp_acceptor_.is_open());
    EXPECT_FALSE(client->udp_socket_.is_open());

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopRunsWhenIoContextNotRunning)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->tcp_acceptor_.is_open());
    ASSERT_TRUE(client->udp_socket_.is_open());

    client->stop();
    EXPECT_FALSE(client->tcp_acceptor_.is_open());
    EXPECT_FALSE(client->udp_socket_.is_open());
    pool.stop();

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopRunsWhenIoQueueBlocked)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->tcp_acceptor_.open(boost::asio::ip::tcp::v4(), ec);
    ASSERT_FALSE(ec);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)client->udp_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(client->tcp_acceptor_.is_open());
    ASSERT_TRUE(client->udp_socket_.is_open());

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(pool.get_io_context(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread runner([&pool]() { pool.run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        pool.stop();
        if (runner.joinable())
        {
            runner.join();
        }
        reset_socket_wrappers();
        FAIL();
    }

    client->stop();
    EXPECT_FALSE(client->tcp_acceptor_.is_open());
    EXPECT_FALSE(client->udp_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }

    reset_socket_wrappers();
}

TEST(TproxyClientTest, ConcurrentStartDuringStopKeepsTunnelPoolStateConsistent)
{
    reset_socket_wrappers();
    force_tproxy_setsockopt_success(true);

    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    const auto tcp_port = pick_free_tcp_port();
    ASSERT_NE(tcp_port, 0);
    const auto udp_port = pick_free_udp_port();
    ASSERT_NE(udp_port, 0);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "127.0.0.1";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = tcp_port;
    cfg.tproxy.udp_port = udp_port;
    cfg.reality.public_key = std::string(64, 'a');

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<always_load_router>();
    client->started_.store(true, std::memory_order_release);
    client->stop_.store(false, std::memory_order_release);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(pool.get_io_context(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 100 && !blocker_started.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(blocker_started.load(std::memory_order_acquire));

    std::thread stop_thread([client]() { client->stop(); });
    for (int i = 0; i < 100 && client->started_.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_FALSE(client->started_.load(std::memory_order_acquire));

    client->start();
    if (stop_thread.joinable())
    {
        stop_thread.join();
    }

    auto runtime_ready = [&client]()
    {
        return client->started_.load(std::memory_order_acquire) && !client->stop_.load(std::memory_order_acquire) && client->tcp_acceptor_.is_open() &&
               client->udp_socket_.is_open() && !client->tunnel_pool_->stop_.load(std::memory_order_acquire);
    };

    if (!runtime_ready())
    {
        bool recovered = false;
        for (int attempt = 0; attempt < 8; ++attempt)
        {
            const auto retry_tcp_port = pick_free_tcp_port();
            const auto retry_udp_port = pick_free_udp_port();
            if (retry_tcp_port == 0 || retry_udp_port == 0)
            {
                continue;
            }
            client->tcp_port_ = retry_tcp_port;
            client->udp_port_ = retry_udp_port;
            client->start();
            if (runtime_ready())
            {
                recovered = true;
                break;
            }
        }
        EXPECT_TRUE(recovered);
    }

    EXPECT_TRUE(runtime_ready());

    release_blocker.store(true, std::memory_order_release);
    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }

    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopClosesUdpSessionsWhenIoContextStopped)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    auto router = std::make_shared<direct_router>();
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12431);
    auto session = std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), nullptr, router, nullptr, 31, cfg, client_ep);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    emplace_udp_session(pool.get_io_context(), client, "127.0.0.1:12431", session);
    ASSERT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    pool.stop();
    client->stop();

    EXPECT_TRUE(udp_sessions_empty(client));
    EXPECT_FALSE(session->direct_socket_.is_open());
    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopClosesUdpSessionsWhenIoContextNotRunning)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    auto router = std::make_shared<direct_router>();
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12432);
    auto session = std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), nullptr, router, nullptr, 32, cfg, client_ep);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    emplace_udp_session(pool.get_io_context(), client, "127.0.0.1:12432", session);
    ASSERT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    client->stop();

    EXPECT_TRUE(udp_sessions_empty(client));
    EXPECT_FALSE(session->direct_socket_.is_open());
    pool.stop();
    reset_socket_wrappers();
}

TEST(TproxyClientTest, StopClosesUdpSessionsWhenIoQueueBlocked)
{
    reset_socket_wrappers();

    boost::system::error_code ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    auto router = std::make_shared<direct_router>();
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12433);
    auto session = std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), nullptr, router, nullptr, 33, cfg, client_ep);
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    (void)session->direct_socket_.open(boost::asio::ip::udp::v4(), ec);
    ASSERT_FALSE(ec);
    ASSERT_TRUE(session->direct_socket_.is_open());

    emplace_udp_session(pool.get_io_context(), client, "127.0.0.1:12433", session);
    ASSERT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    std::atomic<bool> blocker_started{false};
    std::atomic<bool> release_blocker{false};
    boost::asio::post(pool.get_io_context(),
                      [&blocker_started, &release_blocker]()
                      {
                          blocker_started.store(true, std::memory_order_release);
                          while (!release_blocker.load(std::memory_order_acquire))
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds(10));
                          }
                      });

    std::thread runner([&pool]() { pool.run(); });
    bool started = false;
    for (int i = 0; i < 100; ++i)
    {
        if (blocker_started.load(std::memory_order_acquire))
        {
            started = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!started)
    {
        release_blocker.store(true, std::memory_order_release);
        pool.stop();
        if (runner.joinable())
        {
            runner.join();
        }
        reset_socket_wrappers();
        FAIL();
    }

    client->stop();
    EXPECT_TRUE(udp_sessions_empty(client));
    EXPECT_FALSE(session->direct_socket_.is_open());

    release_blocker.store(true, std::memory_order_release);
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpDispatchLoopDoesNotCreateSessionAfterStopRequested)
{
    reset_socket_wrappers();

    mux::io_context_pool pool(1);
    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();
    client->udp_dispatch_channel_ = std::make_shared<mux::tproxy_udp_dispatch_channel>(pool.get_io_context(), 8);
    client->stop_.store(false, std::memory_order_release);

    boost::asio::co_spawn(pool.get_io_context(), [client]() { return client->udp_dispatch_loop(); }, boost::asio::detached);
    std::thread runner([&pool]() { pool.run(); });

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 22345);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("8.8.8.8"), 53);
    const std::vector<std::uint8_t> packet = {0x01, 0x02, 0x03, 0x04};

    ASSERT_TRUE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, packet, packet.size()));

    bool created = false;
    for (int i = 0; i < 100; ++i)
    {
        if (!udp_sessions_empty(client))
        {
            created = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(created);

    client->stop_.store(true, std::memory_order_release);

    auto existing = snapshot_udp_sessions(client);
    for (auto& [key, session] : *existing)
    {
        (void)key;
        if (session != nullptr)
        {
            session->stop();
        }
    }
    std::atomic_store_explicit(&client->udp_sessions_, std::make_shared<mux::tproxy_client::udp_session_map_t>(), std::memory_order_release);
    ASSERT_TRUE(udp_sessions_empty(client));

    ASSERT_TRUE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, packet, packet.size()));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(udp_sessions_empty(client));

    if (client->udp_dispatch_channel_ != nullptr)
    {
        client->udp_dispatch_channel_->close();
    }
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpDispatchLoopConcurrentCreateDoesNotDropFirstBurst)
{
    reset_socket_wrappers();

    mux::io_context_pool pool(2);
    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();
    client->udp_dispatch_channel_ = std::make_shared<mux::tproxy_udp_dispatch_channel>(pool.get_io_context(), 16);
    client->stop_.store(false, std::memory_order_release);
    client->started_.store(true, std::memory_order_release);

    boost::asio::co_spawn(pool.get_io_context(), [client]() { return client->udp_dispatch_loop(); }, boost::asio::detached);
    boost::asio::co_spawn(pool.get_io_context(), [client]() { return client->udp_dispatch_loop(); }, boost::asio::detached);

    auto warn_sink = std::make_shared<text_match_log_sink_t>("udp direct send failed");
    auto logger = std::make_shared<spdlog::logger>("tproxy_start_order_logger", warn_sink);
    logger->set_level(spdlog::level::trace);
    scoped_default_logger_override logger_override(logger);

    std::thread runner([&pool]() { pool.run(); });

    fail_socket_once(EPERM);

    g_socket_delay_entered.store(0, std::memory_order_release);
    g_socket_delay_ms.store(120, std::memory_order_release);

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 33445);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("127.0.0.1"), 53535);
    const std::vector<std::uint8_t> packet_one = {0x11, 0x22, 0x33, 0x44};
    const std::vector<std::uint8_t> packet_two = {0x55, 0x66, 0x77, 0x88};

    ASSERT_TRUE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, packet_one, packet_one.size()));

    bool delay_entered = false;
    for (int i = 0; i < 200; ++i)
    {
        if (g_socket_delay_entered.load(std::memory_order_acquire) > 0)
        {
            delay_entered = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    ASSERT_TRUE(delay_entered);

    ASSERT_TRUE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, packet_two, packet_two.size()));
    g_socket_delay_ms.store(0, std::memory_order_release);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(warn_sink->match_count(), 0U);

    client->stop_.store(true, std::memory_order_release);
    if (client->udp_dispatch_channel_ != nullptr)
    {
        client->udp_dispatch_channel_->close();
    }
    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpDispatchLoopRejectsEmptyPayload)
{
    reset_socket_wrappers();

    mux::io_context_pool pool(1);
    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();
    client->udp_dispatch_channel_ = std::make_shared<mux::tproxy_udp_dispatch_channel>(pool.get_io_context(), 8);
    client->stop_.store(false, std::memory_order_release);

    boost::asio::co_spawn(pool.get_io_context(), [client]() { return client->udp_dispatch_loop(); }, boost::asio::detached);
    std::thread runner([&pool]() { pool.run(); });

    const boost::asio::ip::udp::endpoint src_ep(boost::asio::ip::make_address("127.0.0.1"), 22355);
    const boost::asio::ip::udp::endpoint dst_ep(boost::asio::ip::make_address("8.8.8.8"), 53);
    const std::vector<std::uint8_t> packet = {};

    ASSERT_FALSE(mux::tproxy_client::enqueue_udp_packet(*client->udp_dispatch_channel_, src_ep, dst_ep, packet, packet.size()));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(udp_sessions_empty(client));

    if (client->udp_dispatch_channel_ != nullptr)
    {
        client->udp_dispatch_channel_->close();
    }
    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpDispatchLoopStopsWhenDependenciesMissing)
{
    reset_socket_wrappers();

    mux::io_context_pool pool(1);
    mux::config cfg;
    cfg.tproxy.enabled = true;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->router_ = std::make_shared<direct_router>();
    client->udp_dispatch_channel_ = std::make_shared<mux::tproxy_udp_dispatch_channel>(pool.get_io_context(), 8);
    client->tunnel_pool_ = nullptr;
    client->stop_.store(false, std::memory_order_release);
    client->started_.store(true, std::memory_order_release);

    std::atomic<bool> finished{false};
    boost::asio::co_spawn(
        pool.get_io_context(),
        [client, &finished]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_dispatch_loop();
            finished.store(true, std::memory_order_release);
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    for (int i = 0; i < 50 && !finished.load(std::memory_order_acquire); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    EXPECT_TRUE(finished.load(std::memory_order_acquire));
    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_FALSE(client->started_.load(std::memory_order_acquire));

    client->stop();
    pool.stop();
    if (runner.joinable())
    {
        runner.join();
    }
    reset_socket_wrappers();
}

TEST(TproxyClientTest, UdpCleanupLoopCoversNullSessionBranch)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.timeout.idle = 1;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    emplace_udp_session(pool.get_io_context(), client, "null-session", std::shared_ptr<mux::tproxy_udp_session>{});

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_cleanup_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    client->stop_.store(true, std::memory_order_release);
    pool.stop();
    runner.join();
}

TEST(TproxyClientTest, UdpCleanupLoopPrunesTerminatedSessionsWhenIdleDisabled)
{
    boost::system::error_code const ec;
    mux::io_context_pool pool(1);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.timeout.idle = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    auto router = std::make_shared<direct_router>();
    const boost::asio::ip::udp::endpoint client_ep(boost::asio::ip::make_address("127.0.0.1"), 12434);
    auto terminated_session = std::make_shared<mux::tproxy_udp_session>(pool.get_io_context(), nullptr, router, nullptr, 34, cfg, client_ep);
    terminated_session->terminated_.store(true, std::memory_order_release);
    emplace_udp_session(pool.get_io_context(), client, "127.0.0.1:12434", terminated_session);
    ASSERT_EQ(udp_session_count(pool.get_io_context(), client), 1U);

    boost::asio::co_spawn(
        pool.get_io_context(),
        [client]() -> boost::asio::awaitable<void>
        {
            co_await client->udp_cleanup_loop();
            co_return;
        },
        boost::asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(1300));
    EXPECT_TRUE(udp_sessions_empty(client));

    client->stop_.store(true, std::memory_order_release);
    pool.stop();
    runner.join();
}

// readability-static-accessed-through-instance)
