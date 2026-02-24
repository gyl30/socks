#include <array>
#include <mutex>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <charconv>
#include <expected>
#include <sys/uio.h>
#include <sys/socket.h>
#include <system_error>
#include <unordered_map>

#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "net_utils.h"
#include "statistics.h"
#include "context_pool.h"
#include "stop_dispatch.h"
#include "tproxy_client.h"
#include "tproxy_udp_sender.h"
#include "client_tunnel_pool.h"
#include "tproxy_tcp_session.h"
#include "tproxy_udp_session.h"

namespace mux
{

namespace
{

constexpr std::size_t k_udp_dispatch_worker_count = 4;
constexpr std::uint64_t k_udp_dispatch_drop_log_sample = 256;
constexpr std::size_t k_udp_dispatch_src_key_cache_capacity = 256;
constexpr auto k_udp_recv_error_missing_origdst = "missing origdst";
constexpr auto k_udp_recv_error_origdst_truncated = "origdst truncated";
constexpr auto k_udp_recv_error_payload_truncated = "payload truncated";
using udp_session_map_t = tproxy_client::udp_session_map_t;
std::atomic<std::uint64_t> g_udp_dispatch_drop_last_logged_total{0};

void maybe_log_udp_dispatch_drop(const std::uint64_t dropped_total)
{
    if (dropped_total != 1 && (dropped_total % k_udp_dispatch_drop_log_sample) != 0)
    {
        return;
    }

    auto observed = g_udp_dispatch_drop_last_logged_total.load(std::memory_order_acquire);
    while (observed < dropped_total)
    {
        if (g_udp_dispatch_drop_last_logged_total.compare_exchange_weak(
                observed, dropped_total, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            LOG_WARN("tproxy udp dispatch queue full dropping packet dropped_total={}", dropped_total);
            return;
        }
    }
}

void close_acceptor_on_setup_failure(boost::asio::ip::tcp::acceptor& acceptor)
{
    boost::system::error_code close_ec;
    close_ec = acceptor.close(close_ec);
}

void close_udp_socket_on_setup_failure(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code close_ec;
    close_ec = socket.close(close_ec);
}

std::expected<std::pair<std::string, boost::asio::ip::address>, boost::system::error_code> resolve_listen_address(const std::string& configured_host)
{
    std::string listen_host;
    if (configured_host.empty())
    {
        listen_host = "::";
    }
    else
    {
        listen_host = configured_host;
    }
    boost::system::error_code ec;
    auto listen_addr = boost::asio::ip::make_address(listen_host, ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    return std::make_pair(listen_host, listen_addr);
}

std::expected<void, boost::system::error_code> setup_tcp_listener_options(boost::asio::ip::tcp::acceptor& acceptor, const bool is_v6)
{
    boost::system::error_code ec;
    ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    if (is_v6)
    {
        ec = acceptor.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            return std::unexpected(ec);
        }
    }
    if (auto r = net::set_socket_transparent(acceptor.native_handle(), is_v6); !r)
    {
        return std::unexpected(r.error());
    }
    return {};
}

std::expected<void, boost::system::error_code> setup_tcp_listener(boost::asio::ip::tcp::acceptor& acceptor,
                                                                  const boost::asio::ip::address& listen_addr,
                                                                  const std::uint16_t port)
{
    const boost::asio::ip::tcp::endpoint ep{listen_addr, port};
    boost::system::error_code ec;
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    if (const auto res = setup_tcp_listener_options(acceptor, listen_addr.is_v6()); !res)
    {
        close_acceptor_on_setup_failure(acceptor);
        return std::unexpected(res.error());
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        close_acceptor_on_setup_failure(acceptor);
        return std::unexpected(ec);
    }
    ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        close_acceptor_on_setup_failure(acceptor);
        return std::unexpected(ec);
    }
    return {};
}

void set_udp_reuse_option(boost::asio::ip::udp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp reuse addr failed {}", ec.message());
    }
}

std::expected<void, boost::system::error_code> set_udp_dual_stack_if_needed(boost::asio::ip::udp::socket& socket, const bool is_v6)
{
    if (!is_v6)
    {
        return {};
    }
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::v6_only(false), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    return {};
}

std::expected<void, boost::system::error_code> configure_udp_transparent_options(boost::asio::ip::udp::socket& socket, const bool is_v6)
{
    if (auto r = net::set_socket_transparent(socket.native_handle(), is_v6); !r)
    {
        return std::unexpected(r.error());
    }

    if (auto r = net::set_socket_recv_origdst(socket.native_handle(), is_v6); !r)
    {
        return std::unexpected(r.error());
    }
    return {};
}

void maybe_set_udp_mark(boost::asio::ip::udp::socket& socket, const std::uint32_t mark)
{
    if (mark == 0)
    {
        return;
    }
    if (auto r = net::set_socket_mark(socket.native_handle(), mark); !r)
    {
        LOG_WARN("tproxy udp set mark failed code {}", r.error().value());
    }
}

std::expected<void, boost::system::error_code> setup_udp_listener(boost::asio::ip::udp::socket& socket,
                                                                  const boost::asio::ip::address& listen_addr,
                                                                  const std::uint16_t port,
                                                                  const std::uint32_t mark)
{
    const bool is_v6 = listen_addr.is_v6();
    const boost::asio::ip::udp::endpoint ep{listen_addr, port};
    boost::system::error_code ec;
    ec = socket.open(ep.protocol(), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    set_udp_reuse_option(socket);
    if (auto res = set_udp_dual_stack_if_needed(socket, is_v6); !res)
    {
        close_udp_socket_on_setup_failure(socket);
        return std::unexpected(res.error());
    }
    if (auto res = configure_udp_transparent_options(socket, is_v6); !res)
    {
        close_udp_socket_on_setup_failure(socket);
        return std::unexpected(res.error());
    }
    maybe_set_udp_mark(socket, mark);

    ec = socket.bind(ep, ec);
    if (ec)
    {
        close_udp_socket_on_setup_failure(socket);
        return std::unexpected(ec);
    }
    return {};
}

std::string make_endpoint_key(const boost::asio::ip::udp::endpoint& ep)
{
    std::string key = ep.address().to_string();
    char port_buf[6];
    const auto [ptr, ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), ep.port());
    if (ec == std::errc())
    {
        key.reserve(key.size() + 1 + static_cast<std::size_t>(ptr - port_buf));
        key.push_back(':');
        key.append(port_buf, ptr);
        return key;
    }

    key.reserve(key.size() + 8);
    key.push_back(':');
    key.append(std::to_string(ep.port()));
    return key;
}

template <typename ByteContainer>
std::size_t hash_bytes(const ByteContainer& bytes)
{
    std::size_t seed = 1469598103934665603ULL;
    for (const auto b : bytes)
    {
        seed ^= static_cast<std::size_t>(b);
        seed *= 1099511628211ULL;
    }
    return seed;
}

struct udp_endpoint_key
{
    boost::asio::ip::address addr;
    std::uint16_t port = 0;
};

struct endpoint_hash
{
    std::size_t operator()(const udp_endpoint_key& key) const noexcept
    {
        std::size_t seed = 1469598103934665603ULL;
        if (key.addr.is_v4())
        {
            const auto bytes = key.addr.to_v4().to_bytes();
            seed ^= hash_bytes(bytes);
            seed *= 1099511628211ULL;
        }
        else
        {
            const auto bytes = key.addr.to_v6().to_bytes();
            seed ^= hash_bytes(bytes);
            seed *= 1099511628211ULL;
        }
        seed ^= static_cast<std::size_t>(key.port);
        seed *= 1099511628211ULL;
        return seed;
    }
};

struct endpoint_key_equal
{
    bool operator()(const udp_endpoint_key& lhs, const udp_endpoint_key& rhs) const noexcept { return lhs.port == rhs.port && lhs.addr == rhs.addr; }
};

void close_accepted_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code close_ec;
    close_ec = socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
    close_ec = socket.close(close_ec);
}

boost::asio::awaitable<void> wait_retry_delay(boost::asio::io_context& io_context)
{
    boost::asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(1));
    (void)co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
}

[[nodiscard]] bool is_socket_stop_error(const boost::system::error_code& ec)
{
    return ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor || ec == boost::asio::error::not_socket;
}

enum class tcp_accept_status : std::uint8_t
{
    kAccepted,
    kRetry,
    kStop,
};

boost::asio::awaitable<tcp_accept_status> accept_tcp_connection(boost::asio::ip::tcp::acceptor& acceptor,
                                                                boost::asio::ip::tcp::socket& socket,
                                                                boost::asio::io_context& io_context)
{
    const auto [accept_ec] = co_await acceptor.async_accept(socket, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (!accept_ec)
    {
        co_return tcp_accept_status::kAccepted;
    }
    if (is_socket_stop_error(accept_ec))
    {
        co_return tcp_accept_status::kStop;
    }
    LOG_ERROR("tproxy tcp accept failed {}", accept_ec.message());
    co_await wait_retry_delay(io_context);
    co_return tcp_accept_status::kRetry;
}

std::expected<boost::asio::ip::tcp::endpoint, boost::system::error_code> prepare_tcp_destination(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy tcp set no delay failed code {}", ec.value());
    }

    const auto local_ep = socket.local_endpoint(ec);
    if (ec)
    {
        LOG_ERROR("tproxy tcp local endpoint failed {}", ec.message());
        return std::unexpected(ec);
    }

    return boost::asio::ip::tcp::endpoint(net::normalize_address(local_ep.address()), local_ep.port());
}

void start_tcp_session(boost::asio::ip::tcp::socket s,
                       boost::asio::io_context& io_context,
                       const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                       const std::shared_ptr<router>& router,
                       const std::uint32_t sid,
                       const config& cfg,
                       const boost::asio::ip::tcp::endpoint& dst_ep)
{
    auto session = std::make_shared<tproxy_tcp_session>(std::move(s), io_context, tunnel_pool, router, sid, cfg, dst_ep);
    session->start();
}

void log_udp_recv_error(const std::string& error_text)
{
    if (error_text == k_udp_recv_error_missing_origdst)
    {
        LOG_WARN("tproxy udp missing origdst");
        return;
    }
    if (error_text == k_udp_recv_error_origdst_truncated)
    {
        statistics::instance().inc_tproxy_udp_origdst_truncated();
        LOG_WARN("tproxy udp origdst truncated");
        return;
    }
    if (error_text == k_udp_recv_error_payload_truncated)
    {
        statistics::instance().inc_tproxy_udp_payload_truncated();
        LOG_WARN("tproxy udp payload truncated");
        return;
    }
    LOG_ERROR("tproxy udp recvmsg failed {}", error_text);
}

[[nodiscard]] bool is_valid_udp_dispatch_endpoint(const boost::asio::ip::udp::endpoint& endpoint)
{
    return endpoint.port() != 0 && !endpoint.address().is_unspecified();
}

std::shared_ptr<udp_session_map_t> snapshot_udp_sessions(const std::shared_ptr<udp_session_map_t>& sessions)
{
    auto snapshot = std::atomic_load_explicit(&sessions, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<udp_session_map_t>();
}

void erase_udp_session_if_same(std::shared_ptr<udp_session_map_t>& sessions,
                               const std::string& key,
                               const std::shared_ptr<tproxy_udp_session>& expected_session)
{
    for (;;)
    {
        auto current = snapshot_udp_sessions(sessions);
        const auto it = current->find(key);
        if (it == current->end() || it->second != expected_session)
        {
            return;
        }

        auto updated = std::make_shared<udp_session_map_t>(*current);
        updated->erase(key);
        if (std::atomic_compare_exchange_weak_explicit(&sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

bool stop_requested(const std::atomic<bool>& stop_flag) { return stop_flag.load(std::memory_order_acquire); }

std::shared_ptr<tproxy_udp_session> find_live_udp_session(const std::shared_ptr<udp_session_map_t>& sessions, const std::string& key)
{
    const auto it = sessions->find(key);
    if (it == sessions->end() || it->second == nullptr || it->second->terminated())
    {
        return nullptr;
    }
    return it->second;
}

void ensure_prepared_udp_session(std::shared_ptr<tproxy_udp_session>& prepared_session,
                                 boost::asio::io_context& io_context,
                                 const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                 const std::shared_ptr<router>& router,
                                 const std::shared_ptr<tproxy_udp_sender>& sender,
                                 const config& cfg,
                                 const boost::asio::ip::udp::endpoint& src_ep)
{
    if (prepared_session != nullptr)
    {
        return;
    }
    const std::uint32_t sid = tunnel_pool->next_session_id();
    prepared_session = std::make_shared<tproxy_udp_session>(io_context, tunnel_pool, router, sender, sid, cfg, src_ep);
}

bool try_publish_udp_session(std::shared_ptr<udp_session_map_t>& sessions,
                             std::shared_ptr<udp_session_map_t>& current,
                             const std::string& key,
                             const std::shared_ptr<tproxy_udp_session>& prepared_session)
{
    auto updated = std::make_shared<udp_session_map_t>(*current);
    (*updated)[key] = prepared_session;
    return std::atomic_compare_exchange_weak_explicit(&sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire);
}

std::shared_ptr<tproxy_udp_session> start_udp_session_or_rollback(std::shared_ptr<udp_session_map_t>& sessions,
                                                                  const std::string& key,
                                                                  const std::shared_ptr<tproxy_udp_session>& prepared_session,
                                                                  const std::atomic<bool>& stop_flag)
{
    if (stop_requested(stop_flag))
    {
        erase_udp_session_if_same(sessions, key, prepared_session);
        return nullptr;
    }

    if (!prepared_session->start())
    {
        LOG_WARN("tproxy udp session {} start failed", key);
        erase_udp_session_if_same(sessions, key, prepared_session);
        return nullptr;
    }

    if (stop_requested(stop_flag))
    {
        prepared_session->stop();
        erase_udp_session_if_same(sessions, key, prepared_session);
        return nullptr;
    }
    return prepared_session;
}

std::shared_ptr<tproxy_udp_session> get_or_create_udp_session(std::shared_ptr<udp_session_map_t>& sessions,
                                                              const std::string& key,
                                                              const boost::asio::ip::udp::endpoint& src_ep,
                                                              boost::asio::io_context& io_context,
                                                              const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                              const std::shared_ptr<router>& router,
                                                              const std::shared_ptr<tproxy_udp_sender>& sender,
                                                              const config& cfg,
                                                              const std::atomic<bool>& stop_flag)
{
    if (stop_requested(stop_flag))
    {
        return nullptr;
    }

    std::shared_ptr<tproxy_udp_session> prepared_session = nullptr;
    for (;;)
    {
        if (stop_requested(stop_flag))
        {
            return nullptr;
        }

        auto current = snapshot_udp_sessions(sessions);
        if (auto existing = find_live_udp_session(current, key); existing != nullptr)
        {
            return existing;
        }

        ensure_prepared_udp_session(prepared_session, io_context, tunnel_pool, router, sender, cfg, src_ep);
        if (try_publish_udp_session(sessions, current, key, prepared_session))
        {
            break;
        }
    }

    return start_udp_session_or_rollback(sessions, key, prepared_session, stop_flag);
}

enum class udp_recv_status : std::uint8_t
{
    kOk,
    kTryAgain,
    kError,
};

enum class udp_wait_status : std::uint8_t
{
    kReady,
    kRetry,
    kStop,
};

udp_recv_status recv_udp_packet(boost::asio::ip::udp::socket& socket,
                                std::vector<std::uint8_t>& buffer,
                                std::array<char, 512>& control,
                                boost::asio::ip::udp::endpoint& src_ep,
                                boost::asio::ip::udp::endpoint& dst_ep,
                                std::size_t& packet_len,
                                std::string& error_text)
{
    sockaddr_storage src_addr{};
    iovec iov{};
    iov.iov_base = buffer.data();
    iov.iov_len = buffer.size();

    msghdr msg{};
    msg.msg_name = &src_addr;
    msg.msg_namelen = sizeof(src_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    const auto n = ::recvmsg(socket.native_handle(), &msg, 0);
    if (n < 0)
    {
        if (errno == EAGAIN
#if EAGAIN != EWOULDBLOCK
            || errno == EWOULDBLOCK
#endif
        )
        {
            return udp_recv_status::kTryAgain;
        }
        error_text = std::strerror(errno);
        return udp_recv_status::kError;
    }

    if ((msg.msg_flags & MSG_CTRUNC) != 0)
    {
        error_text = k_udp_recv_error_origdst_truncated;
        return udp_recv_status::kError;
    }
    if ((msg.msg_flags & MSG_TRUNC) != 0)
    {
        error_text = k_udp_recv_error_payload_truncated;
        return udp_recv_status::kError;
    }

    auto parsed_src = net::endpoint_from_sockaddr(src_addr, msg.msg_namelen);
    parsed_src = net::normalize_endpoint(parsed_src);
    const auto parsed_dst = net::parse_original_dst(msg);
    if (!parsed_dst.has_value())
    {
        error_text = k_udp_recv_error_missing_origdst;
        return udp_recv_status::kError;
    }

    src_ep = parsed_src;
    dst_ep = net::normalize_endpoint(*parsed_dst);
    packet_len = static_cast<std::size_t>(n);
    return udp_recv_status::kOk;
}

boost::asio::awaitable<udp_wait_status> wait_udp_readable(boost::asio::ip::udp::socket& socket)
{
    const auto [wait_ec] = co_await socket.async_wait(boost::asio::socket_base::wait_read, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (!wait_ec)
    {
        co_return udp_wait_status::kReady;
    }
    if (is_socket_stop_error(wait_ec))
    {
        co_return udp_wait_status::kStop;
    }
    else
    {
        LOG_ERROR("tproxy udp wait failed {}", wait_ec.message());
    }
    co_return udp_wait_status::kRetry;
}

bool read_udp_packet_for_session(boost::asio::ip::udp::socket& socket,
                                 std::vector<std::uint8_t>& buffer,
                                 std::array<char, 512>& control,
                                 boost::asio::ip::udp::endpoint& src_ep,
                                 boost::asio::ip::udp::endpoint& dst_ep,
                                 std::size_t& packet_len)
{
    std::string recv_error;
    const auto recv_status = recv_udp_packet(socket, buffer, control, src_ep, dst_ep, packet_len, recv_error);
    if (recv_status == udp_recv_status::kTryAgain)
    {
        return false;
    }
    if (recv_status == udp_recv_status::kError)
    {
        log_udp_recv_error(recv_error);
        return false;
    }
    return true;
}

enum class tcp_socket_action : std::uint8_t
{
    kContinue,
    kBreak,
};

tcp_socket_action handle_accepted_tcp_socket(boost::asio::ip::tcp::socket& socket,
                                             std::atomic<bool>& stop_flag,
                                             boost::asio::io_context& io_context,
                                             const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                             const std::shared_ptr<router>& router,
                                             const config& cfg)
{
    if (stop_flag.load(std::memory_order_acquire))
    {
        close_accepted_socket(socket);
        return tcp_socket_action::kBreak;
    }

    auto dst_ep_res = prepare_tcp_destination(socket);
    if (!dst_ep_res)
    {
        close_accepted_socket(socket);
        return tcp_socket_action::kContinue;
    }

    const std::uint32_t sid = tunnel_pool->next_session_id();
    start_tcp_session(std::move(socket), io_context, tunnel_pool, router, sid, cfg, *dst_ep_res);
    return tcp_socket_action::kContinue;
}

enum class udp_loop_action : std::uint8_t
{
    kContinue,
    kBreak,
    kHandlePacket,
};

udp_loop_action evaluate_udp_wait_status(const udp_wait_status wait_status, std::atomic<bool>& stop_flag)
{
    if (wait_status == udp_wait_status::kStop)
    {
        return udp_loop_action::kBreak;
    }
    if (wait_status == udp_wait_status::kRetry)
    {
        return udp_loop_action::kContinue;
    }
    if (stop_flag.load(std::memory_order_acquire))
    {
        return udp_loop_action::kBreak;
    }
    return udp_loop_action::kHandlePacket;
}

enum class udp_packet_action : std::uint8_t
{
    kContinue,
    kBreak,
};

boost::asio::awaitable<udp_packet_action> handle_udp_packet_once(boost::asio::ip::udp::socket& socket,
                                                                 std::atomic<bool>& stop_flag,
                                                                 std::vector<std::uint8_t>& buffer,
                                                                 std::array<char, 512>& control,
                                                                 tproxy_udp_dispatch_channel& dispatch_channel)
{
    boost::asio::ip::udp::endpoint src_ep;
    boost::asio::ip::udp::endpoint dst_ep;
    std::size_t packet_len = 0;
    if (!read_udp_packet_for_session(socket, buffer, control, src_ep, dst_ep, packet_len))
    {
        co_return udp_packet_action::kContinue;
    }

    if (stop_flag.load(std::memory_order_acquire))
    {
        co_return udp_packet_action::kBreak;
    }

    (void)tproxy_client::enqueue_udp_packet(dispatch_channel, src_ep, dst_ep, buffer, packet_len);
    co_return udp_packet_action::kContinue;
}

std::expected<void, boost::system::error_code> setup_tproxy_tcp_runtime(boost::asio::ip::tcp::acceptor& tcp_acceptor,
                                                                        const config::tproxy_t& tproxy_config,
                                                                        const std::uint16_t tcp_port,
                                                                        std::string& listen_host)
{
    auto addr_res = resolve_listen_address(tproxy_config.listen_host);
    if (!addr_res)
    {
        return std::unexpected(addr_res.error());
    }
    const auto& [host, addr] = *addr_res;
    listen_host = host;

    return setup_tcp_listener(tcp_acceptor, addr, tcp_port);
}

boost::asio::awaitable<bool> run_tcp_accept_iteration(boost::asio::ip::tcp::acceptor& tcp_acceptor,
                                                      boost::asio::io_context& io_context,
                                                      std::atomic<bool>& stop_flag,
                                                      const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                      const std::shared_ptr<router>& router,
                                                      const config& cfg)
{
    boost::asio::ip::tcp::socket socket(io_context);
    const auto accept_status = co_await accept_tcp_connection(tcp_acceptor, socket, io_context);
    if (accept_status == tcp_accept_status::kStop)
    {
        co_return false;
    }
    if (accept_status == tcp_accept_status::kRetry)
    {
        co_return true;
    }

    const auto socket_action = handle_accepted_tcp_socket(socket, stop_flag, io_context, tunnel_pool, router, cfg);
    co_return socket_action != tcp_socket_action::kBreak;
}

std::expected<void, boost::system::error_code> setup_tproxy_udp_runtime(boost::asio::ip::udp::socket& udp_socket,
                                                                        const config::tproxy_t& tproxy_config,
                                                                        const std::uint16_t udp_port,
                                                                        std::string& listen_host)
{
    auto addr_res = resolve_listen_address(tproxy_config.listen_host);
    if (!addr_res)
    {
        return std::unexpected(addr_res.error());
    }
    const auto& [host, addr] = *addr_res;
    listen_host = host;

    return setup_udp_listener(udp_socket, addr, udp_port, tproxy_config.mark);
}

boost::asio::awaitable<udp_loop_action> run_udp_iteration(boost::asio::ip::udp::socket& udp_socket,
                                                          std::atomic<bool>& stop_flag,
                                                          std::vector<std::uint8_t>& buffer,
                                                          std::array<char, 512>& control,
                                                          tproxy_udp_dispatch_channel& dispatch_channel)
{
    const auto wait_status = co_await wait_udp_readable(udp_socket);
    const auto loop_action = evaluate_udp_wait_status(wait_status, stop_flag);
    if (loop_action != udp_loop_action::kHandlePacket)
    {
        co_return loop_action;
    }

    const auto packet_action = co_await handle_udp_packet_once(udp_socket, stop_flag, buffer, control, dispatch_channel);
    if (packet_action == udp_packet_action::kBreak)
    {
        co_return udp_loop_action::kBreak;
    }
    co_return udp_loop_action::kContinue;
}

enum class udp_dispatch_receive_action : std::uint8_t
{
    kPacketReady,
    kContinue,
    kBreak,
};

boost::asio::awaitable<udp_dispatch_receive_action> receive_dispatch_packet(tproxy_udp_dispatch_channel& dispatch_channel,
                                                                            std::atomic<bool>& stop_flag,
                                                                            tproxy_udp_dispatch_item& packet)
{
    auto [recv_ec, received_packet] = co_await dispatch_channel.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (recv_ec)
    {
        if (recv_ec != boost::asio::experimental::error::channel_closed && recv_ec != boost::asio::error::operation_aborted)
        {
            LOG_ERROR("tproxy udp dispatch receive failed {}", recv_ec.message());
        }
        co_return udp_dispatch_receive_action::kBreak;
    }

    if (stop_flag.load(std::memory_order_acquire))
    {
        co_return udp_dispatch_receive_action::kBreak;
    }

    packet = std::move(received_packet);
    co_return udp_dispatch_receive_action::kPacketReady;
}

const std::string& resolve_src_key_with_cache(std::unordered_map<udp_endpoint_key, std::string, endpoint_hash, endpoint_key_equal>& src_key_cache,
                                              const boost::asio::ip::udp::endpoint& src_ep)
{
    const udp_endpoint_key src_key{.addr = src_ep.address(), .port = src_ep.port()};
    const auto cached = src_key_cache.find(src_key);
    if (cached != src_key_cache.end())
    {
        return cached->second;
    }

    if (src_key_cache.size() >= k_udp_dispatch_src_key_cache_capacity)
    {
        src_key_cache.clear();
    }
    const auto [inserted_it, inserted] = src_key_cache.emplace(src_key, make_endpoint_key(src_ep));
    (void)inserted;
    return inserted_it->second;
}

boost::asio::awaitable<bool> dispatch_udp_packet_to_session(std::shared_ptr<udp_session_map_t>& udp_sessions,
                                                            const std::string& src_key,
                                                            tproxy_udp_dispatch_item packet,
                                                            boost::asio::io_context& io_context,
                                                            const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                            const std::shared_ptr<router>& router,
                                                            const std::shared_ptr<tproxy_udp_sender>& sender,
                                                            const config& cfg,
                                                            std::atomic<bool>& stop_flag)
{
    auto session = get_or_create_udp_session(udp_sessions, src_key, packet.src_ep, io_context, tunnel_pool, router, sender, cfg, stop_flag);
    if (session == nullptr)
    {
        co_return true;
    }
    if (stop_flag.load(std::memory_order_acquire))
    {
        session->stop();
        erase_udp_session_if_same(udp_sessions, src_key, session);
        co_return false;
    }
    co_await session->handle_packet(packet.dst_ep, std::move(packet.payload));
    co_return true;
}

std::uint64_t now_steady_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

bool udp_session_is_expired(const std::shared_ptr<tproxy_udp_session>& session, const std::uint64_t now_ms, const std::uint64_t idle_ms)
{
    return session->terminated() || (idle_ms != 0 && session->is_idle(now_ms, idle_ms));
}

void split_udp_sessions_by_expiry(const std::shared_ptr<udp_session_map_t>& current,
                                  const std::uint64_t now_ms,
                                  const std::uint64_t idle_ms,
                                  std::shared_ptr<udp_session_map_t>& active_sessions,
                                  std::vector<std::shared_ptr<tproxy_udp_session>>& expired_sessions)
{
    active_sessions = std::make_shared<udp_session_map_t>();
    active_sessions->reserve(current->size());
    expired_sessions.clear();
    expired_sessions.reserve(current->size());

    for (const auto& [key, session] : *current)
    {
        if (session == nullptr)
        {
            continue;
        }
        if (udp_session_is_expired(session, now_ms, idle_ms))
        {
            expired_sessions.push_back(session);
            continue;
        }
        active_sessions->emplace(key, session);
    }
}

bool udp_sessions_unchanged(const std::shared_ptr<udp_session_map_t>& current,
                            const std::shared_ptr<udp_session_map_t>& active_sessions,
                            const std::vector<std::shared_ptr<tproxy_udp_session>>& expired_sessions)
{
    return expired_sessions.empty() && active_sessions->size() == current->size();
}

void append_expired_udp_sessions(std::vector<std::shared_ptr<tproxy_udp_session>>& target,
                                 std::vector<std::shared_ptr<tproxy_udp_session>>& detached_sessions)
{
    for (auto& session : detached_sessions)
    {
        target.push_back(std::move(session));
    }
}

void collect_expired_udp_sessions(std::shared_ptr<udp_session_map_t>& sessions,
                                  const std::uint64_t now_ms,
                                  const std::uint64_t idle_ms,
                                  std::vector<std::shared_ptr<tproxy_udp_session>>& expired_sessions)
{
    for (;;)
    {
        auto current = snapshot_udp_sessions(sessions);
        std::shared_ptr<udp_session_map_t> updated = nullptr;
        std::vector<std::shared_ptr<tproxy_udp_session>> detached_sessions;
        split_udp_sessions_by_expiry(current, now_ms, idle_ms, updated, detached_sessions);

        if (udp_sessions_unchanged(current, updated, detached_sessions))
        {
            return;
        }

        if (std::atomic_compare_exchange_weak_explicit(&sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            append_expired_udp_sessions(expired_sessions, detached_sessions);
            return;
        }
    }
}

void log_close_error(const boost::system::error_code& ec, const char* message)
{
    if (!ec)
    {
        return;
    }
    if (ec == boost::asio::error::bad_descriptor)
    {
        return;
    }
    LOG_ERROR("{} {}", message, ec.message());
}

void close_tproxy_sockets(boost::asio::ip::tcp::acceptor& tcp_acceptor, boost::asio::ip::udp::socket& udp_socket)
{
    boost::system::error_code close_ec;
    close_ec = tcp_acceptor.close(close_ec);
    log_close_error(close_ec, "tproxy acceptor close failed");
    close_ec = udp_socket.close(close_ec);
    log_close_error(close_ec, "tproxy udp close failed");
}

std::vector<std::shared_ptr<tproxy_udp_session>> extract_udp_sessions(std::shared_ptr<udp_session_map_t>& udp_sessions)
{
    auto empty = std::make_shared<udp_session_map_t>();
    for (;;)
    {
        auto current = snapshot_udp_sessions(udp_sessions);
        if (std::atomic_compare_exchange_weak_explicit(&udp_sessions, &current, empty, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            std::vector<std::shared_ptr<tproxy_udp_session>> sessions;
            sessions.reserve(current->size());
            for (auto& entry : *current)
            {
                if (entry.second != nullptr)
                {
                    sessions.push_back(entry.second);
                }
            }
            return sessions;
        }
    }
}

void stop_udp_sessions(std::vector<std::shared_ptr<tproxy_udp_session>>& sessions)
{
    for (auto& session : sessions)
    {
        session->stop();
    }
}

}    // namespace

tproxy_client::tproxy_client(io_context_pool& pool, const config& cfg)
    : io_context_(pool.get_io_context()),
      tcp_acceptor_(io_context_),
      udp_socket_(io_context_),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, cfg.tproxy.mark)),
      router_(std::make_shared<router>()),
      sender_(std::make_shared<tproxy_udp_sender>(io_context_, cfg.tproxy.mark)),
      udp_dispatch_channel_(
          std::make_shared<tproxy_udp_dispatch_channel>(io_context_, static_cast<std::size_t>(cfg.queues.tproxy_udp_dispatch_queue_capacity))),
      cfg_(cfg),
      tproxy_config_(cfg.tproxy),
      tcp_port_(cfg.tproxy.tcp_port),
      udp_port_(cfg.tproxy.udp_port == 0 ? cfg.tproxy.tcp_port : cfg.tproxy.udp_port),
      udp_idle_timeout_sec_(cfg.timeout.idle)
{
}

void tproxy_client::start()
{
    const std::lock_guard<std::mutex> lock(lifecycle_mu_);

    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        LOG_WARN("tproxy client already started");
        return;
    }
    stop_.store(false, std::memory_order_release);
    if (!tproxy_config_.enabled)
    {
        LOG_INFO("tproxy client disabled");
        rollback_start_state();
        return;
    }

    std::shared_ptr<client_tunnel_pool> tunnel_pool = nullptr;
    std::shared_ptr<router> router = nullptr;
    if (!validate_start_prerequisites(tunnel_pool, router))
    {
        return;
    }

    std::string tcp_listen_host;
    std::string udp_listen_host;
    if (!setup_runtime_sockets(tcp_listen_host, udp_listen_host))
    {
        return;
    }

    start_runtime_loops(tunnel_pool, tcp_listen_host, udp_listen_host);
}

void tproxy_client::rollback_start_state()
{
    stop_.store(true, std::memory_order_release);
    started_.store(false, std::memory_order_release);
}

bool tproxy_client::validate_start_prerequisites(std::shared_ptr<client_tunnel_pool>& tunnel_pool, std::shared_ptr<router>& router)
{
    tunnel_pool = tunnel_pool_;
    if (tunnel_pool == nullptr)
    {
        LOG_ERROR("tproxy tunnel pool unavailable");
        rollback_start_state();
        return false;
    }

    router = router_;
    if (router == nullptr)
    {
        LOG_ERROR("tproxy router unavailable");
        rollback_start_state();
        return false;
    }

    if (!tunnel_pool->valid())
    {
        LOG_ERROR("invalid reality auth config");
        rollback_start_state();
        return false;
    }

    if (!router->load())
    {
        LOG_ERROR("failed to load router data");
        rollback_start_state();
        return false;
    }

    if (tcp_port_ == 0)
    {
        LOG_ERROR("tproxy tcp port invalid");
        rollback_start_state();
        return false;
    }

    if (udp_port_ == 0)
    {
        udp_port_ = tcp_port_;
    }
    return true;
}

bool tproxy_client::setup_runtime_sockets(std::string& tcp_listen_host, std::string& udp_listen_host)
{
    if (auto res = setup_tproxy_tcp_runtime(tcp_acceptor_, tproxy_config_, tcp_port_, tcp_listen_host); !res)
    {
        LOG_ERROR("tproxy tcp setup failed {}", res.error().message());
        rollback_start_state();
        return false;
    }

    if (auto res = setup_tproxy_udp_runtime(udp_socket_, tproxy_config_, udp_port_, udp_listen_host); !res)
    {
        LOG_ERROR("tproxy udp setup failed {}", res.error().message());
        close_tproxy_sockets(tcp_acceptor_, udp_socket_);
        rollback_start_state();
        return false;
    }
    return true;
}

void tproxy_client::start_runtime_loops(const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                        const std::string& tcp_listen_host,
                                        const std::string& udp_listen_host)
{
    LOG_INFO("tproxy tcp listening on {}:{}", tcp_listen_host, tcp_port_);
    LOG_INFO("tproxy udp listening on {}:{}", udp_listen_host, udp_port_);

    udp_dispatch_channel_ =
        std::make_shared<tproxy_udp_dispatch_channel>(io_context_, static_cast<std::size_t>(cfg_.queues.tproxy_udp_dispatch_queue_capacity));
    udp_dispatch_started_.store(false, std::memory_order_release);
    tunnel_pool->start();
    auto self = shared_from_this();

    boost::asio::co_spawn(io_context_, [self]() { return self->accept_tcp_loop(); }, boost::asio::detached);

    boost::asio::co_spawn(io_context_, [self]() { return self->udp_loop(); }, boost::asio::detached);

    boost::asio::co_spawn(io_context_, [self]() { return self->udp_cleanup_loop(); }, boost::asio::detached);
}

void tproxy_client::stop()
{
    const std::lock_guard<std::mutex> lock(lifecycle_mu_);

    LOG_INFO("tproxy client stopping closing resources");
    stop_.store(true, std::memory_order_release);
    started_.store(false, std::memory_order_release);

    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   if (self->udp_dispatch_channel_ != nullptr)
                                                   {
                                                       self->udp_dispatch_channel_->close();
                                                   }
                                                   self->udp_dispatch_started_.store(false, std::memory_order_release);
                                                   close_tproxy_sockets(self->tcp_acceptor_, self->udp_socket_);
                                                   auto sessions = extract_udp_sessions(self->udp_sessions_);
                                                   stop_udp_sessions(sessions);
                                               }
                                           });

    if (tunnel_pool_ != nullptr)
    {
        tunnel_pool_->stop();
    }
}

std::string tproxy_client::endpoint_key(const boost::asio::ip::udp::endpoint& ep) { return make_endpoint_key(ep); }

bool tproxy_client::enqueue_udp_packet(tproxy_udp_dispatch_channel& dispatch_channel,
                                       const boost::asio::ip::udp::endpoint& src_ep,
                                       const boost::asio::ip::udp::endpoint& dst_ep,
                                       const std::vector<std::uint8_t>& buffer,
                                       const std::size_t packet_len)
{
    if (!is_valid_udp_dispatch_endpoint(src_ep) || !is_valid_udp_dispatch_endpoint(dst_ep))
    {
        LOG_WARN("tproxy udp invalid endpoint src {} {} dst {} {}", src_ep.address().to_string(), src_ep.port(), dst_ep.address().to_string(), dst_ep.port());
        statistics::instance().inc_tproxy_udp_dispatch_dropped();
        maybe_log_udp_dispatch_drop(statistics::instance().tproxy_udp_dispatch_dropped());
        return false;
    }

    if (packet_len == 0)
    {
        statistics::instance().inc_tproxy_udp_dispatch_dropped();
        maybe_log_udp_dispatch_drop(statistics::instance().tproxy_udp_dispatch_dropped());
        return false;
    }

    if (packet_len > buffer.size())
    {
        LOG_WARN("tproxy udp invalid packet length {} buffer size {}", packet_len, buffer.size());
        statistics::instance().inc_tproxy_udp_dispatch_dropped();
        maybe_log_udp_dispatch_drop(statistics::instance().tproxy_udp_dispatch_dropped());
        return false;
    }

    tproxy_udp_dispatch_item packet;
    packet.src_ep = src_ep;
    packet.dst_ep = dst_ep;
    packet.payload.resize(packet_len);
    if (packet_len > 0)
    {
        std::memcpy(packet.payload.data(), buffer.data(), packet_len);
    }
    if (dispatch_channel.try_send(boost::system::error_code(), std::move(packet)))
    {
        statistics::instance().inc_tproxy_udp_dispatch_enqueued();
        return true;
    }
    statistics::instance().inc_tproxy_udp_dispatch_dropped();
    maybe_log_udp_dispatch_drop(statistics::instance().tproxy_udp_dispatch_dropped());
    return false;
}

boost::asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    if (stop_.load(std::memory_order_acquire))
    {
        co_return;
    }

    auto tunnel_pool = tunnel_pool_;
    auto router = router_;
    if (tunnel_pool == nullptr || router == nullptr)
    {
        LOG_ERROR("tproxy tcp dependencies unavailable");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        co_return;
    }

    if (!tcp_acceptor_.is_open())
    {
        std::string listen_host;
        if (auto res = setup_tproxy_tcp_runtime(tcp_acceptor_, tproxy_config_, tcp_port_, listen_host); !res)
        {
            LOG_ERROR("tproxy tcp setup failed {}", res.error().message());
            stop_.store(true, std::memory_order_release);
            started_.store(false, std::memory_order_release);
            co_return;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            close_acceptor_on_setup_failure(tcp_acceptor_);
            co_return;
        }
        LOG_INFO("tproxy tcp listening on {}:{}", listen_host, tcp_port_);
    }

    while (!stop_.load(std::memory_order_acquire))
    {
        if (!co_await run_tcp_accept_iteration(tcp_acceptor_, io_context_, stop_, tunnel_pool, router, cfg_))
        {
            break;
        }
    }

    LOG_INFO("tproxy tcp accept loop exited");
}

boost::asio::awaitable<void> tproxy_client::udp_loop()
{
    if (stop_.load(std::memory_order_acquire))
    {
        co_return;
    }

    if (!udp_socket_.is_open())
    {
        std::string listen_host;
        if (auto res = setup_tproxy_udp_runtime(udp_socket_, tproxy_config_, udp_port_, listen_host); !res)
        {
            LOG_ERROR("tproxy udp setup failed {}", res.error().message());
            stop_.store(true, std::memory_order_release);
            started_.store(false, std::memory_order_release);
            co_return;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            close_udp_socket_on_setup_failure(udp_socket_);
            co_return;
        }
        LOG_INFO("tproxy udp listening on {}:{}", listen_host, udp_port_);
    }

    std::vector<std::uint8_t> buf(65535);
    std::array<char, 512> control;
    auto dispatch_channel = udp_dispatch_channel_;
    if (dispatch_channel == nullptr)
    {
        LOG_ERROR("tproxy udp dispatch channel unavailable");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        co_return;
    }
    bool expected = false;
    if (udp_dispatch_started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        auto self = shared_from_this();
        for (std::size_t i = 0; i < k_udp_dispatch_worker_count; ++i)
        {
            boost::asio::co_spawn(io_context_, [self]() { return self->udp_dispatch_loop(); }, boost::asio::detached);
        }
    }

    while (!stop_.load(std::memory_order_acquire))
    {
        const auto action = co_await run_udp_iteration(udp_socket_, stop_, buf, control, *dispatch_channel);
        if (action == udp_loop_action::kBreak)
        {
            break;
        }
    }

    LOG_INFO("tproxy udp loop exited");
}

boost::asio::awaitable<void> tproxy_client::udp_dispatch_loop()
{
    auto dispatch_channel = udp_dispatch_channel_;
    if (dispatch_channel == nullptr)
    {
        co_return;
    }
    auto tunnel_pool = tunnel_pool_;
    auto router = router_;
    auto sender = sender_;
    if (tunnel_pool == nullptr || router == nullptr || sender == nullptr)
    {
        LOG_ERROR("tproxy udp dependencies unavailable");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        co_return;
    }
    std::unordered_map<udp_endpoint_key, std::string, endpoint_hash, endpoint_key_equal> src_key_cache;
    src_key_cache.reserve(k_udp_dispatch_src_key_cache_capacity);

    while (!stop_.load(std::memory_order_acquire))
    {
        tproxy_udp_dispatch_item packet;
        const auto receive_action = co_await receive_dispatch_packet(*dispatch_channel, stop_, packet);
        if (receive_action == udp_dispatch_receive_action::kBreak)
        {
            break;
        }
        if (receive_action == udp_dispatch_receive_action::kContinue)
        {
            continue;
        }

        const auto& key = resolve_src_key_with_cache(src_key_cache, packet.src_ep);
        const bool keep_loop =
            co_await dispatch_udp_packet_to_session(udp_sessions_, key, std::move(packet), io_context_, tunnel_pool, router, sender, cfg_, stop_);
        if (!keep_loop)
        {
            break;
        }
    }

    LOG_INFO("tproxy udp dispatch loop exited");
}

boost::asio::awaitable<void> tproxy_client::udp_cleanup_loop()
{
    boost::asio::steady_timer cleanup_timer(io_context_);
    while (!stop_.load(std::memory_order_acquire))
    {
        cleanup_timer.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await cleanup_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }
            continue;
        }

        const auto now_ms = now_steady_ms();
        const auto idle_ms = udp_idle_timeout_sec_ == 0 ? 0U : static_cast<std::uint64_t>(udp_idle_timeout_sec_) * 1000U;

        std::vector<std::shared_ptr<tproxy_udp_session>> expired_sessions;
        collect_expired_udp_sessions(udp_sessions_, now_ms, idle_ms, expired_sessions);

        for (auto& session : expired_sessions)
        {
            session->stop();
        }
    }
}

}    // namespace mux
