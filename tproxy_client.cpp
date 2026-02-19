#include <array>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/experimental/channel_error.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "statistics.h"
#include "stop_dispatch.h"
#include "tproxy_client.h"

namespace mux
{

namespace
{

constexpr std::size_t k_udp_dispatch_worker_count = 4;
constexpr std::uint64_t k_udp_dispatch_drop_log_sample = 256;
constexpr std::size_t k_udp_dispatch_src_key_cache_capacity = 256;
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

void close_acceptor_on_setup_failure(asio::ip::tcp::acceptor& acceptor)
{
    std::error_code close_ec;
    acceptor.close(close_ec);
}

void close_udp_socket_on_setup_failure(asio::ip::udp::socket& socket)
{
    std::error_code close_ec;
    socket.close(close_ec);
}

std::expected<std::pair<std::string, asio::ip::address>, std::error_code> resolve_listen_address(const std::string& configured_host)
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
    std::error_code ec;
    auto listen_addr = asio::ip::make_address(listen_host, ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    return std::make_pair(listen_host, listen_addr);
}

std::expected<void, std::error_code> setup_tcp_listener_options(asio::ip::tcp::acceptor& acceptor, const bool is_v6)
{
    std::error_code ec;
    ec = acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    if (is_v6)
    {
        ec = acceptor.set_option(asio::ip::v6_only(false), ec);
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

std::expected<void, std::error_code> setup_tcp_listener(asio::ip::tcp::acceptor& acceptor, const asio::ip::address& listen_addr, const std::uint16_t port)
{
    const asio::ip::tcp::endpoint ep{listen_addr, port};
    std::error_code ec;
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
    ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        close_acceptor_on_setup_failure(acceptor);
        return std::unexpected(ec);
    }
    return {};
}

void set_udp_reuse_option(asio::ip::udp::socket& socket)
{
    std::error_code ec;
    ec = socket.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        LOG_WARN("tproxy udp reuse addr failed {}", ec.message());
    }
}

std::expected<void, std::error_code> set_udp_dual_stack_if_needed(asio::ip::udp::socket& socket, const bool is_v6)
{
    if (!is_v6)
    {
        return {};
    }
    std::error_code ec;
    ec = socket.set_option(asio::ip::v6_only(false), ec);
    if (ec)
    {
        return std::unexpected(ec);
    }
    return {};
}

std::expected<void, std::error_code> configure_udp_transparent_options(asio::ip::udp::socket& socket, const bool is_v6)
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

void maybe_set_udp_mark(asio::ip::udp::socket& socket, const std::uint32_t mark)
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

std::expected<void, std::error_code> setup_udp_listener(asio::ip::udp::socket& socket,
                        const asio::ip::address& listen_addr,
                        const std::uint16_t port,
                        const std::uint32_t mark)
{
    const bool is_v6 = listen_addr.is_v6();
    const asio::ip::udp::endpoint ep{listen_addr, port};
    std::error_code ec;
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

std::string make_endpoint_key(const asio::ip::udp::endpoint& ep)
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
    asio::ip::address addr;
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
    bool operator()(const udp_endpoint_key& lhs, const udp_endpoint_key& rhs) const noexcept
    {
        return lhs.port == rhs.port && lhs.addr == rhs.addr;
    }
};

void close_accepted_socket(asio::ip::tcp::socket& socket)
{
    std::error_code close_ec;
    close_ec = socket.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
    close_ec = socket.close(close_ec);
}

asio::awaitable<void> wait_retry_delay(asio::io_context& io_context)
{
    asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(1));
    (void)co_await retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
}

enum class tcp_accept_status
{
    kAccepted,
    kRetry,
    kStop,
};

asio::awaitable<tcp_accept_status> accept_tcp_connection(asio::ip::tcp::acceptor& acceptor,
                                                         asio::ip::tcp::socket& socket,
                                                         asio::io_context& io_context)
{
    const auto [accept_ec] = co_await acceptor.async_accept(socket, asio::as_tuple(asio::use_awaitable));
    if (!accept_ec)
    {
        co_return tcp_accept_status::kAccepted;
    }
    if (accept_ec == asio::error::operation_aborted)
    {
        co_return tcp_accept_status::kStop;
    }
    LOG_ERROR("tproxy tcp accept failed {}", accept_ec.message());
    co_await wait_retry_delay(io_context);
    co_return tcp_accept_status::kRetry;
}

std::expected<asio::ip::tcp::endpoint, std::error_code> prepare_tcp_destination(asio::ip::tcp::socket& socket)
{
    std::error_code ec;
    ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
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

    return asio::ip::tcp::endpoint(net::normalize_address(local_ep.address()), local_ep.port());
}

void start_tcp_session(asio::ip::tcp::socket s,
                       asio::io_context& io_context,
                       const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                       const std::shared_ptr<router>& router,
                       const std::uint32_t sid,
                       const config& cfg,
                       const asio::ip::tcp::endpoint& dst_ep)
{
    auto session = std::make_shared<tproxy_tcp_session>(std::move(s), io_context, tunnel_pool, router, sid, cfg, dst_ep);
    session->start();
}

void log_udp_recv_error(const std::string& error_text)
{
    if (error_text == "missing origdst")
    {
        LOG_WARN("tproxy udp missing origdst");
        return;
    }
    LOG_ERROR("tproxy udp recvmsg failed {}", error_text);
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
        if (std::atomic_compare_exchange_weak_explicit(
                &sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

std::shared_ptr<tproxy_udp_session> get_or_create_udp_session(
    std::shared_ptr<udp_session_map_t>& sessions,
    const std::string& key,
    const asio::ip::udp::endpoint& src_ep,
    asio::io_context& io_context,
    const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
    const std::shared_ptr<router>& router,
    const std::shared_ptr<tproxy_udp_sender>& sender,
    const config& cfg,
    const std::atomic<bool>& stop_flag)
{
    if (stop_flag.load(std::memory_order_acquire))
    {
        return nullptr;
    }

    std::shared_ptr<tproxy_udp_session> prepared_session = nullptr;
    for (;;)
    {
        if (stop_flag.load(std::memory_order_acquire))
        {
            return nullptr;
        }

        auto current = snapshot_udp_sessions(sessions);
        const auto it = current->find(key);
        if (it != current->end() && it->second != nullptr && !it->second->terminated())
        {
            return it->second;
        }

        if (prepared_session == nullptr)
        {
            const std::uint32_t sid = tunnel_pool->next_session_id();
            prepared_session = std::make_shared<tproxy_udp_session>(io_context, tunnel_pool, router, sender, sid, cfg, src_ep);
        }

        auto updated = std::make_shared<udp_session_map_t>(*current);
        (*updated)[key] = prepared_session;
        if (std::atomic_compare_exchange_weak_explicit(
                &sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            break;
        }
    }

    if (stop_flag.load(std::memory_order_acquire))
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

    if (stop_flag.load(std::memory_order_acquire))
    {
        prepared_session->stop();
        erase_udp_session_if_same(sessions, key, prepared_session);
        return nullptr;
    }
    return prepared_session;
}

enum class udp_recv_status
{
    kOk,
    kTryAgain,
    kError,
};

enum class udp_wait_status
{
    kReady,
    kRetry,
    kStop,
};

udp_recv_status recv_udp_packet(asio::ip::udp::socket& socket,
                                std::vector<std::uint8_t>& buffer,
                                std::array<char, 512>& control,
                                asio::ip::udp::endpoint& src_ep,
                                asio::ip::udp::endpoint& dst_ep,
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

    auto parsed_src = net::endpoint_from_sockaddr(src_addr, msg.msg_namelen);
    parsed_src = net::normalize_endpoint(parsed_src);
    const auto parsed_dst = net::parse_original_dst(msg);
    if (!parsed_dst.has_value())
    {
        error_text = "missing origdst";
        return udp_recv_status::kError;
    }

    src_ep = parsed_src;
    dst_ep = net::normalize_endpoint(*parsed_dst);
    packet_len = static_cast<std::size_t>(n);
    return udp_recv_status::kOk;
}

asio::awaitable<udp_wait_status> wait_udp_readable(asio::ip::udp::socket& socket)
{
    const auto [wait_ec] = co_await socket.async_wait(asio::socket_base::wait_read, asio::as_tuple(asio::use_awaitable));
    if (!wait_ec)
    {
        co_return udp_wait_status::kReady;
    }
    if (wait_ec == asio::error::operation_aborted)
    {
        co_return udp_wait_status::kStop;
    }
    else
    {
        LOG_ERROR("tproxy udp wait failed {}", wait_ec.message());
    }
    co_return udp_wait_status::kRetry;
}

bool read_udp_packet_for_session(asio::ip::udp::socket& socket,
                                 std::vector<std::uint8_t>& buffer,
                                 std::array<char, 512>& control,
                                 asio::ip::udp::endpoint& src_ep,
                                 asio::ip::udp::endpoint& dst_ep,
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

enum class tcp_socket_action
{
    kContinue,
    kBreak,
};

tcp_socket_action handle_accepted_tcp_socket(asio::ip::tcp::socket& socket,
                                             std::atomic<bool>& stop_flag,
                                             asio::io_context& io_context,
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

enum class udp_loop_action
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

enum class udp_packet_action
{
    kContinue,
    kBreak,
};

asio::awaitable<udp_packet_action> handle_udp_packet_once(
    asio::ip::udp::socket& socket,
    std::atomic<bool>& stop_flag,
    std::vector<std::uint8_t>& buffer,
    std::array<char, 512>& control,
    tproxy_udp_dispatch_channel& dispatch_channel)
{
    asio::ip::udp::endpoint src_ep;
    asio::ip::udp::endpoint dst_ep;
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

std::expected<void, std::error_code> setup_tproxy_tcp_runtime(asio::ip::tcp::acceptor& tcp_acceptor,
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

asio::awaitable<bool> run_tcp_accept_iteration(asio::ip::tcp::acceptor& tcp_acceptor,
                                               asio::io_context& io_context,
                                               std::atomic<bool>& stop_flag,
                                               const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                               const std::shared_ptr<router>& router,
                                               const config& cfg)
{
    asio::ip::tcp::socket socket(io_context);
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

std::expected<void, std::error_code> setup_tproxy_udp_runtime(asio::ip::udp::socket& udp_socket,
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

asio::awaitable<udp_loop_action> run_udp_iteration(asio::ip::udp::socket& udp_socket,
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

    const auto packet_action =
        co_await handle_udp_packet_once(udp_socket, stop_flag, buffer, control, dispatch_channel);
    if (packet_action == udp_packet_action::kBreak)
    {
        co_return udp_loop_action::kBreak;
    }
    co_return udp_loop_action::kContinue;
}

std::uint64_t now_steady_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void collect_expired_udp_sessions(std::shared_ptr<udp_session_map_t>& sessions,
                                  const std::uint64_t now_ms,
                                  const std::uint64_t idle_ms,
                                  std::vector<std::shared_ptr<tproxy_udp_session>>& expired_sessions)
{
    for (;;)
    {
        auto current = snapshot_udp_sessions(sessions);
        auto updated = std::make_shared<udp_session_map_t>();
        updated->reserve(current->size());
        std::vector<std::shared_ptr<tproxy_udp_session>> detached_sessions;
        detached_sessions.reserve(current->size());

        for (const auto& [key, session] : *current)
        {
            if (session == nullptr)
            {
                continue;
            }
            if (session->terminated() || (idle_ms != 0 && session->is_idle(now_ms, idle_ms)))
            {
                detached_sessions.push_back(session);
                continue;
            }
            updated->emplace(key, session);
        }

        if (detached_sessions.empty() && updated->size() == current->size())
        {
            return;
        }

        if (std::atomic_compare_exchange_weak_explicit(
                &sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            for (auto& session : detached_sessions)
            {
                expired_sessions.push_back(std::move(session));
            }
            return;
        }
    }
}

void log_close_error(const std::error_code& ec, const char* message)
{
    if (!ec)
    {
        return;
    }
    if (ec == asio::error::bad_descriptor)
    {
        return;
    }
    LOG_ERROR("{} {}", message, ec.message());
}

void close_tproxy_sockets(asio::ip::tcp::acceptor& tcp_acceptor, asio::ip::udp::socket& udp_socket)
{
    std::error_code close_ec;
    close_ec = tcp_acceptor.close(close_ec);
    log_close_error(close_ec, "tproxy acceptor close failed");
    close_ec = udp_socket.close(close_ec);
    log_close_error(close_ec, "tproxy udp close failed");
}

std::vector<std::shared_ptr<tproxy_udp_session>> extract_udp_sessions(
    std::shared_ptr<udp_session_map_t>& udp_sessions)
{
    auto empty = std::make_shared<udp_session_map_t>();
    for (;;)
    {
        auto current = snapshot_udp_sessions(udp_sessions);
        if (std::atomic_compare_exchange_weak_explicit(
                &udp_sessions, &current, empty, std::memory_order_acq_rel, std::memory_order_acquire))
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
      udp_dispatch_channel_(std::make_shared<tproxy_udp_dispatch_channel>(
          io_context_, static_cast<std::size_t>(cfg.queues.tproxy_udp_dispatch_queue_capacity))),
      cfg_(cfg),
      tproxy_config_(cfg.tproxy),
      tcp_port_(cfg.tproxy.tcp_port),
      udp_port_(cfg.tproxy.udp_port == 0 ? cfg.tproxy.tcp_port : cfg.tproxy.udp_port),
      udp_idle_timeout_sec_(cfg.timeout.idle)
{
}

void tproxy_client::start()
{
    std::lock_guard<std::mutex> lock(lifecycle_mu_);

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
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }
    if (!tunnel_pool_->valid())
    {
        LOG_ERROR("invalid reality auth config");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }
    if (tcp_port_ == 0)
    {
        LOG_ERROR("tproxy tcp port invalid");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }
    if (udp_port_ == 0)
    {
        udp_port_ = tcp_port_;
    }

    std::string tcp_listen_host;
    if (auto res = setup_tproxy_tcp_runtime(tcp_acceptor_, tproxy_config_, tcp_port_, tcp_listen_host); !res)
    {
        LOG_ERROR("tproxy tcp setup failed {}", res.error().message());
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }

    std::string udp_listen_host;
    if (auto res = setup_tproxy_udp_runtime(udp_socket_, tproxy_config_, udp_port_, udp_listen_host); !res)
    {
        LOG_ERROR("tproxy udp setup failed {}", res.error().message());
        close_tproxy_sockets(tcp_acceptor_, udp_socket_);
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }

    LOG_INFO("tproxy tcp listening on {}:{}", tcp_listen_host, tcp_port_);
    LOG_INFO("tproxy udp listening on {}:{}", udp_listen_host, udp_port_);

    udp_dispatch_channel_ = std::make_shared<tproxy_udp_dispatch_channel>(
        io_context_, static_cast<std::size_t>(cfg_.queues.tproxy_udp_dispatch_queue_capacity));
    udp_dispatch_started_.store(false, std::memory_order_release);
    tunnel_pool_->start();
    auto self = shared_from_this();

    asio::co_spawn(io_context_, [self]() { return self->accept_tcp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self]() { return self->udp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self]() { return self->udp_cleanup_loop(); }, asio::detached);
}

void tproxy_client::stop()
{
    std::lock_guard<std::mutex> lock(lifecycle_mu_);

    LOG_INFO("tproxy client stopping closing resources");
    stop_.store(true, std::memory_order_release);
    started_.store(false, std::memory_order_release);

    detail::dispatch_cleanup_or_run_inline(
        io_context_,
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

    tunnel_pool_->stop();
}

std::string tproxy_client::endpoint_key(const asio::ip::udp::endpoint& ep) const
{
    return make_endpoint_key(ep);
}

bool tproxy_client::enqueue_udp_packet(tproxy_udp_dispatch_channel& dispatch_channel,
                                       const asio::ip::udp::endpoint& src_ep,
                                       const asio::ip::udp::endpoint& dst_ep,
                                       const std::vector<std::uint8_t>& buffer,
                                       const std::size_t packet_len)
{
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
    if (dispatch_channel.try_send(std::error_code(), std::move(packet)))
    {
        statistics::instance().inc_tproxy_udp_dispatch_enqueued();
        return true;
    }
    statistics::instance().inc_tproxy_udp_dispatch_dropped();
    maybe_log_udp_dispatch_drop(statistics::instance().tproxy_udp_dispatch_dropped());
    return false;
}

asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    if (stop_.load(std::memory_order_acquire))
    {
        co_return;
    }

    if (!tcp_acceptor_.is_open())
    {
        std::string listen_host;
        if (auto res = setup_tproxy_tcp_runtime(tcp_acceptor_, tproxy_config_, tcp_port_, listen_host); !res)
        {
            LOG_ERROR("tproxy tcp setup failed {}", res.error().message());
            stop_.store(true, std::memory_order_release);
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
        if (!co_await run_tcp_accept_iteration(tcp_acceptor_, io_context_, stop_, tunnel_pool_, router_, cfg_))
        {
            break;
        }
    }

    LOG_INFO("tproxy tcp accept loop exited");
}

asio::awaitable<void> tproxy_client::udp_loop()
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
        co_return;
    }
    bool expected = false;
    if (udp_dispatch_started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        auto self = shared_from_this();
        for (std::size_t i = 0; i < k_udp_dispatch_worker_count; ++i)
        {
            asio::co_spawn(io_context_, [self]() { return self->udp_dispatch_loop(); }, asio::detached);
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

asio::awaitable<void> tproxy_client::udp_dispatch_loop()
{
    auto dispatch_channel = udp_dispatch_channel_;
    if (dispatch_channel == nullptr)
    {
        co_return;
    }
    std::unordered_map<udp_endpoint_key, std::string, endpoint_hash, endpoint_key_equal> src_key_cache;
    src_key_cache.reserve(k_udp_dispatch_src_key_cache_capacity);

    while (!stop_.load(std::memory_order_acquire))
    {
        const auto [recv_ec, packet] = co_await dispatch_channel->async_receive(asio::as_tuple(asio::use_awaitable));
        if (recv_ec)
        {
            if (recv_ec != asio::experimental::error::channel_closed && recv_ec != asio::error::operation_aborted)
            {
                LOG_ERROR("tproxy udp dispatch receive failed {}", recv_ec.message());
            }
            break;
        }

        if (stop_.load(std::memory_order_acquire))
        {
            break;
        }

        if (packet.payload.empty())
        {
            continue;
        }

        const udp_endpoint_key src_key{packet.src_ep.address(), packet.src_ep.port()};
        const std::string* key = nullptr;
        const auto it = src_key_cache.find(src_key);
        if (it != src_key_cache.end())
        {
            key = &it->second;
        }
        else
        {
            if (src_key_cache.size() >= k_udp_dispatch_src_key_cache_capacity)
            {
                src_key_cache.clear();
            }
            const auto [inserted_it, inserted] = src_key_cache.emplace(src_key, make_endpoint_key(packet.src_ep));
            (void)inserted;
            key = &inserted_it->second;
        }

        auto session = get_or_create_udp_session(udp_sessions_, *key, packet.src_ep, io_context_, tunnel_pool_, router_, sender_, cfg_, stop_);
        if (session == nullptr)
        {
            continue;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            session->stop();
            erase_udp_session_if_same(udp_sessions_, *key, session);
            break;
        }
        co_await session->handle_packet(packet.dst_ep, std::move(packet.payload));
    }

    LOG_INFO("tproxy udp dispatch loop exited");
}

asio::awaitable<void> tproxy_client::udp_cleanup_loop()
{
    asio::steady_timer cleanup_timer(io_context_);
    while (!stop_.load(std::memory_order_acquire))
    {
        cleanup_timer.expires_after(std::chrono::seconds(1));
        const auto [ec] = co_await cleanup_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            if (ec == asio::error::operation_aborted)
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
