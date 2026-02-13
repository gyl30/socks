#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <string>
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
#include <asio/ip/v6_only.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "net_utils.h"
#include "tproxy_client.h"

namespace mux
{

namespace
{

bool resolve_listen_address(const std::string& configured_host,
                            std::string& listen_host,
                            asio::ip::address& listen_addr,
                            std::error_code& ec)
{
    if (configured_host.empty())
    {
        listen_host = "::";
    }
    else
    {
        listen_host = configured_host;
    }
    listen_addr = asio::ip::make_address(listen_host, ec);
    return !ec;
}

bool setup_tcp_listener_options(asio::ip::tcp::acceptor& acceptor, const bool is_v6, std::error_code& ec)
{
    ec = acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        return false;
    }
    if (is_v6)
    {
        ec = acceptor.set_option(asio::ip::v6_only(false), ec);
        if (ec)
        {
            return false;
        }
    }
    std::error_code trans_ec;
    if (!net::set_socket_transparent(acceptor.native_handle(), is_v6, trans_ec))
    {
        ec = trans_ec;
        return false;
    }
    return true;
}

bool setup_tcp_listener(asio::ip::tcp::acceptor& acceptor, const asio::ip::address& listen_addr, const std::uint16_t port, std::error_code& ec)
{
    const asio::ip::tcp::endpoint ep{listen_addr, port};
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return false;
    }
    if (!setup_tcp_listener_options(acceptor, listen_addr.is_v6(), ec))
    {
        return false;
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        return false;
    }
    ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
    return !ec;
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

bool set_udp_dual_stack_if_needed(asio::ip::udp::socket& socket, const bool is_v6, std::error_code& ec)
{
    if (!is_v6)
    {
        return true;
    }
    ec = socket.set_option(asio::ip::v6_only(false), ec);
    return !ec;
}

bool configure_udp_transparent_options(asio::ip::udp::socket& socket, const bool is_v6, std::error_code& ec)
{
    std::error_code trans_ec;
    if (!net::set_socket_transparent(socket.native_handle(), is_v6, trans_ec))
    {
        ec = trans_ec;
        return false;
    }

    std::error_code recv_ec;
    if (!net::set_socket_recv_origdst(socket.native_handle(), is_v6, recv_ec))
    {
        ec = recv_ec;
        return false;
    }
    return true;
}

void maybe_set_udp_mark(asio::ip::udp::socket& socket, const std::uint32_t mark)
{
    if (mark == 0)
    {
        return;
    }
    std::error_code mark_ec;
    if (!net::set_socket_mark(socket.native_handle(), mark, mark_ec))
    {
        LOG_WARN("tproxy udp set mark failed code {}", mark_ec.value());
    }
}

bool setup_udp_listener(asio::ip::udp::socket& socket,
                        const asio::ip::address& listen_addr,
                        const std::uint16_t port,
                        const std::uint32_t mark,
                        std::error_code& ec)
{
    const bool is_v6 = listen_addr.is_v6();
    const asio::ip::udp::endpoint ep{listen_addr, port};
    ec = socket.open(ep.protocol(), ec);
    if (ec)
    {
        return false;
    }
    set_udp_reuse_option(socket);
    if (!set_udp_dual_stack_if_needed(socket, is_v6, ec))
    {
        return false;
    }
    if (!configure_udp_transparent_options(socket, is_v6, ec))
    {
        return false;
    }
    maybe_set_udp_mark(socket, mark);

    ec = socket.bind(ep, ec);
    return !ec;
}

std::string make_endpoint_key(const asio::ip::udp::endpoint& ep)
{
    return ep.address().to_string() + ":" + std::to_string(ep.port());
}

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

bool prepare_tcp_destination(asio::ip::tcp::socket& socket, asio::ip::tcp::endpoint& dst_ep)
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
        return false;
    }

    dst_ep = asio::ip::tcp::endpoint(net::normalize_address(local_ep.address()), local_ep.port());
    return true;
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

std::shared_ptr<tproxy_udp_session> get_or_create_udp_session(
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& sessions,
    const std::string& key,
    const asio::ip::udp::endpoint& src_ep,
    asio::io_context& io_context,
    const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
    const std::shared_ptr<router>& router,
    const std::shared_ptr<tproxy_udp_sender>& sender,
    const config& cfg)
{
    auto it = sessions.find(key);
    if (it != sessions.end())
    {
        return it->second;
    }

    const std::uint32_t sid = tunnel_pool->next_session_id();
    auto session = std::make_shared<tproxy_udp_session>(io_context, tunnel_pool, router, sender, sid, cfg, src_ep);
    session->start();
    sessions.emplace(key, session);
    return session;
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

asio::awaitable<void> dispatch_udp_packet(std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& sessions,
                                          const std::string& key,
                                          const asio::ip::udp::endpoint& src_ep,
                                          const asio::ip::udp::endpoint& dst_ep,
                                          const std::vector<std::uint8_t>& buffer,
                                          const std::size_t packet_len,
                                          asio::io_context& io_context,
                                          const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                          const std::shared_ptr<router>& router,
                                          const std::shared_ptr<tproxy_udp_sender>& sender,
                                          const config& cfg)
{
    auto session = get_or_create_udp_session(sessions, key, src_ep, io_context, tunnel_pool, router, sender, cfg);
    if (session != nullptr)
    {
        co_await session->handle_packet(dst_ep, buffer.data(), packet_len);
    }
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

    asio::ip::tcp::endpoint dst_ep;
    if (!prepare_tcp_destination(socket, dst_ep))
    {
        close_accepted_socket(socket);
        return tcp_socket_action::kContinue;
    }

    const std::uint32_t sid = tunnel_pool->next_session_id();
    start_tcp_session(std::move(socket), io_context, tunnel_pool, router, sid, cfg, dst_ep);
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
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& sessions,
    std::atomic<bool>& stop_flag,
    std::vector<std::uint8_t>& buffer,
    std::array<char, 512>& control,
    asio::io_context& io_context,
    const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
    const std::shared_ptr<router>& router,
    const std::shared_ptr<tproxy_udp_sender>& sender,
    const config& cfg)
{
    asio::ip::udp::endpoint src_ep;
    asio::ip::udp::endpoint dst_ep;
    std::size_t packet_len = 0;
    if (!read_udp_packet_for_session(socket, buffer, control, src_ep, dst_ep, packet_len))
    {
        co_return udp_packet_action::kContinue;
    }

    const auto key = make_endpoint_key(src_ep);
    if (stop_flag.load(std::memory_order_acquire))
    {
        co_return udp_packet_action::kBreak;
    }

    co_await dispatch_udp_packet(sessions, key, src_ep, dst_ep, buffer, packet_len, io_context, tunnel_pool, router, sender, cfg);
    co_return udp_packet_action::kContinue;
}

bool setup_tproxy_tcp_runtime(asio::ip::tcp::acceptor& tcp_acceptor,
                              const config::tproxy_t& tproxy_config,
                              const std::uint16_t tcp_port,
                              std::string& listen_host,
                              std::error_code& out_ec)
{
    asio::ip::address listen_addr;
    if (!resolve_listen_address(tproxy_config.listen_host, listen_host, listen_addr, out_ec))
    {
        return false;
    }
    return setup_tcp_listener(tcp_acceptor, listen_addr, tcp_port, out_ec);
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

bool setup_tproxy_udp_runtime(asio::ip::udp::socket& udp_socket,
                              const config::tproxy_t& tproxy_config,
                              const std::uint16_t udp_port,
                              std::string& listen_host,
                              std::error_code& out_ec)
{
    asio::ip::address listen_addr;
    if (!resolve_listen_address(tproxy_config.listen_host, listen_host, listen_addr, out_ec))
    {
        return false;
    }
    return setup_udp_listener(udp_socket, listen_addr, udp_port, tproxy_config.mark, out_ec);
}

asio::awaitable<udp_loop_action> run_udp_iteration(asio::ip::udp::socket& udp_socket,
                                                   std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& udp_sessions,
                                                   std::atomic<bool>& stop_flag,
                                                   std::vector<std::uint8_t>& buffer,
                                                   std::array<char, 512>& control,
                                                   asio::io_context& io_context,
                                                   const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                   const std::shared_ptr<router>& router,
                                                   const std::shared_ptr<tproxy_udp_sender>& sender,
                                                   const config& cfg)
{
    const auto wait_status = co_await wait_udp_readable(udp_socket);
    const auto loop_action = evaluate_udp_wait_status(wait_status, stop_flag);
    if (loop_action != udp_loop_action::kHandlePacket)
    {
        co_return loop_action;
    }

    const auto packet_action =
        co_await handle_udp_packet_once(udp_socket, udp_sessions, stop_flag, buffer, control, io_context, tunnel_pool, router, sender, cfg);
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

void collect_expired_udp_sessions(std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& sessions,
                                  const std::uint64_t now_ms,
                                  const std::uint64_t idle_ms,
                                  std::vector<std::shared_ptr<tproxy_udp_session>>& expired_sessions)
{
    for (auto it = sessions.begin(); it != sessions.end();)
    {
        if (it->second == nullptr)
        {
            ++it;
            continue;
        }
        if (!it->second->is_idle(now_ms, idle_ms))
        {
            ++it;
            continue;
        }
        expired_sessions.push_back(it->second);
        it = sessions.erase(it);
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
    std::unordered_map<std::string, std::shared_ptr<tproxy_udp_session>>& udp_sessions)
{
    std::vector<std::shared_ptr<tproxy_udp_session>> sessions;
    sessions.reserve(udp_sessions.size());
    for (auto& entry : udp_sessions)
    {
        if (entry.second != nullptr)
        {
            sessions.push_back(entry.second);
        }
    }
    udp_sessions.clear();
    return sessions;
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
      cfg_(cfg),
      tproxy_config_(cfg.tproxy),
      tcp_port_(cfg.tproxy.tcp_port),
      udp_port_(cfg.tproxy.udp_port == 0 ? cfg.tproxy.tcp_port : cfg.tproxy.udp_port),
      udp_idle_timeout_sec_(cfg.timeout.idle)
{
}

void tproxy_client::start()
{
    stop_.store(false, std::memory_order_release);
    if (!tproxy_config_.enabled)
    {
        LOG_INFO("tproxy client disabled");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (!tunnel_pool_->valid())
    {
        LOG_ERROR("invalid reality auth config");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (!router_->load())
    {
        LOG_ERROR("failed to load router data");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (tcp_port_ == 0)
    {
        LOG_ERROR("tproxy tcp port invalid");
        stop_.store(true, std::memory_order_release);
        return;
    }
    if (udp_port_ == 0)
    {
        udp_port_ = tcp_port_;
    }

    tunnel_pool_->start();
    auto self = shared_from_this();

    asio::co_spawn(io_context_, [self]() { return self->accept_tcp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self]() { return self->udp_loop(); }, asio::detached);

    asio::co_spawn(io_context_, [self]() { return self->udp_cleanup_loop(); }, asio::detached);
}

void tproxy_client::stop()
{
    LOG_INFO("tproxy client stopping closing resources");
    stop_.store(true, std::memory_order_release);

    asio::dispatch(io_context_,
                   [self = shared_from_this()]()
                   {
                       close_tproxy_sockets(self->tcp_acceptor_, self->udp_socket_);
                       auto sessions = extract_udp_sessions(self->udp_sessions_);
                       stop_udp_sessions(sessions);
                   });

    tunnel_pool_->stop();
}

std::string tproxy_client::endpoint_key(const asio::ip::udp::endpoint& ep) const
{
    return make_endpoint_key(ep);
}

asio::awaitable<void> tproxy_client::accept_tcp_loop()
{
    std::string listen_host;
    std::error_code setup_ec;
    if (!setup_tproxy_tcp_runtime(tcp_acceptor_, tproxy_config_, tcp_port_, listen_host, setup_ec))
    {
        LOG_ERROR("tproxy tcp setup failed {}", setup_ec.message());
        co_return;
    }

    LOG_INFO("tproxy tcp listening on {}:{}", listen_host, tcp_port_);

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
    std::string listen_host;
    std::error_code setup_ec;
    if (!setup_tproxy_udp_runtime(udp_socket_, tproxy_config_, udp_port_, listen_host, setup_ec))
    {
        LOG_ERROR("tproxy udp setup failed {}", setup_ec.message());
        co_return;
    }

    LOG_INFO("tproxy udp listening on {}:{}", listen_host, udp_port_);

    std::vector<std::uint8_t> buf(65535);
    std::array<char, 512> control;

    while (!stop_.load(std::memory_order_acquire))
    {
        const auto action = co_await run_udp_iteration(
            udp_socket_, udp_sessions_, stop_, buf, control, io_context_, tunnel_pool_, router_, sender_, cfg_);
        if (action == udp_loop_action::kBreak)
        {
            break;
        }
    }

    LOG_INFO("tproxy udp loop exited");
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

        if (udp_idle_timeout_sec_ == 0)
        {
            continue;
        }

        const auto now_ms = now_steady_ms();
        const auto idle_ms = static_cast<std::uint64_t>(udp_idle_timeout_sec_) * 1000U;

        std::vector<std::shared_ptr<tproxy_udp_session>> expired_sessions;
        collect_expired_udp_sessions(udp_sessions_, now_ms, idle_ms, expired_sessions);

        for (auto& session : expired_sessions)
        {
            session->stop();
        }
    }
}

}    // namespace mux
