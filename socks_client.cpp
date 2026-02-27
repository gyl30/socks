#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "mux_tunnel.h"
#include "context_pool.h"
#include "socks_client.h"
#include "socks_session.h"
#include "tcp_socks_session.h"
#include "udp_socks_session.h"
#include "stop_dispatch.h"
#include "client_tunnel_pool.h"

namespace mux
{

namespace
{

template <typename SessionT>
using weak_session_list_t = std::vector<std::weak_ptr<SessionT>>;

using session_list_t = weak_session_list_t<socks_session>;
using tcp_session_list_t = weak_session_list_t<tcp_socks_session>;
using udp_session_list_t = weak_session_list_t<udp_socks_session>;
constexpr std::uint32_t kEphemeralBindRetryAttempts = 120;

bool socks_client_running(const std::atomic<socks_client_state>& state)
{
    return state.load(std::memory_order_acquire) == socks_client_state::kRunning;
}

void socks_client_request_stop(std::atomic<socks_client_state>& state)
{
    state.store(socks_client_state::kStopping, std::memory_order_release);
}

void close_local_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code close_ec;
    close_ec = socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
    close_ec = socket.close(close_ec);
}

void close_local_acceptor_on_setup_failure(boost::asio::ip::tcp::acceptor& acceptor)
{
    boost::system::error_code close_ec;
    close_ec = acceptor.close(close_ec);
}

bool setup_local_acceptor(boost::asio::ip::tcp::acceptor& acceptor,
                          const boost::asio::ip::address& listen_addr,
                          const std::uint16_t port,
                          std::uint16_t& bound_port,
                          boost::system::error_code& ec)
{
    const boost::asio::ip::tcp::endpoint ep{listen_addr, port};
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return false;
    }
    ec = acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        close_local_acceptor_on_setup_failure(acceptor);
        return false;
    }
    ec = acceptor.bind(ep, ec);
    if (ec)
    {
        close_local_acceptor_on_setup_failure(acceptor);
        return false;
    }
    const auto bound_ep = acceptor.local_endpoint(ec);
    if (ec)
    {
        close_local_acceptor_on_setup_failure(acceptor);
        return false;
    }
    bound_port = bound_ep.port();
    ec = acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        close_local_acceptor_on_setup_failure(acceptor);
    }
    return !ec;
}

bool prepare_local_listener(boost::asio::ip::tcp::acceptor& acceptor, const std::string& host, const std::uint16_t port, std::uint16_t& bound_port)
{
    boost::system::error_code addr_ec;
    const auto listen_addr = boost::asio::ip::make_address(host, addr_ec);
    if (addr_ec)
    {
        LOG_ERROR("local acceptor parse address failed {}", addr_ec.message());
        return false;
    }

    const bool retry_ephemeral_bind = (port == 0);
    const std::uint32_t max_attempts = retry_ephemeral_bind ? kEphemeralBindRetryAttempts : 1;

    boost::system::error_code setup_ec;
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        if (setup_local_acceptor(acceptor, listen_addr, port, bound_port, setup_ec))
        {
            return true;
        }

        const bool can_retry = retry_ephemeral_bind && setup_ec == boost::asio::error::address_in_use && (attempt + 1) < max_attempts;
        if (!can_retry)
        {
            break;
        }
    }

    LOG_ERROR("local acceptor setup failed {}", setup_ec.message());
    return false;
}

void log_accept_error(const boost::system::error_code& ec) { LOG_ERROR("local accept failed {}", ec.message()); }

boost::asio::awaitable<void> wait_retry_delay(boost::asio::io_context& io_context)
{
    boost::asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(1));
    (void)co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
}

enum class local_accept_status : std::uint8_t
{
    kAccepted,
    kRetry,
    kStop,
};

boost::asio::awaitable<local_accept_status> accept_local_socket(boost::asio::ip::tcp::acceptor& acceptor,
                                                                boost::asio::ip::tcp::socket& socket,
                                                                boost::asio::io_context& io_context)
{
    const auto [accept_ec] = co_await acceptor.async_accept(socket, boost::asio::as_tuple(boost::asio::use_awaitable));
    if (!accept_ec)
    {
        co_return local_accept_status::kAccepted;
    }
    if (accept_ec == boost::asio::error::operation_aborted)
    {
        co_return local_accept_status::kStop;
    }
    log_accept_error(accept_ec);
    co_await wait_retry_delay(io_context);
    co_return local_accept_status::kRetry;
}

void set_no_delay_or_log(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("failed to set no delay on local socket {}", ec.message());
    }
}

template <typename SessionT>
std::shared_ptr<weak_session_list_t<SessionT>> snapshot_sessions(const std::shared_ptr<weak_session_list_t<SessionT>>& sessions)
{
    auto snapshot = std::atomic_load_explicit(&sessions, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<weak_session_list_t<SessionT>>();
}

template <typename SessionT>
void append_session(std::shared_ptr<weak_session_list_t<SessionT>>& sessions, const std::shared_ptr<SessionT>& session)
{
    for (;;)
    {
        auto current = snapshot_sessions<SessionT>(sessions);
        auto updated = std::make_shared<weak_session_list_t<SessionT>>();
        updated->reserve(current->size() + 1);
        for (const auto& weak_session : *current)
        {
            if (!weak_session.expired())
            {
                updated->push_back(weak_session);
            }
        }
        updated->push_back(session);
        if (std::atomic_compare_exchange_weak_explicit(&sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

template <typename SessionT>
std::shared_ptr<weak_session_list_t<SessionT>> detach_sessions(std::shared_ptr<weak_session_list_t<SessionT>>& sessions)
{
    auto empty = std::make_shared<weak_session_list_t<SessionT>>();
    for (;;)
    {
        auto current = snapshot_sessions<SessionT>(sessions);
        if (std::atomic_compare_exchange_weak_explicit(&sessions, &current, empty, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return current;
        }
    }
}

boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>> wait_for_tunnel_ready(boost::asio::io_context& io_context,
                                                                                                             std::shared_ptr<client_tunnel_pool> pool,
                                                                                                             const std::atomic<socks_client_state>& state)
{
    if (pool == nullptr)
    {
        LOG_ERROR("tunnel pool unavailable");
        co_return nullptr;
    }

    auto selected_tunnel = pool->select_tunnel();
    if (selected_tunnel != nullptr)
    {
        co_return selected_tunnel;
    }

    boost::asio::steady_timer tunnel_wait_timer(io_context);
    for (std::uint32_t attempt = 0; attempt < 6 && socks_client_running(state) && selected_tunnel == nullptr; ++attempt)
    {
        tunnel_wait_timer.expires_after(std::chrono::milliseconds(200));
        const auto [wait_ec] = co_await tunnel_wait_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        selected_tunnel = pool->select_tunnel();
    }

    co_return selected_tunnel;
}

void log_tunnel_selection(const std::uint32_t sid, const std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>& selected_tunnel)
{
    if (selected_tunnel == nullptr)
    {
        LOG_WARN("accepting local connection without active tunnel");
        LOG_INFO("client session {} running without tunnel", sid);
        return;
    }
    LOG_INFO("client session {} selected tunnel", sid);
}

boost::asio::awaitable<bool> start_local_session(boost::asio::ip::tcp::socket socket,
                                                 boost::asio::io_context& io_context,
                                                 const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                 const std::shared_ptr<router>& router,
                                                 std::shared_ptr<session_list_t>& sessions,
                                                 const config::socks_t& socks_config,
                                                 const config::timeout_t& timeout_config,
                                                 const config::queues_t& queue_config,
                                                 const std::shared_ptr<boost::asio::cancellation_signal>& stop_signal,
                                                 const socks_session::tcp_session_started_fn& on_tcp_session_started,
                                                 const socks_session::udp_session_started_fn& on_udp_session_started,
                                                 const std::atomic<socks_client_state>& state)
{
    if (tunnel_pool == nullptr)
    {
        LOG_ERROR("local session start failed tunnel pool unavailable");
        close_local_socket(socket);
        co_return false;
    }
    if (router == nullptr)
    {
        LOG_ERROR("local session start failed router unavailable");
        close_local_socket(socket);
        co_return false;
    }

    if (!socks_client_running(state))
    {
        close_local_socket(socket);
        co_return false;
    }

    set_no_delay_or_log(socket);

    auto selected_tunnel = co_await wait_for_tunnel_ready(io_context, tunnel_pool, state);
    if (!socks_client_running(state))
    {
        close_local_socket(socket);
        co_return false;
    }

    const std::uint32_t sid = tunnel_pool->next_session_id();
    log_tunnel_selection(sid, selected_tunnel);

    auto session =
        std::make_shared<socks_session>(
            std::move(socket),
            io_context,
            selected_tunnel,
            router,
            sid,
            socks_config,
            timeout_config,
            queue_config,
            stop_signal,
            on_tcp_session_started,
            on_udp_session_started);
    if (!socks_client_running(state))
    {
        session->stop();
        co_return false;
    }

    append_session(sessions, session);
    if (!socks_client_running(state))
    {
        session->stop();
        co_return false;
    }
    session->start();
    if (!socks_client_running(state))
    {
        session->stop();
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> run_accept_iteration(boost::asio::ip::tcp::acceptor& acceptor,
                                                  boost::asio::io_context& io_context,
                                                  const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                                  const std::shared_ptr<router>& router,
                                                  std::shared_ptr<session_list_t>& sessions,
                                                  const config::socks_t& socks_config,
                                                  const config::timeout_t& timeout_config,
                                                  const config::queues_t& queue_config,
                                                  const std::shared_ptr<boost::asio::cancellation_signal>& stop_signal,
                                                  const socks_session::tcp_session_started_fn& on_tcp_session_started,
                                                  const socks_session::udp_session_started_fn& on_udp_session_started,
                                                  const std::atomic<socks_client_state>& state)
{
    boost::asio::ip::tcp::socket socket(io_context);
    const auto accept_status = co_await accept_local_socket(acceptor, socket, io_context);
    if (accept_status == local_accept_status::kStop)
    {
        co_return false;
    }
    if (accept_status == local_accept_status::kRetry)
    {
        co_return true;
    }

    if (!socks_client_running(state))
    {
        close_local_socket(socket);
        co_return false;
    }

    if (!(co_await start_local_session(
            std::move(socket),
            io_context,
            tunnel_pool,
            router,
            sessions,
            socks_config,
            timeout_config,
            queue_config,
            stop_signal,
            on_tcp_session_started,
            on_udp_session_started,
            state)))
    {
        co_return false;
    }
    co_return true;
}

void close_acceptor_on_stop(boost::asio::ip::tcp::acceptor& acceptor)
{
    boost::system::error_code close_ec;
    close_ec = acceptor.close(close_ec);
    if (close_ec && close_ec != boost::asio::error::bad_descriptor)
    {
        LOG_ERROR("acceptor close failed {}", close_ec.message());
    }
}

template <typename SessionT>
std::vector<std::shared_ptr<SessionT>> collect_sessions_to_stop(const std::shared_ptr<weak_session_list_t<SessionT>>& sessions)
{
    std::vector<std::shared_ptr<SessionT>> sessions_to_stop;
    sessions_to_stop.reserve(sessions->size());
    for (const auto& weak_session : *sessions)
    {
        if (auto session = weak_session.lock())
        {
            sessions_to_stop.push_back(std::move(session));
        }
    }
    return sessions_to_stop;
}

template <typename SessionT>
void stop_sessions(const std::vector<std::shared_ptr<SessionT>>& sessions)
{
    for (const auto& session : sessions)
    {
        session->stop();
    }
}

void stop_local_session_producers(boost::asio::ip::tcp::acceptor& acceptor, std::shared_ptr<session_list_t>& sessions)
{
    close_acceptor_on_stop(acceptor);
    auto sessions_to_stop = collect_sessions_to_stop(detach_sessions<socks_session>(sessions));
    stop_sessions(sessions_to_stop);
}

void stop_local_session_consumers(std::shared_ptr<tcp_session_list_t>& tcp_sessions, std::shared_ptr<udp_session_list_t>& udp_sessions)
{
    auto tcp_sessions_to_stop = collect_sessions_to_stop(detach_sessions<tcp_socks_session>(tcp_sessions));
    auto udp_sessions_to_stop = collect_sessions_to_stop(detach_sessions<udp_socks_session>(udp_sessions));
    stop_sessions(tcp_sessions_to_stop);
    stop_sessions(udp_sessions_to_stop);
}

}    // namespace

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : configured_listen_port_(cfg.socks.port),
      listen_port_(cfg.socks.port),
      io_context_(pool.get_io_context()),
      acceptor_(io_context_),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, 0)),
      timeout_config_(cfg.timeout),
      queue_config_(cfg.queues),
      socks_config_(cfg.socks)
{
}

void socks_client::start()
{
    auto expected_state = socks_client_state::kStopped;
    if (!state_.compare_exchange_strong(expected_state, socks_client_state::kRunning, std::memory_order_acq_rel, std::memory_order_acquire))
    {
        LOG_WARN("socks client already started");
        return;
    }

    auto tunnel_pool = tunnel_pool_;
    if (tunnel_pool == nullptr)
    {
        LOG_ERROR("tunnel pool unavailable");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }

    auto router = router_;
    if (router == nullptr)
    {
        LOG_ERROR("router unavailable");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }

    if (!tunnel_pool->valid())
    {
        LOG_ERROR("invalid reality auth config");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }
    if (!router->load())
    {
        LOG_ERROR("failed to load router data");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }
    if (!socks_config_.enabled)
    {
        LOG_INFO("socks client disabled");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }

    const std::uint16_t configured_port = configured_listen_port_;
    std::uint16_t bound_port = 0;
    if (!prepare_local_listener(acceptor_, socks_config_.host, configured_port, bound_port))
    {
        LOG_ERROR("local socks5 setup failed");
        state_.store(socks_client_state::kStopped, std::memory_order_release);
        return;
    }
    listen_port_.store(bound_port, std::memory_order_release);
    LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));

    tunnel_pool->start();

    boost::asio::co_spawn(io_context_,
                          accept_local_loop_detached(shared_from_this()),
                          boost::asio::bind_cancellation_slot(stop_signal_->slot(), boost::asio::detached));
}

boost::asio::awaitable<void> socks_client::accept_local_loop_detached(std::shared_ptr<socks_client> self) { co_await self->accept_local_loop(); }

void socks_client::stop()
{
    LOG_INFO("client stopping closing resources");
    socks_client_request_stop(state_);
    stop_signal_->emit(boost::asio::cancellation_type::all);

    detail::dispatch_cleanup_or_run_inline(io_context_,
                                           [weak_self = weak_from_this()]()
                                           {
                                               if (const auto self = weak_self.lock())
                                               {
                                                   if (self->state_.load(std::memory_order_acquire) != socks_client_state::kStopping)
                                                   {
                                                       return;
                                                   }
                                                   stop_local_session_producers(self->acceptor_, self->sessions_);
                                                   stop_local_session_consumers(self->tcp_sessions_, self->udp_sessions_);
                                                   self->state_.store(socks_client_state::kStopped, std::memory_order_release);
                                               }
                                           });

    if (tunnel_pool_ != nullptr)
    {
        tunnel_pool_->stop();
    }
}

boost::asio::awaitable<void> socks_client::accept_local_loop()
{
    if (!socks_client_running(state_))
    {
        co_return;
    }

    auto tunnel_pool = tunnel_pool_;
    if (tunnel_pool == nullptr)
    {
        LOG_ERROR("accept loop tunnel pool unavailable");
        socks_client_request_stop(state_);
        co_return;
    }
    auto router = router_;
    if (router == nullptr)
    {
        LOG_ERROR("accept loop router unavailable");
        socks_client_request_stop(state_);
        co_return;
    }

    if (!acceptor_.is_open())
    {
        const std::uint16_t configured_port = configured_listen_port_;
        std::uint16_t bound_port = 0;
        if (!prepare_local_listener(acceptor_, socks_config_.host, configured_port, bound_port))
        {
            socks_client_request_stop(state_);
            co_return;
        }
        if (!socks_client_running(state_))
        {
            close_local_acceptor_on_setup_failure(acceptor_);
            co_return;
        }
        listen_port_.store(bound_port, std::memory_order_release);
        LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));
    }
    const auto weak_self = weak_from_this();
    const socks_session::tcp_session_started_fn on_tcp_session_started =
        [weak_self](const std::shared_ptr<tcp_socks_session>& session)
    {
        if (const auto self = weak_self.lock())
        {
            if (!socks_client_running(self->state_))
            {
                session->stop();
                return false;
            }
            append_session(self->tcp_sessions_, session);
            if (!socks_client_running(self->state_))
            {
                session->stop();
                return false;
            }
            return true;
        }
        session->stop();
        return false;
    };
    const socks_session::udp_session_started_fn on_udp_session_started =
        [weak_self](const std::shared_ptr<udp_socks_session>& session)
    {
        if (const auto self = weak_self.lock())
        {
            if (!socks_client_running(self->state_))
            {
                session->stop();
                return false;
            }
            append_session(self->udp_sessions_, session);
            if (!socks_client_running(self->state_))
            {
                session->stop();
                return false;
            }
            return true;
        }
        session->stop();
        return false;
    };
    while (socks_client_running(state_))
    {
        if (!(co_await run_accept_iteration(
                acceptor_,
                io_context_,
                tunnel_pool,
                router,
                sessions_,
                socks_config_,
                timeout_config_,
                queue_config_,
                std::shared_ptr<boost::asio::cancellation_signal>{},
                on_tcp_session_started,
                on_udp_session_started,
                state_)))
        {
            break;
        }
    }
    LOG_INFO("accept local loop exited");
}

}    // namespace mux
