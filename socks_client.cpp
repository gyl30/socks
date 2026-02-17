#include <chrono>
#include <memory>
#include <thread>
#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "router.h"
#include "stop_dispatch.h"
#include "socks_client.h"
#include "socks_session.h"

namespace mux
{

namespace
{

using session_list_t = std::vector<std::weak_ptr<socks_session>>;
constexpr std::uint32_t kEphemeralBindRetryAttempts = 120;
const auto kEphemeralBindRetryDelay = std::chrono::milliseconds(25);

void close_local_socket(asio::ip::tcp::socket& socket)
{
    std::error_code close_ec;
    close_ec = socket.shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
    close_ec = socket.close(close_ec);
}

void close_local_acceptor_on_setup_failure(asio::ip::tcp::acceptor& acceptor)
{
    std::error_code close_ec;
    close_ec = acceptor.close(close_ec);
}

bool setup_local_acceptor(asio::ip::tcp::acceptor& acceptor,
                          const asio::ip::address& listen_addr,
                          const std::uint16_t port,
                          std::uint16_t& bound_port,
                          std::error_code& ec)
{
    const asio::ip::tcp::endpoint ep{listen_addr, port};
    ec = acceptor.open(ep.protocol(), ec);
    if (ec)
    {
        return false;
    }
    ec = acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
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
    ec = acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        close_local_acceptor_on_setup_failure(acceptor);
    }
    return !ec;
}

bool prepare_local_listener(asio::ip::tcp::acceptor& acceptor, const std::string& host, const std::uint16_t port, std::uint16_t& bound_port)
{
    std::error_code addr_ec;
    const auto listen_addr = asio::ip::make_address(host, addr_ec);
    if (addr_ec)
    {
        LOG_ERROR("local acceptor parse address failed {}", addr_ec.message());
        return false;
    }

    const bool retry_ephemeral_bind = (port == 0);
    const std::uint32_t max_attempts = retry_ephemeral_bind ? kEphemeralBindRetryAttempts : 1;

    std::error_code setup_ec;
    for (std::uint32_t attempt = 0; attempt < max_attempts; ++attempt)
    {
        if (setup_local_acceptor(acceptor, listen_addr, port, bound_port, setup_ec))
        {
            return true;
        }

        const bool can_retry = retry_ephemeral_bind && setup_ec == asio::error::address_in_use && (attempt + 1) < max_attempts;
        if (!can_retry)
        {
            break;
        }
        std::this_thread::sleep_for(kEphemeralBindRetryDelay);
    }

    LOG_ERROR("local acceptor setup failed {}", setup_ec.message());
    return false;
}

void log_accept_error(const std::error_code& ec)
{
    LOG_ERROR("local accept failed {}", ec.message());
}

asio::awaitable<void> wait_retry_delay(asio::io_context& io_context)
{
    asio::steady_timer retry_timer(io_context);
    retry_timer.expires_after(std::chrono::seconds(1));
    (void)co_await retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
}

enum class local_accept_status
{
    kAccepted,
    kRetry,
    kStop,
};

asio::awaitable<local_accept_status> accept_local_socket(asio::ip::tcp::acceptor& acceptor,
                                                         asio::ip::tcp::socket& socket,
                                                         asio::io_context& io_context)
{
    const auto [accept_ec] = co_await acceptor.async_accept(socket, asio::as_tuple(asio::use_awaitable));
    if (!accept_ec)
    {
        co_return local_accept_status::kAccepted;
    }
    if (accept_ec == asio::error::operation_aborted)
    {
        co_return local_accept_status::kStop;
    }
    log_accept_error(accept_ec);
    co_await wait_retry_delay(io_context);
    co_return local_accept_status::kRetry;
}

void set_no_delay_or_log(asio::ip::tcp::socket& socket)
{
    std::error_code ec;
    ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec)
    {
        LOG_WARN("failed to set no delay on local socket {}", ec.message());
    }
}

std::shared_ptr<session_list_t> snapshot_sessions(const std::shared_ptr<session_list_t>& sessions)
{
    auto snapshot = std::atomic_load_explicit(&sessions, std::memory_order_acquire);
    if (snapshot != nullptr)
    {
        return snapshot;
    }
    return std::make_shared<session_list_t>();
}

void append_session(std::shared_ptr<session_list_t>& sessions, const std::shared_ptr<socks_session>& session)
{
    for (;;)
    {
        auto current = snapshot_sessions(sessions);
        auto updated = std::make_shared<session_list_t>();
        updated->reserve(current->size() + 1);
        for (const auto& weak_session : *current)
        {
            if (!weak_session.expired())
            {
                updated->push_back(weak_session);
            }
        }
        updated->push_back(session);
        if (std::atomic_compare_exchange_weak_explicit(
                &sessions, &current, updated, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return;
        }
    }
}

std::shared_ptr<session_list_t> detach_sessions(std::shared_ptr<session_list_t>& sessions)
{
    auto empty = std::make_shared<session_list_t>();
    for (;;)
    {
        auto current = snapshot_sessions(sessions);
        if (std::atomic_compare_exchange_weak_explicit(
                &sessions, &current, empty, std::memory_order_acq_rel, std::memory_order_acquire))
        {
            return current;
        }
    }
}

asio::awaitable<std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> wait_for_tunnel_ready(asio::io_context& io_context,
                                                                                                std::shared_ptr<client_tunnel_pool> pool,
                                                                                                const std::atomic<bool>& stop)
{
    auto selected_tunnel = pool->select_tunnel();
    if (selected_tunnel != nullptr)
    {
        co_return selected_tunnel;
    }

    asio::steady_timer tunnel_wait_timer(io_context);
    for (std::uint32_t attempt = 0; attempt < 6 && !stop.load(std::memory_order_acquire) && selected_tunnel == nullptr; ++attempt)
    {
        tunnel_wait_timer.expires_after(std::chrono::milliseconds(200));
        const auto [wait_ec] = co_await tunnel_wait_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        selected_tunnel = pool->select_tunnel();
    }

    co_return selected_tunnel;
}

void log_tunnel_selection(const std::uint32_t sid, const std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>& selected_tunnel)
{
    if (selected_tunnel == nullptr)
    {
        LOG_WARN("accepting local connection without active tunnel");
        LOG_INFO("client session {} running without tunnel", sid);
        return;
    }
    LOG_INFO("client session {} selected tunnel", sid);
}

asio::awaitable<bool> start_local_session(asio::ip::tcp::socket socket,
                                          asio::io_context& io_context,
                                          const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                          const std::shared_ptr<router>& router,
                                          std::shared_ptr<session_list_t>& sessions,
                                          const config::socks_t& socks_config,
                                          const config::timeout_t& timeout_config,
                                          const std::atomic<bool>& stop)
{
    if (stop.load(std::memory_order_acquire))
    {
        close_local_socket(socket);
        co_return false;
    }

    set_no_delay_or_log(socket);

    auto selected_tunnel = co_await wait_for_tunnel_ready(io_context, tunnel_pool, stop);
    if (stop.load(std::memory_order_acquire))
    {
        close_local_socket(socket);
        co_return false;
    }

    const std::uint32_t sid = tunnel_pool->next_session_id();
    log_tunnel_selection(sid, selected_tunnel);

    auto session = std::make_shared<socks_session>(std::move(socket), io_context, selected_tunnel, router, sid, socks_config, timeout_config);
    if (stop.load(std::memory_order_acquire))
    {
        session->stop();
        co_return false;
    }

    append_session(sessions, session);
    session->start();
    co_return true;
}

asio::awaitable<bool> run_accept_iteration(asio::ip::tcp::acceptor& acceptor,
                                           asio::io_context& io_context,
                                           const std::shared_ptr<client_tunnel_pool>& tunnel_pool,
                                           const std::shared_ptr<router>& router,
                                           std::shared_ptr<session_list_t>& sessions,
                                           const config::socks_t& socks_config,
                                           const config::timeout_t& timeout_config,
                                           const std::atomic<bool>& stop)
{
    asio::ip::tcp::socket socket(io_context);
    const auto accept_status = co_await accept_local_socket(acceptor, socket, io_context);
    if (accept_status == local_accept_status::kStop)
    {
        co_return false;
    }
    if (accept_status == local_accept_status::kRetry)
    {
        co_return true;
    }

    if (stop.load(std::memory_order_acquire))
    {
        close_local_socket(socket);
        co_return false;
    }

    if (!(co_await start_local_session(std::move(socket), io_context, tunnel_pool, router, sessions, socks_config, timeout_config, stop)))
    {
        co_return false;
    }
    co_return true;
}

void close_acceptor_on_stop(asio::ip::tcp::acceptor& acceptor)
{
    std::error_code close_ec;
    close_ec = acceptor.close(close_ec);
    if (close_ec && close_ec != asio::error::bad_descriptor)
    {
        LOG_ERROR("acceptor close failed {}", close_ec.message());
    }
}

std::vector<std::shared_ptr<socks_session>> collect_sessions_to_stop(const std::shared_ptr<session_list_t>& sessions)
{
    std::vector<std::shared_ptr<socks_session>> sessions_to_stop;
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

void stop_sessions(const std::vector<std::shared_ptr<socks_session>>& sessions)
{
    for (const auto& session : sessions)
    {
        session->stop();
    }
}

void stop_local_resources(asio::ip::tcp::acceptor& acceptor, std::shared_ptr<session_list_t>& sessions)
{
    close_acceptor_on_stop(acceptor);
    auto sessions_to_stop = collect_sessions_to_stop(detach_sessions(sessions));
    stop_sessions(sessions_to_stop);
}

}    // namespace

socks_client::socks_client(io_context_pool& pool, const config& cfg)
    : listen_port_(cfg.socks.port),
      io_context_(pool.get_io_context()),
      acceptor_(io_context_),
      router_(std::make_shared<mux::router>()),
      tunnel_pool_(std::make_shared<client_tunnel_pool>(pool, cfg, 0)),
      timeout_config_(cfg.timeout),
      socks_config_(cfg.socks)
{
}

void socks_client::start()
{
    bool expected = false;
    if (!started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        LOG_WARN("socks client already started");
        return;
    }
    stop_.store(false, std::memory_order_release);

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
    if (!socks_config_.enabled)
    {
        LOG_INFO("socks client disabled");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }

    const std::uint16_t configured_port = listen_port_.load(std::memory_order_acquire);
    std::uint16_t bound_port = 0;
    if (!prepare_local_listener(acceptor_, socks_config_.host, configured_port, bound_port))
    {
        LOG_ERROR("local socks5 setup failed");
        stop_.store(true, std::memory_order_release);
        started_.store(false, std::memory_order_release);
        return;
    }
    listen_port_.store(bound_port, std::memory_order_release);
    LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));

    tunnel_pool_->start();

    asio::co_spawn(io_context_, accept_local_loop_detached(shared_from_this()), asio::detached);
}

asio::awaitable<void> socks_client::accept_local_loop_detached(std::shared_ptr<socks_client> self)
{
    co_await self->accept_local_loop();
}

void socks_client::stop()
{
    LOG_INFO("client stopping closing resources");
    stop_.store(true, std::memory_order_release);
    started_.store(false, std::memory_order_release);

    detail::dispatch_cleanup_or_run_inline(
        io_context_,
        [weak_self = weak_from_this()]()
        {
            if (const auto self = weak_self.lock())
            {
                stop_local_resources(self->acceptor_, self->sessions_);
            }
        });

    tunnel_pool_->stop();
}

asio::awaitable<void> socks_client::accept_local_loop()
{
    if (stop_.load(std::memory_order_acquire))
    {
        started_.store(false, std::memory_order_release);
        co_return;
    }

    if (!acceptor_.is_open())
    {
        const std::uint16_t configured_port = listen_port_.load(std::memory_order_acquire);
        std::uint16_t bound_port = 0;
        if (!prepare_local_listener(acceptor_, socks_config_.host, configured_port, bound_port))
        {
            stop_.store(true, std::memory_order_release);
            started_.store(false, std::memory_order_release);
            co_return;
        }
        if (stop_.load(std::memory_order_acquire))
        {
            close_local_acceptor_on_setup_failure(acceptor_);
            started_.store(false, std::memory_order_release);
            co_return;
        }
        listen_port_.store(bound_port, std::memory_order_release);
        LOG_INFO("local socks5 listening on {}:{}", socks_config_.host, listen_port_.load(std::memory_order_acquire));
    }
    while (!stop_.load(std::memory_order_acquire))
    {
        if (!(co_await run_accept_iteration(
                  acceptor_, io_context_, tunnel_pool_, router_, sessions_, socks_config_, timeout_config_, stop_)))
        {
            break;
        }
    }
    started_.store(false, std::memory_order_release);
    LOG_INFO("accept local loop exited");
}

}    // namespace mux
