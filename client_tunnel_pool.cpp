#include <atomic>
#include <cctype>
#include <chrono>
#include <iterator>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <optional>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "log.h"
#include "config.h"
#include "net_utils.h"
#include "timeout_io.h"
#include "context_pool.h"
#include "reality/types.h"
#include "mux_connection.h"
#include "client_tunnel_pool.h"
#include "connection_context.h"
#include "tls/handshake_message.h"
#include "reality/session/session.h"
#include "reality/handshake/fingerprint.h"
#include "reality/session/lightweight_client.h"
#include "reality/handshake/client_handshaker.h"

namespace mux
{

namespace
{

constexpr std::uint32_t kReconnectBaseDelayMs = 200;
constexpr std::uint32_t kReconnectMaxDelayMs = 10000;
constexpr std::uint32_t kReconnectStableDurationMs = 30000;
constexpr std::chrono::milliseconds kTunnelPollInterval(200);
constexpr std::uint16_t kFallbackTlsPort = 443;
constexpr std::uint32_t kFallbackIoTimeoutSec = 2;

std::uint32_t clamp_fallback_timeout(const std::uint32_t configured_timeout_sec)
{
    if (configured_timeout_sec == 0)
    {
        return kFallbackIoTimeoutSec;
    }
    return std::min(configured_timeout_sec, kFallbackIoTimeoutSec);
}

std::string normalize_fingerprint_name(const std::string& name)
{
    std::string normalized_name;
    normalized_name.reserve(name.size());
    for (const char ch : name)
    {
        if (ch == '-' || ch == ' ')
        {
            normalized_name.push_back('_');
            continue;
        }
        normalized_name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized_name;
}

std::optional<reality::fingerprint_type> parse_fingerprint_type(const std::string& name)
{
    const auto normalized_name = normalize_fingerprint_name(name);
    if (normalized_name.empty() || normalized_name == "random")
    {
        return std::nullopt;
    }

    struct fp_entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const fp_entry kFps[] = {
        {.name = "chrome", .type = reality::fingerprint_type::kChrome120},
        {.name = "chrome_120", .type = reality::fingerprint_type::kChrome120},
        {.name = "chrome_mlkem", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_mlkem768", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_hybrid", .type = reality::fingerprint_type::kChrome120Mlkem768},
        {.name = "firefox", .type = reality::fingerprint_type::kFirefox120},
        {.name = "firefox_120", .type = reality::fingerprint_type::kFirefox120},
        {.name = "ios", .type = reality::fingerprint_type::kIOS14},
        {.name = "ios_14", .type = reality::fingerprint_type::kIOS14},
        {.name = "android", .type = reality::fingerprint_type::kAndroid11OkHttp},
        {.name = "android_11_okhttp", .type = reality::fingerprint_type::kAndroid11OkHttp},
    };

    for (const auto& entry : kFps)
    {
        if (normalized_name == entry.name)
        {
            return entry.type;
        }
    }
    return kFps[0].type;
}

void prepare_socket_for_connect(boost::asio::ip::tcp::socket& socket,
                                const boost::asio::ip::tcp::endpoint& endpoint,
                                const std::uint32_t mark,
                                boost::system::error_code& ec)
{
    if (socket.is_open())
    {
        ec = socket.close(ec);
    }
    ec = socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        return;
    }
    if (mark != 0)
    {
        net::set_socket_mark(socket.native_handle(), mark, ec);
        if (ec)
        {
            LOG_WARN("set mark failed target {}:{} error {}", endpoint.address().to_string(), endpoint.port(), ec.message());
            boost::system::error_code close_ec;
            close_ec = socket.close(close_ec);
            (void)close_ec;
            return;
        }
    }
}

}    // namespace

client_tunnel_pool::connect_options client_tunnel_pool::build_connect_options(const config& cfg)
{
    connect_options options;
    options.sni = cfg.reality.sni;
    options.remote_host = cfg.outbound.host;
    options.remote_port = std::to_string(cfg.outbound.port);
    options.max_handshake_records = cfg.limits.max_handshake_records;
    options.tunnel_connections = cfg.limits.max_connections;
    options.connect_mark = cfg.tproxy.enabled ? cfg.tproxy.mark : 0U;
    boost::algorithm::unhex(cfg.reality.public_key, std::back_inserter(options.server_pub_key));
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(options.short_id_bytes));
    options.fingerprint_type = parse_fingerprint_type(cfg.reality.fingerprint);
    return options;
}

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg)
    : cfg_(cfg), pool_(pool), options_(build_connect_options(cfg)), tunnel_pool_(options_.tunnel_connections)
{
}

void client_tunnel_pool::start()
{
    LOG_INFO("client pool starting target {} port {} with {} connections", options_.remote_host, options_.remote_port, options_.tunnel_connections);

    for (std::uint32_t i = 0; i < options_.tunnel_connections; ++i)
    {
        auto& worker = pool_.get_io_worker();
        worker.group.spawn([self = shared_from_this(), i, worker = &worker]() -> boost::asio::awaitable<void>
                           { co_await self->connect_remote_loop(i, *worker); });
    }
}

void client_tunnel_pool::stop()
{
    std::call_once(stop_once_,
                   [this]()
                   {
                       std::vector<std::shared_ptr<mux_connection>> tunnels;
                       {
                           const std::scoped_lock lock(tunnel_mutex_);
                           tunnels.reserve(tunnel_pool_.size());
                           for (auto& tunnel : tunnel_pool_)
                           {
                               if (tunnel != nullptr)
                               {
                                   tunnels.push_back(tunnel);
                                   tunnel.reset();
                               }
                           }
                       }

                       for (const auto& tunnel : tunnels)
                       {
                           if (tunnel == nullptr)
                           {
                               continue;
                           }
                           if (tunnel != nullptr)
                           {
                               tunnel->stop();
                           }
                       }
                   });
}

std::shared_ptr<mux_connection> client_tunnel_pool::select_tunnel()
{
    const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
    if (tunnel_pool_.empty())
    {
        return nullptr;
    }

    const auto pool_size = tunnel_pool_.size();
    const auto start_index = static_cast<std::size_t>(next_tunnel_index_.fetch_add(1, std::memory_order_relaxed) % pool_size);
    for (std::size_t i = 0; i < pool_size; ++i)
    {
        const auto slot = (start_index + i) % pool_size;
        const auto tunnel = tunnel_pool_[slot];
        if (tunnel == nullptr)
        {
            continue;
        }
        if (tunnel == nullptr || !tunnel->is_active())
        {
            continue;
        }
        return tunnel;
    }

    return nullptr;
}

boost::asio::awaitable<std::shared_ptr<mux_connection>> client_tunnel_pool::wait_for_tunnel(const std::uint32_t timeout_sec,
                                                                                            boost::system::error_code& ec)
{
    ec.clear();
    const auto start_ms = timeout_io::now_ms();
    const auto timeout_ms = timeout_io::timeout_seconds_to_milliseconds(timeout_sec);
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer retry_timer(executor);
    for (;;)
    {
        const auto tunnel = select_tunnel();
        if (tunnel != nullptr)
        {
            co_return tunnel;
        }

        if (timeout_ms != 0 && timeout_io::now_ms() - start_ms >= timeout_ms)
        {
            ec = boost::asio::error::timed_out;
            co_return nullptr;
        }

        retry_timer.expires_after(kTunnelPollInterval);
        const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            ec = wait_ec;
            co_return nullptr;
        }
    }
}

std::uint32_t client_tunnel_pool::next_session_id() { return next_session_id_.fetch_add(1, std::memory_order_relaxed); }

std::shared_ptr<mux_connection> client_tunnel_pool::build_tunnel(boost::asio::ip::tcp::socket socket,
                                                                 io_worker& worker,
                                                                 const std::uint32_t cid,
                                                                 const handshake_result& handshake_ret,
                                                                 const std::string& trace_id) const
{
    boost::system::error_code ec;
    auto session = reality::build_reality_session(handshake_ret, ec);
    if (ec)
    {
        LOG_ERROR("build client reality session failed {}", ec.message());
        return nullptr;
    }
    return std::make_shared<mux_connection>(std::move(socket), worker, std::move(session), cfg_, cid, trace_id);
}

boost::asio::awaitable<void> client_tunnel_pool::run_real_certificate_fallback(boost::asio::ip::tcp::socket& socket,
                                                                               const handshake_result& handshake_ret,
                                                                               const connection_context& ctx) const
{
    connection_context fallback_ctx = ctx;
    fallback_ctx.sni(options_.sni);
    fallback_ctx.set_target(options_.sni, kFallbackTlsPort);

    if (!handshake_ret.negotiated.negotiated_alpn.empty() && handshake_ret.negotiated.negotiated_alpn != "http/1.1")
    {
        LOG_CTX_INFO(fallback_ctx,
                     "{} stage skip_request host {} negotiated_alpn {}",
                     log_event::kFallback,
                     options_.sni,
                     handshake_ret.negotiated.negotiated_alpn);
        co_return;
    }

    boost::system::error_code ec;
    auto session = reality::build_reality_session(handshake_ret, ec);
    if (ec)
    {
        LOG_CTX_WARN(fallback_ctx, "{} stage build_session error {}", log_event::kFallback, ec.message());
        co_return;
    }

    reality::lightweight_http_visit_options visit_options;
    visit_options.host = options_.sni;
    visit_options.write_timeout_sec = clamp_fallback_timeout(cfg_.timeout.write);
    visit_options.read_timeout_sec = clamp_fallback_timeout(cfg_.timeout.read);

    const auto visit_result = co_await reality::run_lightweight_http_visit(socket, std::move(session), visit_options, ec);
    if (ec)
    {
        LOG_CTX_WARN(fallback_ctx, "{} stage {} error {}", log_event::kFallback, visit_result.error_stage, ec.message());
        co_return;
    }

    fallback_ctx.add_tx_bytes(visit_result.tx_plain_bytes);
    fallback_ctx.add_rx_bytes(visit_result.rx_plain_bytes);

    if (visit_result.saw_application_data)
    {
        LOG_CTX_INFO(fallback_ctx,
                     "{} stage lightweight_visit_complete status \"{}\" tx_plain {}B rx_plain {}B header_complete {} alert {}",
                     log_event::kFallback,
                     visit_result.status_line.empty() ? "unknown" : visit_result.status_line,
                     fallback_ctx.tx_bytes(),
                     fallback_ctx.rx_bytes(),
                     visit_result.header_complete,
                     visit_result.saw_alert);
    }
    else
    {
        LOG_CTX_WARN(fallback_ctx,
                     "{} stage lightweight_visit_no_response tx_plain {}B alert {}",
                     log_event::kFallback,
                     fallback_ctx.tx_bytes(),
                     visit_result.saw_alert);
    }
    co_return;
}

boost::asio::awaitable<client_tunnel_pool::handshake_result> client_tunnel_pool::perform_reality_handshake_with_timeout(
    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const connection_context& ctx, boost::system::error_code& ec) const
{
    ec.clear();
    if (!socket)
    {
        LOG_CTX_ERROR(ctx, "{} stage handshake target {}:{} error invalid_socket", log_event::kHandshake, options_.remote_host, options_.remote_port);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        co_return handshake_result{};
    }
    const reality::client_handshaker handshaker(
        cfg_, options_.sni, options_.server_pub_key, options_.short_id_bytes, options_.fingerprint_type, options_.max_handshake_records);
    auto handshake_res = co_await handshaker.run(*socket, ctx, ec);
    if (ec)
    {
        LOG_CTX_ERROR(
            ctx, "{} stage handshake target {}:{} error {}", log_event::kHandshake, options_.remote_host, options_.remote_port, ec.message());
    }
    co_return handshake_res;
}

boost::asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index, io_worker& worker)
{
    auto& io_context = worker.io_context;
    boost::system::error_code ec;
    static thread_local std::mt19937 reconnect_gen(std::random_device{}());
    std::uint32_t retry_delay_ms = kReconnectBaseDelayMs;
    const auto wait_before_retry = [&](const connection_context& ctx, const char* stage) -> boost::asio::awaitable<bool>
    {
        std::uniform_int_distribution<std::uint32_t> jitter_dist(0, retry_delay_ms / 4);
        const auto sleep_ms = retry_delay_ms + jitter_dist(reconnect_gen);
        LOG_CTX_WARN(ctx, "{} stage {} retry_backoff {}ms", log_event::kConnInit, stage, sleep_ms);

        boost::asio::steady_timer retry_timer(io_context);
        retry_timer.expires_after(std::chrono::milliseconds(sleep_ms));
        const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec == boost::asio::error::operation_aborted)
        {
            co_return false;
        }
        if (wait_ec)
        {
            LOG_CTX_WARN(ctx, "{} stage {} retry_backoff_wait_failed {}", log_event::kConnInit, stage, wait_ec.message());
        }
        retry_delay_ms = std::min(retry_delay_ms * 2, kReconnectMaxDelayMs);
        co_return true;
    };

    while (true)
    {
        const std::uint32_t cid = next_conn_id_.fetch_add(1, std::memory_order_relaxed);
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(cid);
        LOG_CTX_INFO(ctx,
                     "{} init conn {}/{} to {} {}",
                     log_event::kConnInit,
                     index + 1,
                     options_.tunnel_connections,
                     options_.remote_host,
                     options_.remote_port);
        // step 1 create socket
        const auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
        // step 2 connect remote
        co_await tcp_connect_remote(*socket, ctx, ec);
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }
            LOG_CTX_ERROR(
                ctx, "{} stage connect target {}:{} error {}", log_event::kConnInit, options_.remote_host, options_.remote_port, ec.message());
            if (!(co_await wait_before_retry(ctx, "connect")))
            {
                break;
            }
            continue;
        }
        // step 3 handshake
        auto handshake_ret = co_await perform_reality_handshake_with_timeout(socket, ctx, ec);
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }
            LOG_CTX_ERROR(ctx, "{} handshake error {}", log_event::kHandshake, ec.message());
            if (!(co_await wait_before_retry(ctx, "handshake")))
            {
                break;
            }
            continue;
        }

        LOG_CTX_INFO(ctx,
                     "{} handshake success cipher 0x{:04x} key share group 0x{:04x} {}",
                     log_event::kHandshake,
                     handshake_ret.negotiated.cipher_suite,
                     handshake_ret.negotiated.key_share_group,
                     ::tls::named_group_name(handshake_ret.negotiated.key_share_group));
        if (handshake_ret.auth_mode == handshake_auth_mode::kRealCertificateFallback)
        {
            LOG_CTX_WARN(ctx, "{} received real certificate fallback run lightweight visit", log_event::kHandshake);
            co_await run_real_certificate_fallback(*socket, handshake_ret, ctx);
            boost::system::error_code close_ec;
            close_ec = socket->close(close_ec);
            if (close_ec)
            {
                LOG_CTX_WARN(ctx, "close failed {}", close_ec.message());
            }
            if (!(co_await wait_before_retry(ctx, "real_certificate_fallback")))
            {
                break;
            }
            continue;
        }
        // step 4 build tunnel
        auto tunnel = build_tunnel(std::move(*socket), worker, cid, handshake_ret, ctx.trace_id());
        if (tunnel == nullptr)
        {
            LOG_CTX_ERROR(ctx, "{} build tunnel failed", log_event::kHandshake);
            if (!(co_await wait_before_retry(ctx, "build_tunnel")))
            {
                break;
            }
            continue;
        }
        // step 5 tunnel run
        tunnel->start();
        const auto tunnel_start_ms = timeout_io::now_ms();

        {
            const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
            if (index < tunnel_pool_.size())
            {
                tunnel_pool_[index] = tunnel;
            }
        }

        bool stop_loop = false;
        while (true)
        {
            boost::asio::steady_timer hold_timer(io_context);
            hold_timer.expires_after(std::chrono::seconds(1));
            const auto [wait_ec] = co_await hold_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (wait_ec)
            {
                if (wait_ec == boost::asio::error::operation_aborted)
                {
                    stop_loop = true;
                }
                break;
            }

            if (tunnel == nullptr || !tunnel->is_active())
            {
                break;
            }
        }

        {
            const std::scoped_lock<std::mutex> lock(tunnel_mutex_);
            if (index < tunnel_pool_.size() && tunnel_pool_[index] == tunnel)
            {
                tunnel_pool_[index].reset();
            }
        }

        if (stop_loop)
        {
            break;
        }

        const auto tunnel_alive_ms = timeout_io::now_ms() - tunnel_start_ms;
        if (tunnel_alive_ms >= kReconnectStableDurationMs)
        {
            retry_delay_ms = kReconnectBaseDelayMs;
            continue;
        }
        LOG_CTX_WARN(ctx, "{} stage tunnel_closed short_lived {}ms backoff before retry", log_event::kConnInit, tunnel_alive_ms);
        if (!(co_await wait_before_retry(ctx, "tunnel_closed")))
        {
            break;
        }
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

boost::asio::awaitable<void> client_tunnel_pool::tcp_connect_remote(boost::asio::ip::tcp::socket& socket,
                                                                    const connection_context& ctx,
                                                                    boost::system::error_code& ec) const
{
    const auto timeout_sec = cfg_.timeout.connect;
    boost::asio::ip::tcp::resolver resolver(socket.get_executor());
    const auto resolve_endpoints =
        co_await timeout_io::wait_resolve_with_timeout(resolver, options_.remote_host, options_.remote_port, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }

    for (const auto& entry : resolve_endpoints)
    {
        const auto endpoint = entry.endpoint();
        prepare_socket_for_connect(socket, endpoint, options_.connect_mark, ec);
        if (ec)
        {
            continue;
        }
        co_await timeout_io::wait_connect_with_timeout(socket, endpoint, timeout_sec, ec);
        if (!ec)
        {
            co_return;
        }
    }

    if (ec == boost::asio::error::timed_out)
    {
        LOG_CTX_ERROR(
            ctx, "{} stage connect target {}:{} timeout {}s", log_event::kConnInit, options_.remote_host, options_.remote_port, timeout_sec);
    }
    else
    {
        LOG_CTX_ERROR(ctx, "{} stage connect target {}:{} error {}", log_event::kConnInit, options_.remote_host, options_.remote_port, ec.message());
    }
    co_return;
}

}    // namespace mux
