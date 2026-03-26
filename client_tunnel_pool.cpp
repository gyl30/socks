#include <cctype>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <expected>
#include <optional>
#include <limits>
#include <algorithm>
#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/errc.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>

extern "C"
{
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
}

#include "log.h"
#include "config.h"
#include "constants.h"
#include "net_utils.h"
#include "mux_tunnel.h"
#include "timeout_io.h"
#include "tls/crypto_util.h"
#include "connection_context.h"
#include "context_pool.h"
#include "reality/types.h"
#include "tls/ch_parser.h"
#include "client_tunnel_pool.h"
#include "tls/cipher_suite.h"
#include "tls/handshake_message.h"
#include "tls/record_layer.h"
#include "tls/record_validation.h"
#include "reality/handshake/auth.h"
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

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg)
    : sni_(cfg.reality.sni),
      remote_host_(cfg.outbound.host),
      remote_port_(std::to_string(cfg.outbound.port)),
      cfg_(cfg),
      pool_(pool),
      max_handshake_records_(cfg.limits.max_handshake_records),
      tunnel_pool_(resolve_tunnel_connections(cfg.limits))
{
    boost::algorithm::unhex(cfg.reality.public_key, std::back_inserter(server_pub_key_));
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(short_id_bytes_));
    fingerprint_type_ = parse_fingerprint_type(cfg.reality.fingerprint);
}

void client_tunnel_pool::start()
{
    const auto tunnel_connections = resolve_tunnel_connections(cfg_.limits);
    LOG_INFO("client pool starting target {} port {} with {} connections", remote_host_, remote_port_, tunnel_connections);

    auto self = shared_from_this();

    for (std::uint32_t i = 0; i < tunnel_connections; ++i)
    {
        boost::asio::io_context& io = pool_.get_io_context();
        auto& group = pool_.get_task_group(io);
        boost::asio::co_spawn(
            io,
            [this, i, io = &io, self]() -> boost::asio::awaitable<void> { co_await connect_remote_loop(i, *io); },
            group.adapt(boost::asio::detached));
    }
}

void client_tunnel_pool::stop()
{
    std::call_once(stop_once_,
                   [this]()
                   {
                       std::vector<std::shared_ptr<mux_tunnel_impl>> tunnels;
                       {
                           std::lock_guard<std::mutex> lock(tunnel_mutex_);
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
                           const auto connection = tunnel->connection();
                           if (connection != nullptr)
                           {
                               connection->stop();
                           }
                       }
                   });
}

std::shared_ptr<mux_tunnel_impl> client_tunnel_pool::select_tunnel()
{
    std::lock_guard<std::mutex> lock(tunnel_mutex_);
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
        const auto connection = tunnel->connection();
        if (connection == nullptr || !connection->is_active())
        {
            continue;
        }
        return tunnel;
    }

    return nullptr;
}

boost::asio::awaitable<std::shared_ptr<mux_tunnel_impl>> client_tunnel_pool::wait_for_tunnel(boost::asio::io_context& io_context,
                                                                                             boost::system::error_code& ec)
{
    ec.clear();
    const auto start_ms = timeout_io::now_ms();
    const auto connect_timeout_ms = timeout_io::timeout_seconds_to_milliseconds(cfg_.timeout.connect);
    boost::asio::steady_timer retry_timer(io_context);
    for (;;)
    {
        const auto tunnel = select_tunnel();
        if (tunnel != nullptr)
        {
            co_return tunnel;
        }

        if (connect_timeout_ms != 0 && timeout_io::now_ms() - start_ms >= connect_timeout_ms)
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

std::shared_ptr<mux_tunnel_impl> client_tunnel_pool::build_tunnel(boost::asio::ip::tcp::socket socket,
                                                                  boost::asio::io_context& io_context,
                                                                  const std::uint32_t cid,
                                                                  const handshake_result& handshake_ret,
                                                                  const std::string& trace_id) const
{
    boost::system::error_code ec;
    auto session = reality::reality_session::from_client_handshake(handshake_ret, ec);
    if (ec)
    {
        LOG_ERROR("build client reality session failed {}", ec.message());
        return nullptr;
    }
    return std::make_shared<mux_tunnel_impl>(std::move(socket), io_context, std::move(session), cfg_, pool_.get_task_group(io_context), cid, trace_id);
}

boost::asio::awaitable<void> client_tunnel_pool::run_real_certificate_fallback(boost::asio::ip::tcp::socket& socket,
                                                                               const handshake_result& handshake_ret,
                                                                               const connection_context& ctx) const
{
    connection_context fallback_ctx = ctx;
    fallback_ctx.sni(sni_);
    fallback_ctx.set_target(sni_, kFallbackTlsPort);

    if (!handshake_ret.negotiated.negotiated_alpn.empty() && handshake_ret.negotiated.negotiated_alpn != "http/1.1")
    {
        LOG_CTX_INFO(fallback_ctx,
                     "{} stage skip_request host {} negotiated_alpn {}",
                     log_event::kFallback,
                     sni_,
                     handshake_ret.negotiated.negotiated_alpn);
        co_return;
    }

    boost::system::error_code ec;
    auto session = reality::reality_session::from_client_handshake(handshake_ret, ec);
    if (ec)
    {
        LOG_CTX_WARN(fallback_ctx, "{} stage build_session error {}", log_event::kFallback, ec.message());
        co_return;
    }

    reality::lightweight_http_visit_options visit_options;
    visit_options.host = sni_;
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
        LOG_CTX_WARN(
            fallback_ctx,
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
        LOG_CTX_ERROR(ctx, "{} stage handshake target {}:{} error invalid_socket", log_event::kHandshake, remote_host_, remote_port_);
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        co_return handshake_result{};
    }
    reality::client_handshaker handshaker(cfg_, sni_, server_pub_key_, short_id_bytes_, fingerprint_type_, max_handshake_records_);
    auto handshake_res = co_await handshaker.run(*socket, ctx, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} stage handshake target {}:{} error {}", log_event::kHandshake, remote_host_, remote_port_, ec.message());
    }
    co_return handshake_res;
}

boost::asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index, boost::asio::io_context& io_context)
{
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
        const auto tunnel_connections = resolve_tunnel_connections(cfg_.limits);
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(cid);
        LOG_CTX_INFO(ctx, "{} init conn {}/{} to {} {}", log_event::kConnInit, index + 1, tunnel_connections, remote_host_, remote_port_);
        // step 1 create sockst
        const auto socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context);
        // step 2 connect remote
        co_await tcp_connect_remote(io_context, *socket, ctx, ec);
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }
            LOG_CTX_ERROR(ctx, "{} stage connect target {}:{} error {}", log_event::kConnInit, remote_host_, remote_port_, ec.message());
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
            socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, close_ec);
            socket->close(close_ec);
            if (!(co_await wait_before_retry(ctx, "real_certificate_fallback")))
            {
                break;
            }
            continue;
        }
        // step 4 build tunnel
        auto tunnel = build_tunnel(std::move(*socket), io_context, cid, handshake_ret, ctx.trace_id());
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
        tunnel->run();
        const auto tunnel_start_ms = timeout_io::now_ms();

        {
            std::lock_guard<std::mutex> lock(tunnel_mutex_);
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

            const auto connection = tunnel->connection();
            if (connection == nullptr || !connection->is_active())
            {
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lock(tunnel_mutex_);
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

boost::asio::awaitable<void> client_tunnel_pool::tcp_connect_remote(boost::asio::io_context& io_context,
                                                                    boost::asio::ip::tcp::socket& socket,
                                                                    const connection_context& ctx,
                                                                    boost::system::error_code& ec) const
{
    const auto timeout_sec = cfg_.timeout.connect;
    boost::asio::ip::tcp::resolver resolver(io_context);
    const auto resolve_endpoints = co_await timeout_io::wait_resolve_with_timeout(resolver, remote_host_, remote_port_, timeout_sec, ec);
    if (ec)
    {
        co_return;
    }

    for (const auto& entry : resolve_endpoints)
    {
        const auto endpoint = entry.endpoint();
        const auto connect_mark = cfg_.tproxy.enabled ? cfg_.tproxy.mark : 0U;
        prepare_socket_for_connect(socket, endpoint, connect_mark, ec);
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
        LOG_CTX_ERROR(ctx, "{} stage connect target {}:{} timeout {}s", log_event::kConnInit, remote_host_, remote_port_, timeout_sec);
    }
    else
    {
        LOG_CTX_ERROR(ctx, "{} stage connect target {}:{} error {}", log_event::kConnInit, remote_host_, remote_port_, ec.message());
    }
    co_return;
}


}    // namespace mux
