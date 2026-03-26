#include <array>
#include <ctime>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <cctype>
#include <expected>
#include <optional>
#include <algorithm>

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/detail/errc.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "constants.h"
#include "mux_tunnel.h"
#include "connection_tracker.h"
#include "tls/core.h"
#include "tls/crypto_util.h"
#include "connection_context.h"
#include "context_pool.h"
#include "replay_cache.h"
#include "remote_server.h"
#include "remote_session.h"
#include "tls/ch_parser.h"
#include "tls/record_layer.h"
#include "remote_udp_session.h"
#include "tls/record_validation.h"
#include "reality/handshake/auth.h"
#include "reality/session/session.h"
#include "reality/policy/fallback_gate.h"
#include "reality/handshake/server_handshaker.h"

namespace mux
{

namespace
{

std::shared_ptr<void> make_active_connection_guard()
{
    return {new int(0),
            [](void* ptr)
            {
                delete static_cast<int*>(ptr);
                connection_tracker::instance().release();
            }};
}

void close_tcp_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    ec = socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    ec = socket.close(ec);
}

connection_context build_connection_context(const std::shared_ptr<boost::asio::ip::tcp::socket>& s, std::uint32_t conn_id)
{
    connection_context ctx;
    ctx.new_trace_id();
    ctx.conn_id(conn_id);

    boost::system::error_code local_ep_ec;
    const auto local_ep = s->local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_CTX_WARN(ctx, "{} query local endpoint failed {}", log_event::kConnInit, local_ep_ec.message());
        ctx.local_addr("unknown");
        ctx.local_port(0);
    }
    else
    {
        const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
        ctx.local_addr(local_addr.to_string());
        ctx.local_port(local_ep.port());
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (remote_ep_ec)
    {
        LOG_CTX_WARN(ctx, "{} query remote endpoint failed {}", log_event::kConnInit, remote_ep_ec.message());
        ctx.remote_addr("unknown");
        ctx.remote_port(0);
    }
    else
    {
        const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
        ctx.remote_addr(remote_addr.to_string());
        ctx.remote_port(remote_ep.port());
    }
    return ctx;
}

struct fallback_target
{
    std::string host;
    std::uint16_t port = 443;
};

std::optional<fallback_target> resolve_fallback_target(const config& cfg)
{
    if (cfg.reality.sni.empty())
    {
        return std::nullopt;
    }

    return fallback_target{.host = cfg.reality.sni, .port = 443};
}

}    // namespace

boost::asio::awaitable<void> remote_server::fallback_to_target_site(reality::fallback_request request, const char* reason)
{
    auto& ctx = request.ctx;
    const auto target = resolve_fallback_target(cfg_);
    if (!target.has_value())
    {
        LOG_CTX_WARN(ctx, "{} reason {} no fallback target", log_event::kFallback, reason);
        co_return;
    }

    auto budget_ticket = fallback_gate_.try_acquire(ctx, reason);
    if (!budget_ticket.acquired())
    {
        co_return;
    }

    boost::system::error_code ec;
    co_await fallback_executor_.run(request, target->host, target->port, reason, ec);
}

remote_server::remote_server(io_context_pool& pool, const config& cfg)
    : cfg_(cfg),
      pool_(pool),
      io_context_(pool.get_io_context()),
      replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries)),
      material_provider_({.cfg = cfg, .opts = {}, .now_seconds = {}, .fetch = {}}),
      fallback_gate_({.opts = {}, .now_seconds = {}}),
      fallback_executor_({.io_context = io_context_, .cfg = cfg, .opts = {}})
{
    private_key_ = ::tls::crypto_util::hex_to_bytes(cfg.reality.private_key);
    if (private_key_.size() != 32)
    {
        LOG_ERROR("private key length invalid {}", private_key_.size());
        return;
    }
    boost::algorithm::unhex(cfg.reality.short_id, std::back_inserter(short_id_bytes_));
    boost::system::error_code ec;
    auto pub = ::tls::crypto_util::extract_public_key(private_key_, ec);
    LOG_INFO("server public key size {}", ec ? 0 : pub.size());

    std::uint8_t cert_public_key[32] = {};
    if (!::tls::crypto_util::generate_ed25519_keypair(cert_public_key, reality_cert_private_key_.data()))
    {
        LOG_ERROR("failed to generate reality certificate identity");
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_public_key_.assign(cert_public_key, cert_public_key + 32);
    auto cert_template = ::tls::crypto_util::create_self_signed_ed25519_certificate(
        std::vector<std::uint8_t>(reality_cert_private_key_.begin(), reality_cert_private_key_.end()), ec);
    if (ec)
    {
        LOG_ERROR("failed to build reality certificate template {}", ec.message());
        reality_cert_public_key_.clear();
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_template_ = std::move(cert_template);
}

remote_server::~remote_server()
{
    if (!private_key_.empty())
    {
        OPENSSL_cleanse(private_key_.data(), private_key_.size());
    }
    OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
}

void remote_server::start()
{
    if (private_key_.size() != 32 || reality_cert_public_key_.size() != 32 || reality_cert_template_.empty())
    {
        LOG_ERROR("remote server initialization incomplete private key {} cert public key {} cert template {}",
                  private_key_.size(),
                  reality_cert_public_key_.size(),
                  reality_cert_template_.size());
        std::exit(EXIT_FAILURE);
    }

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(cfg_.inbound.host, ec);
    if (ec)
    {
        LOG_ERROR("remote server parse listen address {} failed {}", cfg_.inbound.host, ec.message());
        std::exit(EXIT_FAILURE);
    }
    const auto ep = boost::asio::ip::tcp::endpoint(addr, cfg_.inbound.port);
    const bool enable_dual_stack = addr.is_v6() && addr.to_v6().is_unspecified();
    ec = acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("remote server open listen socket {}:{} failed {}", cfg_.inbound.host, cfg_.inbound.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("remote server set reuse_address {}:{} failed {}", cfg_.inbound.host, cfg_.inbound.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    if (enable_dual_stack)
    {
        ec = acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR("remote server disable v6_only {}:{} failed {}", cfg_.inbound.host, cfg_.inbound.port, ec.message());
            std::exit(EXIT_FAILURE);
        }
    }
    ec = acceptor_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("remote server bind {}:{} failed {}", cfg_.inbound.host, cfg_.inbound.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("remote server listen {}:{} failed {}", cfg_.inbound.host, cfg_.inbound.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("remote server listening on {}:{}", cfg_.inbound.host, cfg_.inbound.port);

    auto& owner_group = pool_.get_task_group(io_context_);
    boost::asio::co_spawn(
        io_context_, [self = shared_from_this()] { return self->material_provider_.refresh_loop(self->io_context_); }, owner_group.adapt(boost::asio::detached));
    boost::asio::co_spawn(io_context_, [self = shared_from_this()] { return self->accept_loop(); }, owner_group.adapt(boost::asio::detached));
}

void remote_server::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(io_context_,
                      [self = shared_from_this()]()
                      {
                          boost::system::error_code ec;
                          self->acceptor_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("remote acceptor close error {}", ec.message());
                          }
                          self->pool_.emit_all(boost::asio::cancellation_type::all);
                      });
}

boost::asio::awaitable<void> remote_server::wait_stopped()
{
    co_await pool_.async_wait_all();
}

boost::asio::awaitable<void> remote_server::accept_loop()
{
    auto self = shared_from_this();
    boost::asio::steady_timer retry_timer(io_context_);
    while (true)
    {
        auto& io = pool_.get_io_context();
        auto& io_group = pool_.get_task_group(io);
        const auto s = std::make_shared<boost::asio::ip::tcp::socket>(io);
        const auto [accept_ec] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (accept_ec)
        {
            if (accept_ec == boost::asio::error::operation_aborted || accept_ec == boost::asio::error::bad_descriptor)
            {
                LOG_INFO("accept loop stopped {}", accept_ec.message());
                break;
            }
            LOG_WARN("accept error {} retrying", accept_ec.message());
            retry_timer.expires_after(std::chrono::milliseconds(200));
            const auto [wait_ec] = co_await retry_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (wait_ec && wait_ec != boost::asio::error::operation_aborted)
            {
                LOG_WARN("accept retry wait error {}", wait_ec.message());
            }
            continue;
        }

        if (connection_tracker::instance().active_connections() >= cfg_.limits.max_connections)
        {
            close_tcp_socket(*s);
            LOG_WARN("remote server connection limit reached drop");
            continue;
        }

        boost::system::error_code ec;
        ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
        (void)ec;
        const std::uint32_t conn_id = next_conn_id_++;
        connection_tracker::instance().acquire();
        boost::asio::co_spawn(
            io,
            [self = shared_from_this(), io = &io, s, conn_id]() -> boost::asio::awaitable<void>
            {
                [[maybe_unused]] const auto active_guard = make_active_connection_guard();
                co_await self->handle(*io, s, conn_id);
            },
            io_group.adapt(boost::asio::detached));
    }
    LOG_INFO("accept loop exited");
}

boost::asio::awaitable<void> remote_server::handle(boost::asio::io_context& io,
                                                   std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                   std::uint32_t conn_id)
{
    reality::server_handshake_context reality_ctx;
    reality_ctx.socket = s.get();
    reality_ctx.ctx = build_connection_context(s, conn_id);
    auto& ctx = reality_ctx.ctx;
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());
    boost::system::error_code ec;
    reality::server_handshaker handshaker(
        {.cfg = cfg_,
         .private_key = private_key_,
         .short_id_bytes = short_id_bytes_,
         .replay_cache = replay_cache_,
         .material_provider_ref = material_provider_,
         .reality_cert_private_key = reality_cert_private_key_,
         .reality_cert_public_key = reality_cert_public_key_,
         .reality_cert_template = reality_cert_template_});
    const auto accept_result = co_await handshaker.accept(reality_ctx, ec);
    if (ec)
    {
        co_return;
    }
    if (accept_result.mode == reality::accept_mode::kFallbackToTarget)
    {
        reality::fallback_request request;
        request.client_socket = reality_ctx.socket;
        request.ctx = std::move(reality_ctx.ctx);
        request.client_hello_record = std::move(accept_result.decision_context.client_hello_record);
        co_await fallback_to_target_site(std::move(request), accept_result.decision_reason.c_str());
        co_return;
    }
    if (accept_result.mode == reality::accept_mode::kReject)
    {
        if (s != nullptr)
        {
            close_tcp_socket(*s);
        }
        co_return;
    }
    if (accept_result.mode != reality::accept_mode::kAuthenticated)
    {
        LOG_CTX_ERROR(ctx, "{} unexpected accept mode {}", log_event::kHandshake, static_cast<int>(accept_result.mode));
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, ctx.sni());

    auto session = reality::reality_session::from_authenticated_session(accept_result.authenticated, ec);
    if (ec)
    {
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);
    auto tunnel = std::make_shared<mux_tunnel_impl>(std::move(*s), io, std::move(session), cfg_, pool_.get_task_group(io), conn_id, ctx.trace_id());

    std::weak_ptr<remote_server> weak_self = weak_from_this();
    std::weak_ptr<mux_tunnel_impl> weak_tunnel = tunnel;
    tunnel->set_new_stream_cb(
        [weak_self, weak_tunnel, ctx](mux_frame frame) -> boost::asio::awaitable<void>
        {
            const auto self = weak_self.lock();
            const auto tunnel_ref = weak_tunnel.lock();
            if (self == nullptr || tunnel_ref == nullptr)
            {
                co_return;
            }
            co_await self->process_stream_request(tunnel_ref, ctx, std::move(frame));
        });
    tunnel->run();
    const auto connection = tunnel->connection();
    if (connection != nullptr)
    {
        co_await connection->async_wait_stopped();
    }
    co_return;
}

static boost::asio::awaitable<void> send_stream_reset(const std::shared_ptr<mux_connection>& connection, mux_frame frame)
{
    frame.h.command = mux::kCmdRst;
    if (!frame.payload.empty())
    {
        std::vector<std::uint8_t>().swap(frame.payload);
    }
    boost::system::error_code ec;
    constexpr std::uint32_t kRstSendTimeoutSec = 1;
    co_await connection->send_async_with_timeout(std::move(frame), kRstSendTimeoutSec, ec);
}

boost::asio::awaitable<void> remote_server::process_stream_request(std::shared_ptr<mux_tunnel_impl> tunnel,
                                                                   const connection_context& ctx,
                                                                   mux_frame frame)
{
    const auto connection = tunnel->connection();
    if (connection == nullptr)
    {
        LOG_CTX_WARN(ctx, "{} stream {} dropped without connection", log_event::kMux, frame.h.stream_id);
        co_return;
    }

    syn_payload syn;
    if (!mux_codec::decode_syn(frame.payload.data(), frame.payload.size(), syn))
    {
        LOG_CTX_WARN(ctx, "{} stream {} invalid syn", log_event::kMux, frame.h.stream_id);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }

    connection_context stream_ctx = ctx;
    if (!syn.trace_id.empty())
    {
        stream_ctx.trace_id(syn.trace_id);
    }
    if (!syn.trace_id.empty())
    {
        LOG_CTX_DEBUG(stream_ctx, "{} linked client trace id {}", log_event::kMux, syn.trace_id);
    }
    if (syn.addr.empty())
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} invalid target empty", log_event::kMux, frame.h.stream_id);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdConnect && syn.port == 0)
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} invalid target {} {}", log_event::kMux, frame.h.stream_id, syn.addr, syn.port);
        co_await send_stream_reset(connection, std::move(frame));
        co_return;
    }

    auto& connection_io = connection->io_context();
    auto& connection_group = pool_.get_task_group(connection_io);

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        LOG_CTX_INFO(stream_ctx,
                     "{} stream {} type tcp connect target {} {} payload size {}",
                     log_event::kMux,
                     frame.h.stream_id,
                     syn.addr,
                     syn.port,
                     frame.payload.size());
        const auto sess = std::make_shared<remote_tcp_session>(connection, frame.h.stream_id, stream_ctx, cfg_);
        sess->set_manager(tunnel);
        boost::asio::co_spawn(connection_io,
                              [sess, syn]() mutable -> boost::asio::awaitable<void> { co_await sess->start(syn); },
                              connection_group.adapt(boost::asio::detached));
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, frame.h.stream_id);
        const auto sess = std::make_shared<remote_udp_session>(connection, frame.h.stream_id, stream_ctx, cfg_);
        sess->set_manager(tunnel);
        boost::asio::co_spawn(connection_io,
                              [sess]() mutable -> boost::asio::awaitable<void> { co_await sess->start(); },
                              connection_group.adapt(boost::asio::detached));
        co_return;
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, frame.h.stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, std::move(frame));
}

}    // namespace mux
