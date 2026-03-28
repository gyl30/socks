#include <memory>
#include <string>
#include <vector>
#include <chrono>
#include <utility>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <optional>

#include <boost/asio.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>

extern "C"
{
#include <openssl/crypto.h>
}

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "mux_codec.h"
#include "mux_protocol.h"
#include "context_pool.h"
#include "replay_cache.h"
#include "remote_server.h"
#include "reality/types.h"
#include "mux_connection.h"
#include "remote_session.h"
#include "tls/crypto_util.h"
#include "connection_context.h"
#include "connection_tracker.h"
#include "remote_udp_session.h"
#include "reality/session/session.h"
#include "reality/policy/fallback_gate.h"
#include "reality/policy/fallback_executor.h"
#include "reality/material/material_provider.h"
#include "reality/handshake/server_handshaker.h"

namespace mux
{

namespace
{
[[nodiscard]] reality::fallback_gate::dependencies make_fallback_gate_dependencies()
{
    reality::fallback_gate::dependencies deps;
    return deps;
}

void close_tcp_socket(boost::asio::ip::tcp::socket& socket)    // NOLINT(misc-const-correctness)
{
    boost::system::error_code ec;
    ec = socket.close(ec);
    (void)ec;
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
        ctx.set_local_endpoint("unknown", 0);
    }
    else
    {
        const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
        ctx.set_local_endpoint(local_addr.to_string(), local_ep.port());
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (remote_ep_ec)
    {
        LOG_CTX_WARN(ctx, "{} query remote endpoint failed {}", log_event::kConnInit, remote_ep_ec.message());
        ctx.set_remote_endpoint("unknown", 0);
    }
    else
    {
        const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
        ctx.set_remote_endpoint(remote_addr.to_string(), remote_ep.port());
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

boost::asio::awaitable<void> remote_server::fallback_to_target_site(reality::fallback_request&& request, const char* reason)
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
      owner_worker_(pool.get_io_worker()),
      replay_cache_(static_cast<std::size_t>(cfg.reality.replay_cache_max_entries)),
      fallback_gate_(make_fallback_gate_dependencies()),
      fallback_executor_(owner_worker_.io_context, cfg)
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

    site_material_.reset();
    boost::system::error_code ec;
    auto loaded_material = reality::load_site_material(cfg_, ec);
    if (ec)
    {
        LOG_ERROR("remote server failed to load reality site material {}", ec.message());
        std::exit(EXIT_FAILURE);
    }
    site_material_ = std::move(loaded_material);

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

    owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_loop(); });
}

void remote_server::stop()
{
    if (stopping_.exchange(true))
    {
        return;
    }

    boost::asio::post(owner_worker_.io_context,
                      [self = shared_from_this()]()
                      {
                          boost::system::error_code ec;
                          ec = self->acceptor_.close(ec);
                          if (ec && ec != boost::asio::error::bad_descriptor)
                          {
                              LOG_ERROR("remote acceptor close error {}", ec.message());
                          }
                      });
}

boost::asio::awaitable<void> remote_server::accept_loop()
{
    auto self = shared_from_this();
    boost::asio::steady_timer retry_timer(owner_worker_.io_context);
    while (true)
    {
        auto& worker = pool_.get_io_worker();
        const auto s = std::make_shared<boost::asio::ip::tcp::socket>(worker.io_context);
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
        worker.group.spawn(
            [self, worker = &worker, s, conn_id]() -> boost::asio::awaitable<void>
            {
                const auto active_guard = acquire_active_connection_guard();

                co_await self->handle(*worker, s, conn_id);
            });
    }
    LOG_INFO("accept loop exited");
}

boost::asio::awaitable<void> remote_server::handle(io_worker& worker, std::shared_ptr<boost::asio::ip::tcp::socket> s, std::uint32_t conn_id)
{
    reality::server_handshake_context reality_ctx;
    reality_ctx.socket = s.get();
    reality_ctx.ctx = build_connection_context(s, conn_id);
    auto& ctx = reality_ctx.ctx;
    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());
    boost::system::error_code ec;
    const reality::server_handshaker handshaker({
        .cfg = cfg_,
        .private_key = private_key_,
        .short_id_bytes = short_id_bytes_,
        .replay_cache = replay_cache_,
        .site_material_ptr = site_material_ ? &*site_material_ : nullptr,
        .reality_cert_private_key = reality_cert_private_key_,
        .reality_cert_public_key = reality_cert_public_key_,
        .reality_cert_template = reality_cert_template_,
    });
    auto accept_result = co_await handshaker.accept(reality_ctx, ec);
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

    auto record_context = reality::build_reality_record_context(accept_result.authenticated, ec);
    if (ec)
    {
        co_return;
    }
    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);
    auto connection = std::make_shared<mux_connection>(std::move(*s), worker, std::move(record_context), cfg_, conn_id, ctx.trace_id());
    connection->start_accepting_streams();
    connection->start();
    for (;;)
    {
        mux_frame frame;
        frame = co_await connection->async_receive_syn(ec);
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted && ec != boost::asio::experimental::error::channel_errors::channel_closed &&
                ec != boost::asio::experimental::error::channel_errors::channel_cancelled)
            {
                LOG_CTX_WARN(ctx, "{} accept incoming stream failed {}", log_event::kMux, ec.message());
            }
            break;
        }
        co_await process_stream_request(worker, connection, ctx, std::move(frame));
    }
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

boost::asio::awaitable<void> remote_server::process_stream_request(io_worker& worker,
                                                                   std::shared_ptr<mux_connection> connection,
                                                                   const connection_context& ctx,
                                                                   mux_frame frame) const
{
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

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        LOG_CTX_INFO(stream_ctx,
                     "{} stream {} type tcp connect target {} {} payload size {}",
                     log_event::kMux,
                     frame.h.stream_id,
                     syn.addr,
                     syn.port,
                     frame.payload.size());
        const auto sess = std::make_shared<remote_tcp_session>(worker.io_context, connection, frame.h.stream_id, stream_ctx, cfg_);
        if (!sess->has_stream())
        {
            LOG_CTX_WARN(stream_ctx, "{} stream {} create incoming tcp stream failed", log_event::kMux, frame.h.stream_id);
            co_await send_stream_reset(connection, std::move(frame));
            co_return;
        }
        worker.group.spawn([sess, syn]() mutable -> boost::asio::awaitable<void> { co_await sess->start(syn); });
        co_return;
    }
    if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, frame.h.stream_id);
        const auto sess = std::make_shared<remote_udp_session>(worker.io_context, connection, frame.h.stream_id, stream_ctx, cfg_);
        if (!sess->has_stream())
        {
            LOG_CTX_WARN(stream_ctx, "{} stream {} create incoming udp stream failed", log_event::kMux, frame.h.stream_id);
            co_await send_stream_reset(connection, std::move(frame));
            co_return;
        }
        worker.group.spawn([sess]() mutable -> boost::asio::awaitable<void> { co_await sess->start(); });
        co_return;
    }

    LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, frame.h.stream_id, syn.socks_cmd);
    co_await send_stream_reset(connection, std::move(frame));
}

}    // namespace mux
