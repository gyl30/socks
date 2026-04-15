#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdlib>
#include <utility>
#include <iterator>
#include <optional>

#include <boost/asio.hpp>
#include <openssl/crypto.h>
#include <boost/algorithm/hex.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel_error.hpp>

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "constants.h"
#include "net_utils.h"
#include "context_pool.h"
#include "replay_cache.h"
#include "reality/types.h"
#include "router.h"
#include "reality_inbound.h"
#include "proxy_protocol.h"
#include "trace_store.h"
#include "tls/crypto_util.h"
#include "reality/session/session.h"
#include "reality_tcp_connect_session.h"
#include "reality_udp_associate_session.h"
#include "proxy_reality_connection.h"
#include "reality/policy/fallback_gate.h"
#include "reality/policy/fallback_executor.h"
#include "reality/material/material_provider.h"
#include "reality/handshake/server_handshaker.h"
namespace relay
{

namespace
{
[[nodiscard]] reality::fallback_gate::dependencies make_fallback_gate_dependencies()
{
    reality::fallback_gate::dependencies deps;
    return deps;
}

void close_tcp_socket(boost::asio::ip::tcp::socket& socket)
{
    boost::system::error_code ec;
    socket.close(ec);
    (void)ec;
}

reality::server_handshake_context build_handshake_context(const std::shared_ptr<boost::asio::ip::tcp::socket>& s, uint32_t conn_id)
{
    reality::server_handshake_context ctx;
    ctx.socket = s.get();
    ctx.conn_id = conn_id;

    boost::system::error_code local_ep_ec;
    const auto local_ep = s->local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        LOG_WARN("{} conn {} query local endpoint failed {}", log_event::kConnInit, conn_id, local_ep_ec.message());
        ctx.local_addr = "unknown";
        ctx.local_port = 0;
    }
    else
    {
        const auto local_addr = socks_codec::normalize_ip_address(local_ep.address());
        ctx.local_addr = local_addr.to_string();
        ctx.local_port = local_ep.port();
    }

    boost::system::error_code remote_ep_ec;
    const auto remote_ep = s->remote_endpoint(remote_ep_ec);
    if (remote_ep_ec)
    {
        LOG_WARN("{} conn {} query remote endpoint failed {}", log_event::kConnInit, conn_id, remote_ep_ec.message());
        ctx.remote_addr = "unknown";
        ctx.remote_port = 0;
    }
    else
    {
        const auto remote_addr = socks_codec::normalize_ip_address(remote_ep.address());
        ctx.remote_addr = remote_addr.to_string();
        ctx.remote_port = remote_ep.port();
    }
    return ctx;
}

struct fallback_target
{
    std::string host;
    uint16_t port = constants::reality_limits::kDefaultTlsPort;
};

std::optional<fallback_target> resolve_fallback_target(const config::reality_inbound_t& settings)
{
    if (settings.sni.empty())
    {
        return std::nullopt;
    }

    return fallback_target{.host = settings.sni, .port = constants::reality_limits::kDefaultTlsPort};
}

}    // namespace

boost::asio::awaitable<void> reality_inbound::fallback_to_target_site(reality::fallback_request&& request, const char* reason)
{
    const auto target = resolve_fallback_target(settings_);
    if (!target.has_value())
    {
        LOG_WARN("{} conn {} reason {} no fallback target", log_event::kFallback, request.conn_id, reason == nullptr ? "unknown" : reason);
        co_return;
    }

    auto budget_ticket = fallback_gate_.try_acquire(request, reason);
    if (!budget_ticket.acquired())
    {
        co_return;
    }

    boost::system::error_code ec;
    co_await fallback_executor_.run(request, target->host, target->port, reason, ec);
}

reality_inbound::reality_inbound(io_context_pool& pool, const config& cfg, std::string inbound_tag, const config::reality_inbound_t& settings)
    : cfg_(cfg),
      inbound_tag_(std::move(inbound_tag)),
      settings_(settings),
      pool_(pool),
      owner_worker_(pool.get_io_worker()),
      replay_cache_(static_cast<std::size_t>(settings_.replay_cache_max_entries)),
      router_(std::make_shared<router>(cfg_, inbound_tag_)),
      fallback_gate_(make_fallback_gate_dependencies()),
      fallback_executor_(owner_worker_.io_context, cfg)
{
    private_key_ = tls::crypto_util::hex_to_bytes(settings_.private_key);
    if (private_key_.size() != 32)
    {
        LOG_ERROR("{} stage init private_key length invalid {}", log_event::kConnInit, private_key_.size());
        return;
    }
    boost::algorithm::unhex(settings_.short_id, std::back_inserter(short_id_bytes_));
    boost::system::error_code ec;
    auto pub = tls::crypto_util::extract_public_key(private_key_, ec);
    LOG_INFO("{} stage init reality inbound public key size {}", log_event::kConnInit, ec ? 0 : pub.size());

    uint8_t cert_public_key[32] = {};
    if (!tls::crypto_util::generate_ed25519_keypair(cert_public_key, reality_cert_private_key_.data()))
    {
        LOG_ERROR("{} stage init generate reality certificate identity failed", log_event::kConnInit);
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_public_key_.assign(cert_public_key, cert_public_key + 32);
    auto cert_template = tls::crypto_util::create_self_signed_ed25519_certificate(
        std::vector<uint8_t>(reality_cert_private_key_.begin(), reality_cert_private_key_.end()), ec);
    if (ec)
    {
        LOG_ERROR("{} stage init build reality certificate template failed {}", log_event::kConnInit, ec.message());
        reality_cert_public_key_.clear();
        OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
        return;
    }
    reality_cert_template_ = std::move(cert_template);
}

reality_inbound::~reality_inbound()
{
    if (!private_key_.empty())
    {
        OPENSSL_cleanse(private_key_.data(), private_key_.size());
    }
    OPENSSL_cleanse(reality_cert_private_key_.data(), reality_cert_private_key_.size());
}

void reality_inbound::start()
{
    if (private_key_.size() != 32 || reality_cert_public_key_.size() != 32 || reality_cert_template_.empty())
    {
        LOG_ERROR("{} stage start initialization incomplete private_key {} cert_public_key {} cert_template {}",
                  log_event::kConnInit,
                  private_key_.size(),
                  reality_cert_public_key_.size(),
                  reality_cert_template_.size());
        std::exit(EXIT_FAILURE);
    }

    if (router_ == nullptr || !router_->load())
    {
        LOG_ERROR("{} stage start load router data failed", log_event::kConnInit);
        std::exit(EXIT_FAILURE);
    }

    site_material_.reset();
    boost::system::error_code ec;
    auto loaded_material = reality::load_site_material(settings_, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start load reality site material failed {}", log_event::kConnInit, ec.message());
        std::exit(EXIT_FAILURE);
    }
    site_material_ = std::move(loaded_material);

    const auto addr = boost::asio::ip::make_address(settings_.host, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start parse listen address {} failed {}", log_event::kConnInit, settings_.host, ec.message());
        std::exit(EXIT_FAILURE);
    }
    const auto ep = boost::asio::ip::tcp::endpoint(addr, settings_.port);
    const bool enable_dual_stack = addr.is_v6() && addr.to_v6().is_unspecified();
    ec = acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("{} stage start listen {}:{} open socket failed {}", log_event::kConnInit, settings_.host, settings_.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR(
            "{} stage start listen {}:{} set reuse_address failed {}", log_event::kConnInit, settings_.host, settings_.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    if (enable_dual_stack)
    {
        ec = acceptor_.set_option(boost::asio::ip::v6_only(false), ec);
        if (ec)
        {
            LOG_ERROR(
                "{} stage start listen {}:{} disable v6_only failed {}", log_event::kConnInit, settings_.host, settings_.port, ec.message());
            std::exit(EXIT_FAILURE);
        }
    }
    ec = acceptor_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start listen {}:{} bind failed {}", log_event::kConnInit, settings_.host, settings_.port, ec.message());
        std::exit(EXIT_FAILURE);
    }
    ec = acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("{} stage start listen {}:{} listen failed {}", log_event::kConnInit, settings_.host, settings_.port, ec.message());
        std::exit(EXIT_FAILURE);
    }

    LOG_INFO("{} listen {}:{} reality inbound listening", log_event::kConnInit, settings_.host, settings_.port);

    owner_worker_.group.spawn([self = shared_from_this()]() { return self->accept_loop(); });
}

void reality_inbound::stop()
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
                              LOG_ERROR("{} listen {}:{} acceptor close failed {}",
                                        log_event::kConnClose,
                                        self->settings_.host,
                                        self->settings_.port,
                                        ec.message());
                          }
                      });
}

boost::asio::awaitable<void> reality_inbound::accept_loop()
{
    auto self = shared_from_this();
    while (true)
    {
        auto& worker = pool_.get_io_worker();
        const auto s = std::make_shared<boost::asio::ip::tcp::socket>(worker.io_context);
        const auto [accept_ec] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (accept_ec)
        {
            if (accept_ec == boost::asio::error::operation_aborted || accept_ec == boost::asio::error::bad_descriptor)
            {
                LOG_INFO("{} listen {}:{} accept loop stopped {}", log_event::kConnClose, settings_.host, settings_.port, accept_ec.message());
                break;
            }

            LOG_WARN("{} listen {}:{} accept error {} retrying", log_event::kConnInit, settings_.host, settings_.port, accept_ec.message());

            const auto wait_ec = co_await net::wait_for(owner_worker_.io_context, std::chrono::milliseconds(200));
            if (wait_ec && wait_ec != boost::asio::error::operation_aborted)
            {
                LOG_WARN("{} listen {}:{} accept retry wait error {}", log_event::kConnInit, settings_.host, settings_.port, wait_ec.message());
            }
            continue;
        }

        boost::system::error_code ec;
        ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
        const uint32_t conn_id = next_conn_id_++;
        if (ec)
        {
            LOG_WARN("{} conn {} set no delay failed {}", log_event::kConnInit, conn_id, ec.message());
        }
        worker.group.spawn([self, worker = &worker, s, conn_id]() -> boost::asio::awaitable<void> { co_await self->handle(*worker, s, conn_id); });
    }
    LOG_INFO("{} listen {}:{} accept loop exited", log_event::kConnClose, settings_.host, settings_.port);
}

boost::asio::awaitable<void> reality_inbound::handle(io_worker& worker, std::shared_ptr<boost::asio::ip::tcp::socket> s, uint32_t conn_id)
{
    auto reality_ctx = build_handshake_context(s, conn_id);
    LOG_INFO("{} conn {} local {}:{} remote {}:{} accepted",
             log_event::kConnInit,
             reality_ctx.conn_id,
             reality_ctx.local_addr,
             reality_ctx.local_port,
             reality_ctx.remote_addr,
             reality_ctx.remote_port);
    boost::system::error_code ec;
    const reality::server_handshaker handshaker({
        .cfg = cfg_,
        .settings = settings_,
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
        request.conn_id = reality_ctx.conn_id;
        request.local_addr = std::move(reality_ctx.local_addr);
        request.local_port = reality_ctx.local_port;
        request.remote_addr = std::move(reality_ctx.remote_addr);
        request.remote_port = reality_ctx.remote_port;
        request.sni = std::move(reality_ctx.sni);
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
        LOG_ERROR("{} conn {} unexpected accept mode {}", log_event::kHandshake, reality_ctx.conn_id, static_cast<int>(accept_result.mode));
        co_return;
    }
    LOG_INFO("{} conn {} authorized sni {}", log_event::kAuth, reality_ctx.conn_id, reality_ctx.sni);

    auto record_context = reality::build_reality_record_context(accept_result.authenticated, ec);
    if (ec)
    {
        LOG_ERROR("{} conn {} sni {} stage build_record_context error {}",
                  log_event::kHandshake,
                  reality_ctx.conn_id,
                  reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni,
                  ec.message());
        co_return;
    }
    LOG_INFO("{} conn {} sni {} tunnel starting",
             log_event::kConnEstablished,
             reality_ctx.conn_id,
             reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni);
    auto connection = std::make_shared<proxy_reality_connection>(std::move(*s), std::move(record_context), cfg_, conn_id);
    co_await process_proxy_request(worker, connection, reality_ctx);
}

boost::asio::awaitable<void> reality_inbound::process_proxy_request(io_worker& worker,
                                                                    std::shared_ptr<proxy_reality_connection> connection,
                                                                    const reality::server_handshake_context& reality_ctx) const
{
    if (connection == nullptr)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} dropped without connection",
                 log_event::kRoute,
                 reality_ctx.conn_id,
                 reality_ctx.local_addr,
                 reality_ctx.local_port,
                 reality_ctx.remote_addr,
                 reality_ctx.remote_port,
                 reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni);
        co_return;
    }

    boost::system::error_code ec;
    const auto packet = co_await connection->read_packet(cfg_.timeout.connect == 0 ? cfg_.timeout.read : cfg_.timeout.connect + 1, ec);
    if (ec)
    {
        LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} read initial proxy packet failed {}",
                 log_event::kRoute,
                 reality_ctx.conn_id,
                 reality_ctx.local_addr,
                 reality_ctx.local_port,
                 reality_ctx.remote_addr,
                 reality_ctx.remote_port,
                 reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni,
                 ec.message());
        co_return;
    }

    proxy::tcp_connect_request tcp_request;
    if (proxy::decode_tcp_connect_request(packet.data(), packet.size(), tcp_request))
    {
        LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} sni {} type tcp connect target {}:{} payload_size {}",
                 log_event::kRoute,
                 tcp_request.trace_id,
                 reality_ctx.conn_id,
                 reality_ctx.local_addr,
                 reality_ctx.local_port,
                 reality_ctx.remote_addr,
                 reality_ctx.remote_port,
                 reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni,
                 tcp_request.target_host,
                 tcp_request.target_port,
                 packet.size());
        trace_store::instance().record_event(trace_event{
            .trace_id = tcp_request.trace_id,
            .conn_id = reality_ctx.conn_id,
            .stage = trace_stage::kRequestDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .target_host = tcp_request.target_host,
            .target_port = tcp_request.target_port,
            .local_host = reality_ctx.local_addr,
            .local_port = reality_ctx.local_port,
            .remote_host = reality_ctx.remote_addr,
            .remote_port = reality_ctx.remote_port,
            .extra = {{"type", "tcp"}},
        });
        const auto tcp_connect_session = std::make_shared<reality_tcp_connect_session>(
            worker.io_context, std::move(connection), router_, reality_ctx.conn_id, tcp_request.trace_id, inbound_tag_, cfg_);
        co_await tcp_connect_session->start(tcp_request);
        co_return;
    }

    proxy::udp_associate_request udp_request;
    if (proxy::decode_udp_associate_request(packet.data(), packet.size(), udp_request))
    {
        LOG_INFO("{} trace {:016x} conn {} local {}:{} remote {}:{} sni {} type udp associate payload_size {}",
                 log_event::kRoute,
                 udp_request.trace_id,
                 reality_ctx.conn_id,
                 reality_ctx.local_addr,
                 reality_ctx.local_port,
                 reality_ctx.remote_addr,
                 reality_ctx.remote_port,
                 reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni,
                 packet.size());
        trace_store::instance().record_event(trace_event{
            .trace_id = udp_request.trace_id,
            .conn_id = reality_ctx.conn_id,
            .stage = trace_stage::kRequestDone,
            .result = trace_result::kOk,
            .inbound_tag = inbound_tag_,
            .inbound_type = "reality",
            .local_host = reality_ctx.local_addr,
            .local_port = reality_ctx.local_port,
            .remote_host = reality_ctx.remote_addr,
            .remote_port = reality_ctx.remote_port,
            .extra = {{"type", "udp"}},
        });
        const auto udp_associate_session = std::make_shared<reality_udp_associate_session>(
            worker.io_context, std::move(connection), router_, reality_ctx.conn_id, udp_request.trace_id, inbound_tag_, cfg_);
        co_await udp_associate_session->start(udp_request);
        co_return;
    }

    LOG_WARN("{} conn {} local {}:{} remote {}:{} sni {} invalid initial proxy request payload_size {}",
             log_event::kRoute,
             reality_ctx.conn_id,
             reality_ctx.local_addr,
             reality_ctx.local_port,
             reality_ctx.remote_addr,
             reality_ctx.remote_port,
             reality_ctx.sni.empty() ? "unknown" : reality_ctx.sni,
             packet.size());
}

}    // namespace relay
