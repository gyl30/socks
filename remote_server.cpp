#include <ctime>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <utility>
#include <charconv>
#include <system_error>

#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/experimental/awaitable_operators.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "log.h"
#include "config.h"
#include "protocol.h"
#include "ch_parser.h"
#include "constants.h"
#include "mux_codec.h"
#include "mux_tunnel.h"
#include "crypto_util.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "reality_auth.h"
#include "remote_server.h"
#include "reality_engine.h"
#include "remote_session.h"
#include "remote_udp_session.h"

namespace mux
{

namespace
{

bool parse_hex_to_bytes(const std::string& hex, std::vector<std::uint8_t>& out, const std::size_t max_len, const char* label)
{
    out.clear();
    if (hex.empty())
    {
        return true;
    }
    if (hex.size() % 2 != 0)
    {
        LOG_ERROR("{} hex length invalid", label);
        return false;
    }
    out = reality::crypto_util::hex_to_bytes(hex);
    if (out.empty())
    {
        LOG_ERROR("{} hex decode failed", label);
        return false;
    }
    if (max_len > 0 && out.size() > max_len)
    {
        LOG_ERROR("{} length {} exceeds max {}", label, out.size(), max_len);
        return false;
    }
    return true;
}

bool parse_dest_target(const std::string& input, std::string& host, std::string& port)
{
    host.clear();
    port.clear();
    if (input.empty())
    {
        return false;
    }

    if (input.front() == '[')
    {
        const auto end = input.find(']');
        if (end == std::string::npos)
        {
            return false;
        }
        host = input.substr(1, end - 1);
        if (end + 1 >= input.size() || input[end + 1] != ':')
        {
            return false;
        }
        port = input.substr(end + 2);
    }
    else
    {
        const auto pos = input.rfind(':');
        if (pos == std::string::npos)
        {
            return false;
        }
        host = input.substr(0, pos);
        port = input.substr(pos + 1);
    }

    if (host.empty() || port.empty())
    {
        return false;
    }
    return true;
}

}    // namespace

remote_server::remote_server(io_context_pool& pool, const config& cfg)
    : pool_(pool),
      acceptor_(pool.get_io_context()),
      fallbacks_(cfg.fallbacks),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    std::error_code ec;
    auto addr = asio::ip::make_address(cfg.inbound.host, ec);
    if (ec)
    {
        LOG_ERROR("parse inbound host {} failed {}", cfg.inbound.host, ec.message());
        addr = asio::ip::address_v6::any();
    }
    asio::ip::tcp::endpoint ep(addr, cfg.inbound.port);
    ec = acceptor_.open(ep.protocol(), ec);
    if (ec)
    {
        LOG_ERROR("acceptor open failed {}", ec.message());
        return;
    }
    ec = acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
    {
        LOG_ERROR("acceptor set reuse address failed {}", ec.message());
        return;
    }
    ec = acceptor_.bind(ep, ec);
    if (ec)
    {
        LOG_ERROR("acceptor bind failed {}", ec.message());
        return;
    }
    ec = acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        LOG_ERROR("acceptor listen failed {}", ec.message());
        return;
    }
    private_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.private_key);
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id");
    fallback_type_ = cfg.reality.type;
    if (!fallback_type_.empty() && fallback_type_ != "tcp")
    {
        LOG_WARN("reality fallback type not supported {}", fallback_type_);
    }
    if (!cfg.reality.dest.empty())
    {
        if (!parse_dest_target(cfg.reality.dest, fallback_dest_host_, fallback_dest_port_))
        {
            LOG_ERROR("reality dest invalid {}", cfg.reality.dest);
            auth_config_valid_ = false;
        }
        else
        {
            fallback_dest_valid_ = true;
        }
    }
    std::error_code ignore;
    const auto pub = reality::crypto_util::extract_public_key(private_key_, ignore);
    LOG_INFO("server public key size {}", pub.size());
}

remote_server::~remote_server()
{
    if (!private_key_.empty())
    {
        OPENSSL_cleanse(private_key_.data(), private_key_.size());
    }
}

void remote_server::start()
{
    stop_.store(false, std::memory_order_release);
    asio::co_spawn(acceptor_.get_executor(), [self = shared_from_this()] { return self->accept_loop(); }, asio::detached);
}

void remote_server::stop()
{
    stop_.store(true, std::memory_order_release);
    LOG_INFO("remote server stopping");

    auto close_acceptor = [this]()
    {
        std::error_code close_ec;
        close_ec = acceptor_.close(close_ec);
        if (close_ec && close_ec != asio::error::bad_descriptor)
        {
            LOG_WARN("acceptor close failed {}", close_ec.message());
        }
    };
    asio::dispatch(acceptor_.get_executor(), close_acceptor);

    std::vector<std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> tunnels_to_close;
    {
        const std::scoped_lock lock(tunnels_mutex_);
        LOG_INFO("closing {} active tunnels", active_tunnels_.size());
        tunnels_to_close = active_tunnels_;
        active_tunnels_.clear();
    }

    for (auto& weak_tunnel : tunnels_to_close)
    {
        const auto tunnel = weak_tunnel.lock();
        if (tunnel != nullptr)
        {
            if (tunnel->connection() != nullptr)
            {
                tunnel->connection()->stop();
            }
        }
    }
}

asio::awaitable<void> remote_server::accept_loop()
{
    LOG_INFO("remote server listening for connections");
    while (!stop_.load(std::memory_order_acquire))
    {
        auto& ctx = pool_.get_io_context();
        const auto s = std::make_shared<asio::ip::tcp::socket>(ctx);
        const auto [accept_ec] = co_await acceptor_.async_accept(*s, asio::as_tuple(asio::use_awaitable));
        if (!accept_ec)
        {
            std::error_code ec;
            ec = s->set_option(asio::ip::tcp::no_delay(true), ec);
            (void)ec;
            const std::uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);

            asio::co_spawn(ctx, [this, s, self = shared_from_this(), conn_id = conn_id]() { return handle(s, conn_id); }, asio::detached);
        }
        else
        {
            if (accept_ec == asio::error::operation_aborted || accept_ec == asio::error::bad_descriptor || stop_.load(std::memory_order_acquire) ||
                !acceptor_.is_open())
            {
                LOG_INFO("acceptor closed stopping loop");
                break;
            }
            LOG_WARN("accept error {}", accept_ec.message());
        }
    }
}

asio::awaitable<remote_server::server_handshake_res> remote_server::negotiate_reality(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                      const connection_context& ctx,
                                                                                      std::vector<std::uint8_t>& initial_buf)
{
    const auto ok = co_await read_initial_and_validate(s, ctx, initial_buf);

    std::string client_sni;
    client_hello_info info;
    if (!initial_buf.empty())
    {
        info = ch_parser::parse(initial_buf);
        client_sni = info.sni;
    }

    if (!ok)
    {
        static thread_local std::mt19937 delay_gen(std::random_device{}());
        std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
        asio::steady_timer delay_timer(s->get_executor());
        delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
        co_await delay_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        co_await handle_fallback(s, initial_buf, ctx, client_sni);
        co_return server_handshake_res{.ok = false};
    }

    const auto auth_ok = authenticate_client(info, initial_buf, ctx);
    if (!auth_ok)
    {
        LOG_CTX_WARN(ctx, "{} auth failed sni {}", log_event::kAuth, client_sni);
        static thread_local std::mt19937 delay_gen(std::random_device{}());
        std::uniform_int_distribution<std::uint32_t> delay_dist(10, 50);
        asio::steady_timer delay_timer(s->get_executor());
        delay_timer.expires_after(std::chrono::milliseconds(delay_dist(delay_gen)));
        co_await delay_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        co_await handle_fallback(s, initial_buf, ctx, client_sni);
        co_return server_handshake_res{.ok = false};
    }

    LOG_CTX_INFO(ctx, "{} authorized sni {}", log_event::kAuth, info.sni);
    reality::transcript trans;

    if (initial_buf.size() > 5)
    {
        trans.update(std::vector<std::uint8_t>(initial_buf.begin() + 5, initial_buf.end()));
    }
    else
    {
        LOG_CTX_ERROR(ctx, "{} buffer too short", log_event::kHandshake);
        co_return server_handshake_res{.ok = false};
    }

    std::error_code ec;
    auto sh_res = co_await perform_handshake_response(s, info, trans, ctx, ec);
    if (!sh_res.ok)
    {
        LOG_CTX_ERROR(ctx, "{} response error {}", log_event::kHandshake, ec.message());
        co_return server_handshake_res{.ok = false};
    }

    if (!co_await verify_client_finished(s, sh_res.c_hs_keys, sh_res.hs_keys, trans, sh_res.cipher, sh_res.negotiated_md, ctx, ec))
    {
        co_return server_handshake_res{.ok = false};
    }

    sh_res.handshake_hash = trans.finish();
    co_return sh_res;
}

asio::awaitable<void> remote_server::handle(std::shared_ptr<asio::ip::tcp::socket> s, const std::uint32_t conn_id)
{
    auto self = shared_from_this();
    connection_context ctx;
    ctx.new_trace_id();
    ctx.conn_id(conn_id);
    const auto local_addr = socks_codec::normalize_ip_address(s->local_endpoint().address());
    const auto remote_addr = socks_codec::normalize_ip_address(s->remote_endpoint().address());
    ctx.local_addr(local_addr.to_string());
    ctx.local_port(s->local_endpoint().port());
    ctx.remote_addr(remote_addr.to_string());
    ctx.remote_port(s->remote_endpoint().port());

    LOG_CTX_INFO(ctx, "{} accepted {}", log_event::kConnInit, ctx.connection_info());

    std::vector<std::uint8_t> initial_buf;
    auto sh_res = co_await negotiate_reality(s, ctx, initial_buf);
    if (!sh_res.ok)
    {
        co_return;
    }

    std::error_code ec;
    const auto app_sec =
        reality::tls_key_schedule::derive_application_secrets(sh_res.hs_keys.master_secret, sh_res.handshake_hash, sh_res.negotiated_md, ec);
    const std::size_t key_len = EVP_CIPHER_key_length(sh_res.cipher);
    constexpr std::size_t iv_len = 12;

    const auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec, key_len, iv_len, sh_res.negotiated_md);
    const auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec, key_len, iv_len, sh_res.negotiated_md);

    LOG_CTX_INFO(ctx, "{} tunnel starting", log_event::kConnEstablished);

    bool over_limit = false;
    {
        const std::scoped_lock lock(tunnels_mutex_);
        std::erase_if(active_tunnels_, [](const auto& wp) { return wp.expired(); });
        over_limit = active_tunnels_.size() >= limits_config_.max_connections;
    }
    if (over_limit)
    {
        LOG_CTX_WARN(ctx, "{} connection limit reached {} rejecting", log_event::kConnClose, limits_config_.max_connections);
        client_hello_info info = ch_parser::parse(initial_buf);
        co_await handle_fallback(s, initial_buf, ctx, info.sni);
        co_return;
    }

    reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second, sh_res.cipher);
    auto tunnel = std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(
        std::move(*s), std::move(engine), false, conn_id, ctx.trace_id(), timeout_config_, limits_config_, heartbeat_config_);

    {
        const std::scoped_lock lock(tunnels_mutex_);
        active_tunnels_.push_back(tunnel);
    }

    std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> weak_tunnel = tunnel;
    tunnel->connection()->set_syn_callback(
        [weak_self = std::weak_ptr<remote_server>(shared_from_this()), weak_tunnel, ctx](const std::uint32_t id, std::vector<std::uint8_t> p)
        {
            if (auto self = weak_self.lock())
            {
                if (auto tunnel = weak_tunnel.lock())
                {
                    auto ex = tunnel->connection()->executor();
                    asio::co_spawn(
                        ex,
                        [self, tunnel, ctx, id, p = std::move(p), ex]() mutable
                        { return self->process_stream_request(tunnel, ctx, id, std::move(p), ex); },
                        asio::detached);
                }
            }
        });

    co_await tunnel->run();
}

asio::awaitable<void> remote_server::process_stream_request(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel,
                                                            const connection_context& ctx,
                                                            const std::uint32_t stream_id,
                                                            std::vector<std::uint8_t> payload,
                                                            asio::any_io_executor ex) const
{
    if (!tunnel->connection()->can_accept_stream())
    {
        LOG_CTX_WARN(ctx, "{} stream limit reached", log_event::kMux);
        const ack_payload ack{.socks_rep = socks::kRepGenFail, .bnd_addr = "", .bnd_port = 0};
        std::vector<std::uint8_t> ack_data;
        mux_codec::encode_ack(ack, ack_data);
        (void)co_await tunnel->connection()->send_async(stream_id, kCmdAck, std::move(ack_data));
        (void)co_await tunnel->connection()->send_async(stream_id, kCmdRst, {});
        co_return;
    }
    syn_payload syn;
    if (!mux_codec::decode_syn(payload.data(), payload.size(), syn))
    {
        LOG_CTX_WARN(ctx, "{} stream {} invalid syn", log_event::kMux, stream_id);
        (void)co_await tunnel->connection()->send_async(stream_id, kCmdRst, {});
        co_return;
    }
    connection_context stream_ctx = ctx;
    if (!syn.trace_id.empty())
    {
        stream_ctx.trace_id(syn.trace_id);
        LOG_CTX_DEBUG(stream_ctx, "{} linked client trace id {}", log_event::kMux, syn.trace_id);
    }

    if (syn.socks_cmd == socks::kCmdConnect)
    {
        LOG_CTX_INFO(
            stream_ctx, "{} stream {} type tcp connect target {} {} payload size {}", log_event::kMux, stream_id, syn.addr, syn.port, payload.size());
        const auto sess = std::make_shared<remote_session>(tunnel->connection(), stream_id, ex, stream_ctx);
        sess->set_manager(tunnel);
        if (!tunnel->try_register_stream(stream_id, sess))
        {
            LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
            (void)co_await tunnel->connection()->send_async(stream_id, kCmdRst, {});
            co_return;
        }
        co_await sess->start(syn);
    }
    else if (syn.socks_cmd == socks::kCmdUdpAssociate)
    {
        LOG_CTX_INFO(stream_ctx, "{} stream {} type udp associate associated via tcp", log_event::kMux, stream_id);
        const auto sess = std::make_shared<remote_udp_session>(tunnel->connection(), stream_id, ex, stream_ctx);
        sess->set_manager(tunnel);
        if (!tunnel->try_register_stream(stream_id, sess))
        {
            LOG_CTX_WARN(stream_ctx, "{} stream id conflict {}", log_event::kMux, stream_id);
            (void)co_await tunnel->connection()->send_async(stream_id, kCmdRst, {});
            co_return;
        }
        co_await sess->start();
    }
    else
    {
        LOG_CTX_WARN(stream_ctx, "{} stream {} unknown cmd {}", log_event::kMux, stream_id, syn.socks_cmd);
        (void)co_await tunnel->connection()->send_async(stream_id, kCmdRst, {});
    }
}

asio::awaitable<bool> remote_server::read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                               const connection_context& ctx,
                                                               std::vector<std::uint8_t>& buf)
{
    buf.resize(constants::net::kBufferSize);
    const auto [read_ec, n] = co_await s->async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
    if (read_ec)
    {
        LOG_CTX_ERROR(ctx, "{} initial read error {}", log_event::kHandshake, read_ec.message());
        co_return false;
    }
    buf.resize(n);
    if (n < 5)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header short read {}", log_event::kHandshake, n);
        co_return false;
    }

    if (buf[0] != 0x16)
    {
        LOG_CTX_WARN(ctx, "{} invalid tls header 0x{:02x}", log_event::kHandshake, buf[0]);
        co_return false;
    }
    const std::size_t len = static_cast<std::uint16_t>((buf[3] << 8) | buf[4]);
    while (buf.size() < 5 + len)
    {
        std::vector<std::uint8_t> tmp(5 + len - buf.size());
        const auto [read_ec2, n2] = co_await asio::async_read(*s, asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
        if (read_ec2)
        {
            co_return false;
        }
        buf.insert(buf.end(), tmp.begin(), tmp.end());
    }
    LOG_CTX_DEBUG(ctx, "{} received client hello record size {}", log_event::kHandshake, buf.size());
    co_return true;
}

std::optional<remote_server::selected_key_share> remote_server::select_key_share(const client_hello_info& info, const connection_context& ctx) const
{
    if (info.has_x25519_share && info.x25519_pub.size() == 32)
    {
        selected_key_share sel;
        sel.group = reality::tls_consts::group::kX25519;
        sel.x25519_pub = info.x25519_pub;
        return sel;
    }

    LOG_CTX_ERROR(ctx, "{} no supported key share", log_event::kHandshake);
    return std::nullopt;
}

bool remote_server::authenticate_client(const client_hello_info& info, const std::vector<std::uint8_t>& buf, const connection_context& ctx)
{
    if (!auth_config_valid_)
    {
        LOG_CTX_ERROR(ctx, "{} invalid auth config", log_event::kAuth);
        return false;
    }
    if (!info.is_tls13 || info.session_id.size() != 32)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail is tls13 {} sid len {}", log_event::kAuth, info.is_tls13, info.session_id.size());
        return false;
    }

    const auto selected = select_key_share(info, ctx);
    if (!selected.has_value())
    {
        return false;
    }

    std::error_code ec;
    const auto shared = reality::crypto_util::x25519_derive(private_key_, selected->x25519_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail x25519 derive failed {}", log_event::kAuth, ec.message());
        return false;
    }

    const auto salt = std::vector<std::uint8_t>(info.random.begin(), info.random.begin() + 20);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    const auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    const std::size_t auth_key_len = 16;
    const auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, auth_key_len, EVP_sha256(), ec);
    LOG_CTX_DEBUG(ctx, "auth key derived");

    std::vector<std::uint8_t> aad(buf.begin() + 5, buf.end());
    if (info.sid_offset < 5)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail invalid sid offset {}", log_event::kAuth, info.sid_offset);
        return false;
    }
    const std::uint32_t aad_sid_offset = info.sid_offset - 5;
    if (aad_sid_offset + constants::auth::kSessionIdLen > aad.size())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail aad size mismatch", log_event::kAuth);
        return false;
    }

    std::fill_n(aad.begin() + aad_sid_offset, constants::auth::kSessionIdLen, 0);

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    const auto pt = reality::crypto_util::aead_decrypt(
        auth_cipher, auth_key, std::vector<std::uint8_t>(info.random.begin() + 20, info.random.end()), info.session_id, aad, ec);

    if (ec || pt.size() != 16)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail decrypt failed tag mismatch ec {} pt size {}", log_event::kAuth, ec.message(), pt.size());
        return false;
    }

    const auto auth = reality::parse_auth_payload(pt);
    if (!auth.has_value())
    {
        LOG_CTX_ERROR(ctx, "{} auth fail invalid payload", log_event::kAuth);
        return false;
    }
    if (!short_id_bytes_.empty())
    {
        if (std::vector<std::uint8_t>(auth->short_id.begin(), auth->short_id.begin() + short_id_bytes_.size()) != short_id_bytes_)
        {
            LOG_CTX_WARN(ctx, "{} auth fail short id mismatch", log_event::kAuth);
            return false;
        }
    }

    const std::uint32_t timestamp = auth->timestamp;
    const auto now_tp = std::chrono::system_clock::now();
    const auto ts_tp = std::chrono::system_clock::time_point(std::chrono::seconds(timestamp));
    const auto diff = (now_tp > ts_tp) ? (now_tp - ts_tp) : (ts_tp - now_tp);
    const auto diff_sec = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
    const auto max_diff = std::chrono::seconds(constants::auth::kMaxClockSkewSec);
    if (diff > max_diff)
    {
        LOG_CTX_WARN(ctx, "{} clock skew too large diff {}s", log_event::kAuth, diff_sec);
        return false;
    }

    if (!replay_cache_.check_and_insert(info.session_id))
    {
        LOG_CTX_WARN(ctx, "{} replay attack detected", log_event::kAuth);
        return false;
    }
    return true;
}

asio::awaitable<remote_server::server_handshake_res> remote_server::perform_handshake_response(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                               const client_hello_info& info,
                                                                                               reality::transcript& trans,
                                                                                               const connection_context& ctx,
                                                                                               std::error_code& ec)
{
    const auto key_pair = key_rotator_.get_current_key();
    const std::uint8_t* public_key = key_pair->public_key;
    const std::uint8_t* private_key = key_pair->private_key;
    std::vector<std::uint8_t> srand(32);
    if (RAND_bytes(srand.data(), 32) != 1)
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        co_return server_handshake_res{.ok = false};
    }

    LOG_CTX_TRACE(ctx,
                  "{} generated ephemeral key {}",
                  log_event::kHandshake,
                  reality::crypto_util::bytes_to_hex(std::vector<std::uint8_t>(public_key, public_key + 32)));

    const auto selected = select_key_share(info, ctx);
    if (!selected.has_value())
    {
        ec = asio::error::invalid_argument;
        co_return server_handshake_res{.ok = false};
    }

    const auto x25519_shared =
        reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), selected->x25519_pub, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} x25519 derive failed", log_event::kHandshake);
        co_return server_handshake_res{.ok = false};
    }

    std::vector<std::uint8_t> sh_shared = x25519_shared;
    std::vector<std::uint8_t> key_share_data(public_key, public_key + 32);
    std::uint16_t key_share_group = selected->group;

    std::string cert_sni = info.sni;
    std::string fetch_host = "www.apple.com";
    std::uint16_t fetch_port = 443;

    const auto fb = find_fallback_target_by_sni(info.sni);
    if (!fb.first.empty())
    {
        fetch_host = fb.first;
        auto [ptr, from_ec] = std::from_chars(fb.second.data(), fb.second.data() + fb.second.size(), fetch_port);
        if (from_ec != std::errc())
        {
            LOG_WARN("invalid fallback port {} defaulting to 443", fb.second);
            fetch_port = 443;
        }
        if (cert_sni.empty())
        {
            cert_sni = fb.first;
        }
    }

    std::vector<std::uint8_t> cert_msg;
    reality::server_fingerprint fingerprint;

    const auto cached_entry = cert_manager_.get_certificate(cert_sni);
    if (cached_entry.has_value())
    {
        cert_msg = cached_entry->cert_msg;
        fingerprint = cached_entry->fingerprint;
    }
    else
    {
        LOG_CTX_INFO(ctx, "{} certificate miss fetching {} {}", log_event::kCert, fetch_host, fetch_port);
        const auto res = co_await reality::cert_fetcher::fetch(s->get_executor(), fetch_host, fetch_port, cert_sni, ctx.trace_id());

        if (!res.has_value())
        {
            LOG_CTX_ERROR(ctx, "{} fetch certificate failed", log_event::kCert);
            ec = asio::error::connection_refused;
            co_return server_handshake_res{.ok = false};
        }

        cert_msg = res->cert_msg;
        fingerprint = res->fingerprint;
        cert_manager_.set_certificate(cert_sni, cert_msg, fingerprint, ctx.trace_id());
    }

    std::uint16_t cipher_suite = (fingerprint.cipher_suite != 0) ? fingerprint.cipher_suite : 0x1301;
    if (cipher_suite != 0x1301 && cipher_suite != 0x1302 && cipher_suite != 0x1303)
    {
        cipher_suite = 0x1301;
    }

    const auto sh_msg = reality::construct_server_hello(srand, info.session_id, cipher_suite, key_share_group, key_share_data);
    trans.update(sh_msg);

    const EVP_MD* md = (cipher_suite == 0x1302) ? EVP_sha384() : EVP_sha256();
    trans.set_protocol_hash(md);

    const auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(sh_shared, trans.finish(), md, ec);

    const std::size_t key_len = (cipher_suite == 0x1302) ? 32 : 16;
    constexpr std::size_t iv_len = 12;

    const auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, md);
    const auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, md);

    const auto enc_ext = reality::construct_encrypted_extensions(fingerprint.alpn);
    trans.update(enc_ext);

    trans.update(cert_msg);

    const std::vector<std::uint8_t>& sign_key_bytes = private_key_;
    const reality::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, sign_key_bytes.data(), 32));
    if (sign_key == nullptr)
    {
        LOG_CTX_ERROR(ctx, "{} failed to load private key", log_event::kHandshake);
        ec = asio::error::fault;
        co_return server_handshake_res{.ok = false};
    }

    const auto cv = reality::construct_certificate_verify(sign_key.get(), trans.finish());
    trans.update(cv);

    const auto s_fin_verify =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), md, ec);
    const auto s_fin = reality::construct_finished(s_fin_verify);
    trans.update(s_fin);

    std::vector<std::uint8_t> flight2_plain;
    flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
    flight2_plain.insert(flight2_plain.end(), cert_msg.begin(), cert_msg.end());
    flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
    flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

    const EVP_CIPHER* cipher = nullptr;
    if (cipher_suite == 0x1302)
    {
        cipher = EVP_aes_256_gcm();
    }
    else if (cipher_suite == 0x1303)
    {
        cipher = EVP_chacha20_poly1305();
    }
    else
    {
        cipher = EVP_aes_128_gcm();
    }

    LOG_CTX_INFO(ctx, "generated sh msg size {}", sh_msg.size());
    const auto flight2_enc =
        reality::tls_record_layer::encrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, 0, flight2_plain, reality::kContentTypeHandshake, ec);
    if (ec)
    {
        LOG_CTX_ERROR(ctx, "{} auth fail flight2 encrypt failed {}", log_event::kAuth, ec.message());
        co_return server_handshake_res{.ok = false};
    }

    std::vector<std::uint8_t> out_sh;
    const auto sh_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(sh_msg.size()));
    out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
    out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
    out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
    out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());

    LOG_CTX_INFO(ctx, "total out sh size {}", out_sh.size());
    LOG_CTX_DEBUG(ctx, "{} sending server hello flight size {}", log_event::kHandshake, out_sh.size());
    const auto [we, wn] = co_await asio::async_write(*s, asio::buffer(out_sh), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        ec = we;
        co_return server_handshake_res{.ok = false};
    }

    co_return server_handshake_res{
        .ok = true, .hs_keys = hs_keys, .s_hs_keys = s_hs_keys, .c_hs_keys = c_hs_keys, .cipher = cipher, .negotiated_md = md};
}

asio::awaitable<bool> remote_server::verify_client_finished(std::shared_ptr<asio::ip::tcp::socket> s,
                                                            const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                            const reality::handshake_keys& hs_keys,
                                                            const reality::transcript& trans,
                                                            const EVP_CIPHER* cipher,
                                                            const EVP_MD* md,
                                                            const connection_context& ctx,
                                                            std::error_code& ec)
{
    std::uint8_t h[5];
    const auto [read_ec3, rn3] = co_await asio::async_read(*s, asio::buffer(h, 5), asio::as_tuple(asio::use_awaitable));
    if (read_ec3)
    {
        LOG_CTX_ERROR(ctx, "{} read client finished header error {}", log_event::kHandshake, read_ec3.message());
        co_return false;
    }

    if (h[0] == 0x14)
    {
        std::uint8_t dummy[1];
        co_await asio::async_read(*s, asio::buffer(dummy, 1), asio::as_tuple(asio::use_awaitable));
        co_await asio::async_read(*s, asio::buffer(h, 5), asio::as_tuple(asio::use_awaitable));
    }

    const auto flen = static_cast<std::uint16_t>((h[3] << 8) | h[4]);
    std::vector<std::uint8_t> data(flen);
    const auto [read_ec4, rn4] = co_await asio::async_read(*s, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
    if (read_ec4)
    {
        LOG_CTX_ERROR(ctx, "{} read client finished body error {}", log_event::kHandshake, read_ec4.message());
        co_return false;
    }

    std::vector<std::uint8_t> cth(5 + flen);
    std::memcpy(cth.data(), h, 5);
    std::memcpy(cth.data() + 5, data.data(), flen);
    std::uint8_t ctype = 0;
    const auto pt = reality::tls_record_layer::decrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);

    if (ec || ctype != reality::kContentTypeHandshake || pt.empty() || pt[0] != 0x14)
    {
        LOG_CTX_ERROR(ctx, "{} client finished verification failed type {}", log_event::kHandshake, static_cast<int>(ctype));
        co_return false;
    }

    const auto expected_fin_verify =
        reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), md, ec);
    if (pt.size() < expected_fin_verify.size() + 4 || std::memcmp(pt.data() + 4, expected_fin_verify.data(), expected_fin_verify.size()) != 0)
    {
        LOG_CTX_ERROR(ctx, "{} client finished hmac verification failed", log_event::kHandshake);
        co_return false;
    }
    co_return true;
}

std::pair<std::string, std::string> remote_server::find_fallback_target_by_sni(const std::string& sni) const
{
    if (!sni.empty())
    {
        for (const auto& fb : fallbacks_)
        {
            if (fb.sni == sni)
            {
                return std::make_pair(fb.host, fb.port);
            }
        }
    }

    for (const auto& fb : fallbacks_)
    {
        if (fb.sni.empty() || fb.sni == "*")
        {
            return std::make_pair(fb.host, fb.port);
        }
    }
    if (fallback_dest_valid_)
    {
        return std::make_pair(fallback_dest_host_, fallback_dest_port_);
    }
    return {};
}

asio::awaitable<void> remote_server::fallback_failed_timer(const std::uint32_t conn_id, asio::any_io_executor ex)
{
    asio::steady_timer fallback_timer(ex);
    constexpr std::uint32_t max_wait_ms = constants::fallback::kMaxWaitMs;
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<std::uint32_t> dist(0, max_wait_ms - 1);
    const std::uint32_t wait_ms = dist(gen);
    fallback_timer.expires_after(std::chrono::milliseconds(wait_ms));
    const auto [wait_ec] = co_await fallback_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (wait_ec)
    {
        LOG_ERROR("{} fallback failed timer {} ms error {}", conn_id, wait_ms, wait_ec.message());
    }
    LOG_DEBUG("{} fallback failed timer {} ms", conn_id, wait_ms);
}

asio::awaitable<void> remote_server::fallback_failed(const std::shared_ptr<asio::ip::tcp::socket>& s)
{
    char d[constants::net::kBufferSize] = {0};
    for (;;)
    {
        const auto [read_ec, n] = co_await s->async_read_some(asio::buffer(d), asio::as_tuple(asio::use_awaitable));
        if (read_ec || n == 0)
        {
            break;
        }
    }

    std::error_code ignore;
    ignore = s->shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
}

asio::awaitable<void> remote_server::handle_fallback(const std::shared_ptr<asio::ip::tcp::socket>& s,
                                                     const std::vector<std::uint8_t>& buf,
                                                     const connection_context& ctx,
                                                     const std::string& sni) const
{
    const auto fallback_target = find_fallback_target_by_sni(sni);
    if (fallback_target.first.empty())
    {
        LOG_CTX_INFO(ctx, "{} no target sni {}", log_event::kFallback, sni.empty() ? "empty" : sni);
        using asio::experimental::awaitable_operators::operator||;
        co_await (fallback_failed(s) || fallback_failed_timer(ctx.conn_id(), s->get_executor()));
        std::error_code close_ec;
        close_ec = s->shutdown(asio::ip::tcp::socket::shutdown_both, close_ec);
        if (close_ec && close_ec != asio::error::not_connected)
        {
            LOG_CTX_WARN(ctx, "{} shutdown failed {}", log_event::kFallback, close_ec.message());
        }
        close_ec = s->close(close_ec);
        if (close_ec && close_ec != asio::error::bad_descriptor)
        {
            LOG_CTX_WARN(ctx, "{} close failed {}", log_event::kFallback, close_ec.message());
        }
        LOG_CTX_INFO(ctx, "{} done", log_event::kFallback);
        co_return;
    }

    const auto target_host = fallback_target.first;
    const auto target_port = fallback_target.second;
    auto t = std::make_shared<asio::ip::tcp::socket>(s->get_executor());
    asio::ip::tcp::resolver r(s->get_executor());

    LOG_CTX_INFO(ctx, "{} proxying sni {} to {} {}", log_event::kFallback, sni, target_host, target_port);

    const auto [resolve_ec, eps] = co_await r.async_resolve(target_host, target_port, asio::as_tuple(asio::use_awaitable));
    if (resolve_ec)
    {
        LOG_CTX_WARN(ctx, "{} resolve failed {}", log_event::kFallback, resolve_ec.message());
        co_return;
    }

    const auto [connect_ec, ep_c] = co_await asio::async_connect(*t, eps, asio::as_tuple(asio::use_awaitable));
    if (connect_ec)
    {
        LOG_CTX_WARN(ctx, "{} connect target failed {}", log_event::kFallback, connect_ec.message());
        co_return;
    }

    if (!buf.empty())
    {
        const auto [write_ec, n] = co_await asio::async_write(*t, asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        if (write_ec)
        {
            LOG_CTX_WARN(ctx, "{} write initial buf failed", log_event::kFallback);
            co_return;
        }
    }

    auto proxy_half = [](std::shared_ptr<asio::ip::tcp::socket> from, std::shared_ptr<asio::ip::tcp::socket> to) -> asio::awaitable<void>
    {
        std::vector<std::uint8_t> data(constants::net::kBufferSize);
        for (;;)
        {
            auto [read_ec, n] = co_await from->async_read_some(asio::buffer(data), asio::as_tuple(asio::use_awaitable));
            if (read_ec)
            {
                break;
            }
            auto [write_ec, wn] = co_await asio::async_write(*to, asio::buffer(data, n), asio::as_tuple(asio::use_awaitable));
            if (write_ec)
            {
                break;
            }
        }
        std::error_code ec;
        ec = to->shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    };

    using asio::experimental::awaitable_operators::operator&&;
    co_await (proxy_half(s, t) && proxy_half(t, s));
    LOG_CTX_INFO(ctx, "{} session finished", log_event::kFallback);
}

}    // namespace mux
