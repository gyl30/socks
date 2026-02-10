#include <array>
#include <mutex>
#include <cctype>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <optional>
#include <system_error>

#include <asio/read.hpp>
#include <asio/error.hpp>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/connect.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "log.h"
#include "config.h"
#include "ch_parser.h"
#include "constants.h"
#include "net_utils.h"
#include "transcript.h"
#include "crypto_util.h"
#include "log_context.h"
#include "reality_auth.h"
#include "reality_engine.h"
#include "reality_messages.h"
#include "tls_key_schedule.h"
#include "tls_record_layer.h"
#include "client_tunnel_pool.h"
#include "reality_fingerprint.h"

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

std::string normalize_fingerprint_name(const std::string& input)
{
    std::string out;
    out.reserve(input.size());
    for (const char c : input)
    {
        if (c == '-' || c == ' ')
        {
            out.push_back('_');
            continue;
        }
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool parse_fingerprint_type(const std::string& input, std::optional<reality::fingerprint_type>& out)
{
    out.reset();
    if (input.empty())
    {
        return true;
    }

    const auto name = normalize_fingerprint_name(input);
    if (name == "random")
    {
        return true;
    }

    struct fp_entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const fp_entry kFps[] = {
        {"chrome", reality::fingerprint_type::kChrome120},
        {"chrome_120", reality::fingerprint_type::kChrome120},
        {"firefox", reality::fingerprint_type::kFirefox120},
        {"firefox_120", reality::fingerprint_type::kFirefox120},
        {"ios", reality::fingerprint_type::kIOS14},
        {"ios_14", reality::fingerprint_type::kIOS14},
        {"android", reality::fingerprint_type::kAndroid11OkHttp},
        {"android_11_okhttp", reality::fingerprint_type::kAndroid11OkHttp},
    };

    for (const auto& entry : kFps)
    {
        if (name == entry.name)
        {
            out = entry.type;
            return true;
        }
    }

    return false;
}

std::optional<std::vector<std::uint8_t>> extract_first_cert_der(const std::vector<std::uint8_t>& cert_msg)
{
    if (cert_msg.size() < 4 + 1 + 3 + 3)
    {
        return std::nullopt;
    }
    if (cert_msg[0] != 0x0b)
    {
        return std::nullopt;
    }

    std::size_t pos = 4;
    pos += 1;
    if (pos + 3 > cert_msg.size())
    {
        return std::nullopt;
    }
    const std::uint32_t list_len = (cert_msg[pos] << 16) | (cert_msg[pos + 1] << 8) | cert_msg[pos + 2];
    pos += 3;
    if (pos + list_len > cert_msg.size())
    {
        return std::nullopt;
    }
    if (pos + 3 > cert_msg.size())
    {
        return std::nullopt;
    }
    const std::uint32_t cert_len = (cert_msg[pos] << 16) | (cert_msg[pos + 1] << 8) | cert_msg[pos + 2];
    pos += 3;
    if (pos + cert_len > cert_msg.size())
    {
        return std::nullopt;
    }
    std::vector<std::uint8_t> cert(cert_msg.begin() + static_cast<std::ptrdiff_t>(pos),
                                   cert_msg.begin() + static_cast<std::ptrdiff_t>(pos + cert_len));
    return cert;
}

}    // namespace

client_tunnel_pool::client_tunnel_pool(io_context_pool& pool, const config& cfg, const std::uint32_t mark)
    : mark_(mark),
      remote_host_(cfg.outbound.host),
      remote_port_(std::to_string(cfg.outbound.port)),
      sni_(cfg.reality.sni),
      pool_(pool),
      timeout_config_(cfg.timeout),
      limits_config_(cfg.limits),
      heartbeat_config_(cfg.heartbeat)
{
    server_pub_key_ = reality::crypto_util::hex_to_bytes(cfg.reality.public_key);
    auth_config_valid_ = parse_hex_to_bytes(cfg.reality.short_id, short_id_bytes_, reality::kShortIdMaxLen, "short id");
    if (!parse_fingerprint_type(cfg.reality.fingerprint, fingerprint_type_))
    {
        LOG_ERROR("fingerprint invalid");
        auth_config_valid_ = false;
    }
}

void client_tunnel_pool::start()
{
    if (!auth_config_valid_)
    {
        LOG_ERROR("invalid reality auth config");
        stop_ = true;
        return;
    }

    LOG_INFO("client pool starting target {} port {} with {} connections", remote_host_, remote_port_, limits_config_.max_connections);

    if (limits_config_.max_connections == 0)
    {
        limits_config_.max_connections = 1;
    }
    tunnel_pool_.resize(limits_config_.max_connections);

    for (std::uint32_t i = 0; i < limits_config_.max_connections; ++i)
    {
        asio::co_spawn(
            pool_.get_io_context(),
            [this, i, self = shared_from_this()]() -> asio::awaitable<void> { co_await connect_remote_loop(i); },
            asio::detached);
    }
}

void client_tunnel_pool::stop()
{
    LOG_INFO("client pool stopping closing resources");
    stop_ = true;

    const std::lock_guard<std::mutex> lock(pool_mutex_);
    for (auto& tunnel : tunnel_pool_)
    {
        if (tunnel != nullptr && tunnel->connection() != nullptr)
        {
            tunnel->connection()->stop();
        }
    }
}

std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> client_tunnel_pool::select_tunnel()
{
    std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> selected_tunnel = nullptr;
    const std::lock_guard<std::mutex> lock(pool_mutex_);
    if (tunnel_pool_.empty())
    {
        return nullptr;
    }
    for (std::size_t i = 0; i < tunnel_pool_.size(); ++i)
    {
        const std::uint32_t idx = (next_tunnel_index_ + i) % tunnel_pool_.size();
        const auto tunnel = tunnel_pool_[idx];
        if (tunnel != nullptr && tunnel->connection() != nullptr && tunnel->connection()->is_open())
        {
            selected_tunnel = tunnel;
            next_tunnel_index_ = (idx + 1) % tunnel_pool_.size();
            break;
        }
    }
    return selected_tunnel;
}

std::uint32_t client_tunnel_pool::next_session_id() { return next_session_id_++; }

asio::awaitable<void> client_tunnel_pool::connect_remote_loop(const std::uint32_t index)
{
    while (!stop_)
    {
        const std::uint32_t cid = next_conn_id_++;
        connection_context ctx;
        ctx.new_trace_id();
        ctx.conn_id(cid);
        LOG_CTX_INFO(ctx,
                     "{} initiating connection {}/{} to {} {}",
                     log_event::kConnInit,
                     index + 1,
                     limits_config_.max_connections,
                     remote_host_,
                     remote_port_);

        std::error_code ec;
        const auto socket = std::make_shared<asio::ip::tcp::socket>(pool_.get_io_context());

        if (!co_await tcp_connect(*socket, ec))
        {
            LOG_ERROR("connect failed {} retry in {}s", ec.message(), constants::net::kRetryIntervalSec);
            co_await wait_remote_retry();
            continue;
        }

        auto [handshake_success, handshake_ret] = co_await perform_reality_handshake(*socket, ec);
        if (!handshake_success)
        {
            LOG_ERROR("handshake failed {} retry in {}s", ec.message(), constants::net::kRetryIntervalSec);
            co_await wait_remote_retry();
            continue;
        }

        const std::size_t key_len = (handshake_ret.cipher_suite == 0x1302 || handshake_ret.cipher_suite == 0x1303) ? constants::crypto::kKeyLen256
                                                                                                                   : constants::crypto::kKeyLen128;

        const auto c_app_keys =
            reality::tls_key_schedule::derive_traffic_keys(handshake_ret.c_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);
        const auto s_app_keys =
            reality::tls_key_schedule::derive_traffic_keys(handshake_ret.s_app_secret, ec, key_len, constants::crypto::kIvLen, handshake_ret.md);

        LOG_CTX_INFO(ctx, "{} handshake success cipher 0x{:04x}", log_event::kHandshake, handshake_ret.cipher_suite);
        reality_engine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second, handshake_ret.cipher);

        auto tunnel = std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(
            std::move(*socket), std::move(re), true, cid, ctx.trace_id(), timeout_config_, limits_config_, heartbeat_config_);

        {
            const std::lock_guard<std::mutex> lock(pool_mutex_);
            tunnel_pool_[index] = tunnel;
        }

        co_await tunnel->run();

        {
            const std::lock_guard<std::mutex> lock(pool_mutex_);
            tunnel_pool_[index] = nullptr;
        }

        co_await wait_remote_retry();
    }
    LOG_INFO("{} connect remote loop {} exited", log_event::kConnClose, index);
}

asio::awaitable<bool> client_tunnel_pool::tcp_connect(asio::ip::tcp::socket& socket, std::error_code& ec) const
{
    asio::ip::tcp::resolver res(pool_.get_io_context());
    auto [resolve_error, resolve_endpoints] = co_await res.async_resolve(remote_host_, remote_port_, asio::as_tuple(asio::use_awaitable));
    if (resolve_error)
    {
        ec = resolve_error;
        LOG_ERROR("resolve {} failed {}", remote_host_, resolve_error.message());
        co_return false;
    }

    for (const auto& entry : resolve_endpoints)
    {
        std::error_code open_ec;
        if (socket.is_open())
        {
            socket.close(open_ec);
        }
        open_ec = socket.open(entry.endpoint().protocol(), open_ec);
        if (open_ec)
        {
            ec = open_ec;
            continue;
        }
        if (mark_ != 0)
        {
            std::error_code mark_ec;
            if (!net::set_socket_mark(socket.native_handle(), mark_, mark_ec))
            {
                LOG_WARN("set mark failed {}", mark_ec.message());
            }
        }

        auto [conn_error] = co_await socket.async_connect(entry.endpoint(), asio::as_tuple(asio::use_awaitable));
        if (conn_error)
        {
            ec = conn_error;
            continue;
        }

        ec = socket.set_option(asio::ip::tcp::no_delay(true), ec);
        if (ec)
        {
            LOG_WARN("set no delay failed {}", ec.message());
        }
        LOG_DEBUG("tcp connected {} <-> {}", socket.local_endpoint().address().to_string(), entry.endpoint().address().to_string());
        co_return true;
    }

    if (!ec)
    {
        ec = std::make_error_code(std::errc::host_unreachable);
    }
    LOG_ERROR("connect {} failed {}", remote_host_, ec.message());
    co_return false;
}

asio::awaitable<std::pair<bool, client_tunnel_pool::handshake_result>> client_tunnel_pool::perform_reality_handshake(asio::ip::tcp::socket& socket,
                                                                                                                     std::error_code& ec) const
{
    std::uint8_t public_key[32];
    std::uint8_t private_key[32];

    if (!reality::crypto_util::generate_x25519_keypair(public_key, private_key))
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        co_return std::make_pair(false, handshake_result{});
    }

    const std::shared_ptr<void> defer_cleanse(nullptr, [&](void*) { OPENSSL_cleanse(private_key, 32); });

    reality::fingerprint_spec spec;
    if (fingerprint_type_.has_value())
    {
        spec = reality::fingerprint_factory::get(*fingerprint_type_);
    }
    else
    {
        static const std::vector<reality::fingerprint_type> fp_types = {
            reality::fingerprint_type::kChrome120,
            reality::fingerprint_type::kFirefox120,
            reality::fingerprint_type::kIOS14,
            reality::fingerprint_type::kAndroid11OkHttp,
        };
        const auto& candidates = fp_types;
        static thread_local std::mt19937 fp_gen(std::random_device{}());
        std::uniform_int_distribution<std::size_t> fp_dist(0, candidates.size() - 1);
        spec = reality::fingerprint_factory::get(candidates[fp_dist(fp_gen)]);
    }

    reality::transcript trans;
    if (!co_await generate_and_send_client_hello(socket, public_key, private_key, spec, trans, ec))
    {
        co_return std::make_pair(false, handshake_result{});
    }

    const auto sh_res = co_await process_server_hello(socket, private_key, trans, ec);
    if (!sh_res.ok)
    {
        co_return std::make_pair(false, handshake_result{});
    }

    const std::size_t key_len =
        (sh_res.cipher_suite == 0x1302 || sh_res.cipher_suite == 0x1303) ? constants::crypto::kKeyLen256 : constants::crypto::kKeyLen128;
    constexpr std::size_t iv_len = constants::crypto::kIvLen;

    const auto c_hs_keys =
        reality::tls_key_schedule::derive_traffic_keys(sh_res.hs_keys.client_handshake_traffic_secret, ec, key_len, iv_len, sh_res.negotiated_md);
    const auto s_hs_keys =
        reality::tls_key_schedule::derive_traffic_keys(sh_res.hs_keys.server_handshake_traffic_secret, ec, key_len, iv_len, sh_res.negotiated_md);

    auto [loop_ok, app_sec] =
        co_await handshake_read_loop(socket, s_hs_keys, sh_res.hs_keys, trans, sh_res.negotiated_cipher, sh_res.negotiated_md, ec);
    if (!loop_ok)
    {
        co_return std::make_pair(false, handshake_result{});
    }

    if (!co_await send_client_finished(
            socket, c_hs_keys, sh_res.hs_keys.client_handshake_traffic_secret, trans, sh_res.negotiated_cipher, sh_res.negotiated_md, ec))
    {
        co_return std::make_pair(false, handshake_result{});
    }

    co_return std::make_pair(true,
                             handshake_result{.c_app_secret = app_sec.first,
                                              .s_app_secret = app_sec.second,
                                              .cipher_suite = sh_res.cipher_suite,
                                              .md = sh_res.negotiated_md,
                                              .cipher = sh_res.negotiated_cipher});
}

asio::awaitable<bool> client_tunnel_pool::generate_and_send_client_hello(asio::ip::tcp::socket& socket,
                                                                         const std::uint8_t* public_key,
                                                                         const std::uint8_t* private_key,
                                                                         const reality::fingerprint_spec& spec,
                                                                         reality::transcript& trans,
                                                                         std::error_code& ec) const
{
    const auto shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), server_pub_key_, ec);
    LOG_DEBUG("using server pub key size {}", server_pub_key_.size());
    if (ec)
    {
        co_return false;
    }

    std::vector<std::uint8_t> client_random(32);
    if (RAND_bytes(client_random.data(), 32) != 1)
    {
        ec = std::make_error_code(std::errc::operation_canceled);
        co_return false;
    }
    const std::vector<std::uint8_t> salt(client_random.begin(), client_random.begin() + constants::auth::kSaltLen);
    const auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
    const auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
    const std::size_t auth_key_len = 16;
    const auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, auth_key_len, EVP_sha256(), ec);

    LOG_DEBUG("client auth material ready random {} bytes eph pub {} bytes", client_random.size(), 32);
    const std::uint32_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<std::uint8_t, reality::kAuthPayloadLen> payload{};
    if (!reality::build_auth_payload(short_id_bytes_, client_ver_, now, payload))
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        co_return false;
    }

    const std::vector<std::uint8_t> placeholder_session_id(32, 0);
    auto hello_body = reality::client_hello_builder::build(
        spec, placeholder_session_id, client_random, std::vector<std::uint8_t>(public_key, public_key + 32), sni_);

    std::vector<std::uint8_t> dummy_record =
        reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(hello_body.size()));
    dummy_record.insert(dummy_record.end(), hello_body.begin(), hello_body.end());

    client_hello_info ch_info = ch_parser::parse(dummy_record);
    if (ch_info.sid_offset < 5)
    {
        LOG_ERROR("generated client hello session id offset is invalid: {}", ch_info.sid_offset);
        co_return false;
    }

    const std::uint32_t absolute_sid_offset = ch_info.sid_offset - 5;
    if (absolute_sid_offset + 32 > hello_body.size())
    {
        LOG_ERROR("session id offset out of bounds: {} / {}", absolute_sid_offset, hello_body.size());
        co_return false;
    }

    const EVP_CIPHER* auth_cipher = EVP_aes_128_gcm();
    const auto sid =
        reality::crypto_util::aead_encrypt(auth_cipher,
                                           auth_key,
                                           std::vector<std::uint8_t>(client_random.begin() + constants::auth::kSaltLen, client_random.end()),
                                           std::vector<std::uint8_t>(payload.begin(), payload.end()),
                                           hello_body,
                                           ec);

    if (ec || sid.size() != 32)
    {
        LOG_ERROR("auth encryption failed ct size {}", sid.size());
        co_return false;
    }

    std::memcpy(hello_body.data() + absolute_sid_offset, sid.data(), 32);

    const std::vector<std::uint8_t> ch = hello_body;
    auto ch_rec = reality::write_record_header(reality::kContentTypeHandshake, static_cast<std::uint16_t>(ch.size()));
    ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());

    auto [we, wn] = co_await asio::async_write(socket, asio::buffer(ch_rec), asio::as_tuple(asio::use_awaitable));
    if (we)
    {
        ec = we;
        LOG_ERROR("error sending client hello {}", ec.message());
        co_return false;
    }
    LOG_DEBUG("sending client hello record size {}", ch_rec.size());
    trans.update(ch);
    co_return true;
}

asio::awaitable<client_tunnel_pool::server_hello_res> client_tunnel_pool::process_server_hello(asio::ip::tcp::socket& socket,
                                                                                               const std::uint8_t* private_key,
                                                                                               reality::transcript& trans,
                                                                                               std::error_code& ec)
{
    std::uint8_t data[5];
    auto [re1, rn1] = co_await asio::async_read(socket, asio::buffer(data, 5), asio::as_tuple(asio::use_awaitable));
    if (re1)
    {
        ec = re1;
        LOG_ERROR("error reading server hello {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    const auto sh_len = static_cast<std::uint16_t>((data[3] << 8) | data[4]);
    std::vector<std::uint8_t> sh_data(sh_len);
    auto [re2, rn2] = co_await asio::async_read(socket, asio::buffer(sh_data), asio::as_tuple(asio::use_awaitable));
    if (re2)
    {
        ec = re2;
        LOG_ERROR("error reading server hello data {}", ec.message());
        co_return server_hello_res{.ok = false};
    }
    LOG_DEBUG("server hello received size {}", sh_len);

    trans.update(sh_data);

    std::size_t pos = 4 + 2 + 32;
    if (pos >= sh_data.size())
    {
        ec = asio::error::fault;
        LOG_ERROR("bad server hello {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    const std::uint8_t sid_len = sh_data[pos];
    pos += 1 + sid_len;

    if (pos + 2 > sh_data.size())
    {
        ec = asio::error::fault;
        LOG_ERROR("bad server hello session data {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    const std::uint16_t cipher_suite = (sh_data[pos] << 8) | sh_data[pos + 1];

    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    if (cipher_suite == 0x1302)
    {
        md = EVP_sha384();
        cipher = EVP_aes_256_gcm();
        LOG_DEBUG("cipher suite 1302 used sha384 cipher aes 256 gcm");
    }
    else if (cipher_suite == 0x1303)
    {
        md = EVP_sha256();
        cipher = EVP_chacha20_poly1305();
        LOG_DEBUG("cipher suite 1303 used sha256 cipher chacha20 poly1305");
    }
    else
    {
        md = EVP_sha256();
        cipher = EVP_aes_128_gcm();
        LOG_DEBUG("cipher suite not found used sha256 cipher aes 128 gcm");
    }

    trans.set_protocol_hash(md);

    const auto key_share = reality::extract_server_key_share(sh_data);
    LOG_DEBUG("rx server hello size {}", sh_data.size());
    if (!key_share.has_value())
    {
        ec = asio::error::invalid_argument;
        LOG_ERROR("bad server hello key share {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    std::vector<std::uint8_t> hs_shared;
    if (key_share->group == reality::tls_consts::group::kX25519)
    {
        if (key_share->data.size() != 32)
        {
            ec = asio::error::invalid_argument;
            LOG_ERROR("invalid x25519 key share length {}", key_share->data.size());
            co_return server_hello_res{.ok = false};
        }
        hs_shared = reality::crypto_util::x25519_derive(std::vector<std::uint8_t>(private_key, private_key + 32), key_share->data, ec);
    }
    else
    {
        ec = asio::error::no_protocol_option;
        LOG_ERROR("unsupported key share group {}", key_share->group);
        co_return server_hello_res{.ok = false};
    }

    if (ec)
    {
        LOG_ERROR("handshake shared secret failed {}", ec.message());
        co_return server_hello_res{.ok = false};
    }

    auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(hs_shared, trans.finish(), md, ec);

    co_return server_hello_res{.ok = true, .hs_keys = hs_keys, .negotiated_md = md, .negotiated_cipher = cipher, .cipher_suite = cipher_suite};
}

asio::awaitable<std::pair<bool, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>>> client_tunnel_pool::handshake_read_loop(
    asio::ip::tcp::socket& socket,
    const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& s_hs_keys,
    const reality::handshake_keys& hs_keys,
    reality::transcript& trans,
    const EVP_CIPHER* cipher,
    const EVP_MD* md,
    std::error_code& ec)
{
    bool handshake_fin = false;
    bool cert_checked = false;
    std::uint64_t seq = 0;
    std::vector<std::uint8_t> handshake_buffer;

    while (!handshake_fin)
    {
        std::uint8_t rh[5];
        auto [re3, rn3] = co_await asio::async_read(socket, asio::buffer(rh, 5), asio::as_tuple(asio::use_awaitable));
        if (re3)
        {
            ec = re3;
            LOG_ERROR("error reading record header {}", ec.message());
            co_return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
        }
        const auto n = static_cast<std::uint16_t>((rh[3] << 8) | rh[4]);
        std::vector<std::uint8_t> rec(n);
        auto [re4, rn4] = co_await asio::async_read(socket, asio::buffer(rec), asio::as_tuple(asio::use_awaitable));
        if (re4)
        {
            ec = re4;
            LOG_ERROR("error reading record payload {}", ec.message());
            co_return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
        }
        if (rn4 != n)
        {
            ec = asio::error::fault;
            LOG_ERROR("short read record payload {} of {}", rn4, n);
            co_return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
        }

        if (rh[0] == reality::kContentTypeChangeCipherSpec)
        {
            LOG_DEBUG("received change cipher spec skip");
            continue;
        }

        std::vector<std::uint8_t> cth(5 + n);
        std::memcpy(cth.data(), rh, 5);
        std::memcpy(cth.data() + 5, rec.data(), n);
        std::uint8_t type = 0;
        const auto pt = reality::tls_record_layer::decrypt_record(cipher, s_hs_keys.first, s_hs_keys.second, seq++, cth, type, ec);
        if (ec)
        {
            LOG_ERROR("error decrypting record {}", ec.message());
            co_return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
        }

        if (type == reality::kContentTypeHandshake)
        {
            handshake_buffer.insert(handshake_buffer.end(), pt.begin(), pt.end());
            std::uint32_t offset = 0;
            while (offset + 4 <= handshake_buffer.size())
            {
                const std::uint8_t msg_type = handshake_buffer[offset];
                const std::uint32_t msg_len =
                    (handshake_buffer[offset + 1] << 16) | (handshake_buffer[offset + 2] << 8) | handshake_buffer[offset + 3];
                if (offset + 4 + msg_len > handshake_buffer.size())
                {
                    break;
                }

                const std::vector<std::uint8_t> msg_data(handshake_buffer.begin() + offset, handshake_buffer.begin() + offset + 4 + msg_len);

                if (msg_type == 0x0b)
                {
                    LOG_DEBUG("received certificate message size {}", msg_data.size());
                    if (!cert_checked)
                    {
                        cert_checked = true;
                        auto cert_der = extract_first_cert_der(msg_data);
                        if (!cert_der.has_value())
                        {
                            ec = asio::error::invalid_argument;
                            LOG_ERROR("certificate message parse failed");
                            co_return std::make_pair(false, std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>{});
                        }
                    }
                }
                trans.update(msg_data);
                if (msg_type == 0x14)
                {
                    handshake_fin = true;
                }
                offset += 4 + msg_len;
            }
            handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + offset);
        }
    }

    const auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), md, ec);
    co_return std::make_pair(true, app_sec);
}

asio::awaitable<bool> client_tunnel_pool::send_client_finished(asio::ip::tcp::socket& socket,
                                                               const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>& c_hs_keys,
                                                               const std::vector<std::uint8_t>& c_hs_secret,
                                                               const reality::transcript& trans,
                                                               const EVP_CIPHER* cipher,
                                                               const EVP_MD* md,
                                                               std::error_code& ec)
{
    const auto fin_verify = reality::tls_key_schedule::compute_finished_verify_data(c_hs_secret, trans.finish(), md, ec);
    const auto fin_msg = reality::construct_finished(fin_verify);
    const auto fin_rec =
        reality::tls_record_layer::encrypt_record(cipher, c_hs_keys.first, c_hs_keys.second, 0, fin_msg, reality::kContentTypeHandshake, ec);

    std::vector<std::uint8_t> out_flight = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    out_flight.insert(out_flight.end(), fin_rec.begin(), fin_rec.end());

    auto [write_error, write_len] = co_await asio::async_write(socket, asio::buffer(out_flight), asio::as_tuple(asio::use_awaitable));
    if (write_error)
    {
        ec = write_error;
        LOG_ERROR("send client finished flight error {}", ec.message());
        co_return false;
    }
    LOG_DEBUG("sending client finished flight size {}", out_flight.size());
    co_return true;
}

asio::awaitable<void> client_tunnel_pool::wait_remote_retry()
{
    if (stop_)
    {
        co_return;
    }
    asio::steady_timer retry_timer(pool_.get_io_context());
    retry_timer.expires_after(std::chrono::seconds(constants::net::kRetryIntervalSec));
    const auto [ec] = co_await retry_timer.async_wait(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        LOG_ERROR("remote retry timer error {}", ec.message());
    }
}

}    // namespace mux
