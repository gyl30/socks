#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <vector>
#include <mutex>

#include "config.h"
#include "protocol.h"
#include "ch_parser.h"
#include "mux_tunnel.h"
#include "transcript.h"
#include "key_rotator.h"
#include "replay_cache.h"
#include "cert_fetcher.h"
#include "cert_manager.h"
#include "context_pool.h"
#include "remote_session.h"
#include "tls_record_layer.h"
#include "tls_key_schedule.h"
#include "reality_messages.h"
#include "remote_udp_session.h"

namespace mux
{
class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool &pool, uint16_t port, std::vector<config::fallback_entry> fbs, const std::string &key)
        : pool_(pool), acceptor_(pool.get_io_context(), asio::ip::tcp::endpoint(asio::ip::tcp::v6(), port)), fallbacks_(std::move(fbs))
    {
        private_key_ = reality::crypto_util::hex_to_bytes(key);
        std::error_code ignore;
        auto pub = reality::crypto_util::extract_public_key(private_key_, ignore);
        LOG_INFO("server public key {}", reality::crypto_util::bytes_to_hex(pub));
    }

    void start() { asio::co_spawn(acceptor_.get_executor(), accept_loop(), asio::detached); }

    void stop()
    {
        LOG_INFO("remote server stopping");
        std::error_code ignore;
        ignore = acceptor_.close(ignore);
        (void)ignore;

        const std::scoped_lock lock(tunnels_mutex_);
        for (auto &weak_tunnel : active_tunnels_)
        {
            if (auto tunnel = weak_tunnel.lock())
            {
                if (tunnel->get_connection())
                {
                    tunnel->get_connection()->stop();
                }
            }
        }
        active_tunnels_.clear();
    }

   private:
    asio::awaitable<void> accept_loop()
    {
        LOG_INFO("remote server listening for connections");
        for (;;)
        {
            auto s = std::make_shared<asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [e] = co_await acceptor_.async_accept(*s, asio::as_tuple(asio::use_awaitable));
            if (!e)
            {
                std::error_code ec;
                ec = s->set_option(asio::ip::tcp::no_delay(true), ec);
                (void)ec;
                const uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);

                asio::co_spawn(
                    pool_.get_io_context(), [this, s, self = shared_from_this(), conn_id = conn_id]() { return handle(s, conn_id); }, asio::detached);
            }
            else
            {
                if (e == asio::error::operation_aborted)
                {
                    LOG_INFO("acceptor closed, stopping loop");
                    break;
                }
                LOG_WARN("accept error {}", e.message());
            }
        }
    }

    asio::awaitable<void> handle(std::shared_ptr<asio::ip::tcp::socket> s, uint32_t conn_id)
    {
        auto [ok, buf] = co_await read_initial_and_validate(s, conn_id);

        std::string client_sni;
        client_hello_info_t info;
        if (!buf.empty())
        {
            info = ch_parser::parse(buf);
            client_sni = info.sni;
        }

        if (!ok)
        {
            co_await handle_fallback(s, buf, conn_id, client_sni);
            co_return;
        }

        auto [auth_ok, auth_key] = authenticate_client(info, buf, conn_id);
        LOG_INFO("authkey {}", reality::crypto_util::bytes_to_hex(auth_key));
        if (!auth_ok)
        {
            co_await handle_fallback(s, buf, conn_id, client_sni);
            co_return;
        }

        LOG_INFO("srv {} authorized proceeding sni {}", conn_id, info.sni);
        reality::transcript trans;

        if (buf.size() > 5)
        {
            trans.update(std::vector<uint8_t>(buf.begin() + 5, buf.end()));
        }
        else
        {
            LOG_ERROR("srv {} buffer too short for transcript", conn_id);
            co_return;
        }

        std::error_code ec;
        auto [handshake_ok, hs_keys, s_hs_keys, c_hs_keys] = co_await perform_handshake_response(s, info, trans, auth_key, conn_id, ec);

        if (!handshake_ok)
        {
            LOG_ERROR("srv {} handshake response error {}", conn_id, ec.message());
            co_return;
        }

        if (!co_await verify_client_finished(s, c_hs_keys, hs_keys, trans, conn_id, ec))
        {
            co_return;
        }

        auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), EVP_sha256(), ec);
        auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("srv {} tunnel start", conn_id);
        reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);
        auto tunnel = std::make_shared<mux_tunnel_impl<asio::ip::tcp::socket>>(std::move(*s), std::move(engine), false, conn_id);

        {
            const std::scoped_lock lock(tunnels_mutex_);
            std::erase_if(active_tunnels_, [](const auto &wp) { return wp.expired(); });
            active_tunnels_.push_back(tunnel);
        }

        tunnel->get_connection()->set_syn_callback(
            [this, tunnel, conn_id](uint32_t id, const std::vector<uint8_t> &p)
            {
                asio::co_spawn(
                    pool_.get_io_context(),
                    [this, tunnel, conn_id, id, p = p]() { return process_stream_request(tunnel, conn_id, id, p); },
                    asio::detached);
            });

        co_await tunnel->run();
    }

    asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<asio::ip::tcp::socket>> tunnel,
                                                 uint32_t conn_id,
                                                 uint32_t stream_id,
                                                 std::vector<uint8_t> payload) const
    {
        syn_payload syn;
        if (!mux_codec::decode_syn(payload.data(), payload.size(), syn))
        {
            LOG_WARN("srv {} stream {} invalid syn", conn_id, stream_id);
            co_return;
        }
        if (syn.socks_cmd == socks::CMD_CONNECT)
        {
            LOG_INFO("srv {} stream {} type TCP_CONNECT target {}:{}", conn_id, stream_id, syn.addr, syn.port);
            auto sess = std::make_shared<remote_session>(tunnel->get_connection(), stream_id, pool_.get_io_context().get_executor());
            sess->set_manager(tunnel);
            tunnel->register_stream(stream_id, sess);
            co_await sess->start(payload);
        }
        else if (syn.socks_cmd == socks::CMD_UDP_ASSOCIATE)
        {
            LOG_INFO("srv {} stream {} type UDP_ASSOCIATE associated via tcp", conn_id, stream_id);
            auto sess = std::make_shared<remote_udp_session>(tunnel->get_connection(), stream_id, pool_.get_io_context().get_executor());
            sess->set_manager(tunnel);
            tunnel->register_stream(stream_id, sess);
            co_await sess->start();
        }
        else
        {
            LOG_WARN("srv {} stream {} unknown cmd {}", conn_id, stream_id, syn.socks_cmd);
        }
    }

    static asio::awaitable<std::pair<bool, std::vector<uint8_t>>> read_initial_and_validate(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                                            uint32_t conn_id)
    {
        std::vector<uint8_t> buf(4096);
        auto [re, n] = co_await s->async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
        if (re)
        {
            LOG_ERROR("srv {} initial read error {}", conn_id, re.message());
            co_return std::make_pair(false, std::vector<uint8_t>{});
        }
        buf.resize(n);
        if (n < 5 || buf[0] != 0x16)
        {
            LOG_WARN("srv {} invalid tls header 0x{:02x}", conn_id, buf[0]);
            co_return std::make_pair(false, buf);
        }
        const size_t len = static_cast<uint16_t>((buf[3] << 8) | buf[4]);
        while (buf.size() < 5 + len)
        {
            std::vector<uint8_t> tmp(5 + len - buf.size());
            auto [re2, n2] = co_await asio::async_read(*s, asio::buffer(tmp), asio::as_tuple(asio::use_awaitable));
            if (re2)
            {
                co_return std::make_pair(false, buf);
            }
            buf.insert(buf.end(), tmp.begin(), tmp.end());
        }
        LOG_DEBUG("srv {} received client hello record size {}", conn_id, buf.size());
        co_return std::make_pair(true, buf);
    }

    std::pair<bool, std::vector<uint8_t>> authenticate_client(const client_hello_info_t &info, const std::vector<uint8_t> &buf, uint32_t conn_id)
    {
        if (!info.is_tls13 || info.session_id.size() != 32)
        {
            return {false, {}};
        }

        std::error_code ec;
        auto shared = reality::crypto_util::x25519_derive(private_key_, info.x25519_pub, ec);
        if (ec)
        {
            return {false, {}};
        }

        auto salt = std::vector<uint8_t>(info.random.begin(), info.random.begin() + 20);
        auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, EVP_sha256(), ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 32, EVP_sha256(), ec);

        auto aad = std::vector<uint8_t>(buf.begin() + 5, buf.end());
        if (info.sid_offset < 5)
        {
            return {false, {}};
        }
        const uint32_t aad_sid_offset = info.sid_offset - 5;
        if (aad_sid_offset + 32 > aad.size())
        {
            return {false, {}};
        }

        std::fill_n(aad.begin() + aad_sid_offset, 32, 0);

        auto pt = reality::crypto_util::aead_decrypt(
            EVP_aes_128_gcm(), auth_key, std::vector<uint8_t>(info.random.begin() + 20, info.random.end()), info.session_id, aad, ec);

        if (ec || pt.size() != 16)
        {
            return {false, {}};
        }

        if (!replay_cache_.check_and_insert(info.session_id))
        {
            LOG_WARN("srv {} replay attack detected for sid", conn_id);
            return {false, {}};
        }

        const uint32_t timestamp = (static_cast<uint32_t>(pt[4]) << 24) | (static_cast<uint32_t>(pt[5]) << 16) | (static_cast<uint32_t>(pt[6]) << 8) |
                                   static_cast<uint32_t>(pt[7]);
        auto now = static_cast<uint32_t>(time(nullptr));
        if (timestamp > now + 300 || timestamp < now - 300)
        {
            LOG_WARN("srv {} auth failed clock skew too large diff {}s", conn_id, (int)now - (int)timestamp);
            return {false, {}};
        }
        return {true, auth_key};
    }

    struct server_handshake_res
    {
        bool ok;
        reality::handshake_keys hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> s_hs_keys;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> c_hs_keys;
    };
    asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<asio::ip::tcp::socket> s,
                                                                     const client_hello_info_t &info,
                                                                     reality::transcript &trans,
                                                                     const std::vector<uint8_t> &auth_key,
                                                                     uint32_t conn_id,
                                                                     std::error_code &ec)
    {
        auto key_pair = key_rotator_.get_current_key();
        const uint8_t *public_key = key_pair->public_key;
        const uint8_t *private_key = key_pair->private_key;
        std::vector<uint8_t> srand(32);
        RAND_bytes(srand.data(), 32);

        LOG_TRACE(
            "srv {} generated ephemeral key {}", conn_id, reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(public_key, public_key + 32)));

        auto sh_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), info.x25519_pub, ec);
        if (ec)
        {
            LOG_ERROR("srv {} x25519 derive failed", conn_id);
            co_return server_handshake_res{.ok = false};
        }

        auto sh_msg = reality::construct_server_hello(srand, info.session_id, 0x1301, std::vector<uint8_t>(public_key, public_key + 32));
        trans.update(sh_msg);

        auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(sh_shared, trans.finish(), EVP_sha256(), ec);
        auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        auto enc_ext = reality::construct_encrypted_extensions();
        trans.update(enc_ext);

        std::string cert_sni = info.sni;
        std::string fetch_host = "www.apple.com";
        uint16_t fetch_port = 443;

        auto fb = find_fallback_target_by_sni(info.sni);
        if (!fb.first.empty())
        {
            fetch_host = fb.first;
            fetch_port = std::stoi(fb.second);
            if (cert_sni.empty())
            {
                cert_sni = fb.first;
            }
        }

        std::vector<uint8_t> cert_msg;

        auto cached = cert_manager_.get_certificate(cert_sni);
        if (cached)
        {
            cert_msg = *cached;
        }
        else
        {
            LOG_INFO("srv {} certificate miss for {}, fetching from {}:{}", conn_id, cert_sni, fetch_host, fetch_port);
            try
            {
                cert_msg = co_await reality::cert_fetcher::fetch(s->get_executor(), fetch_host, fetch_port, cert_sni);
            }
            catch (std::exception &e)
            {
                LOG_ERROR("srv {} fetch cert exception {}", conn_id, e.what());
            }

            if (cert_msg.empty())
            {
                LOG_ERROR("srv {} failed to fetch certificate", conn_id);

                ec = asio::error::connection_refused;
                co_return server_handshake_res{.ok = false};
            }

            cert_manager_.set_certificate(cert_sni, cert_msg);
        }

        trans.update(cert_msg);

        const reality::openssl_ptrs::evp_pkey_ptr sign_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key_.data(), 32));
        if (!sign_key)
        {
            LOG_ERROR("srv {} failed to load reality private key for signing", conn_id);
            ec = asio::error::fault;
            co_return server_handshake_res{.ok = false};
        }

        auto cv = reality::construct_certificate_verify(sign_key.get(), trans.finish());
        trans.update(cv);

        auto s_fin_verify =
            reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), EVP_sha256(), ec);
        auto s_fin = reality::construct_finished(s_fin_verify);
        trans.update(s_fin);

        std::vector<uint8_t> flight2_plain;
        flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
        flight2_plain.insert(flight2_plain.end(), cert_msg.begin(), cert_msg.end());
        flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
        flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

        auto flight2_enc = reality::tls_record_layer::encrypt_record(
            EVP_aes_128_gcm(), s_hs_keys.first, s_hs_keys.second, 0, flight2_plain, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out_sh;
        auto sh_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(sh_msg.size()));
        out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
        out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
        out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
        out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());

        LOG_DEBUG("srv {} sending server hello flight size {}", conn_id, out_sh.size());
        auto [we, wn] = co_await asio::async_write(*s, asio::buffer(out_sh), asio::as_tuple(asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return server_handshake_res{.ok = false};
        }

        co_return server_handshake_res{.ok = true, .hs_keys = hs_keys, .s_hs_keys = s_hs_keys, .c_hs_keys = c_hs_keys};
    }

    static asio::awaitable<bool> verify_client_finished(std::shared_ptr<asio::ip::tcp::socket> s,
                                                        const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                        const reality::handshake_keys &hs_keys,
                                                        const reality::transcript &trans,
                                                        uint32_t conn_id,
                                                        std::error_code &ec)
    {
        uint8_t h[5];
        auto [re3, rn3] = co_await asio::async_read(*s, asio::buffer(h, 5), asio::as_tuple(asio::use_awaitable));
        if (re3)
        {
            LOG_ERROR("srv {} read client finished header error {}", conn_id, re3.message());
            co_return false;
        }

        if (h[0] == 0x14)
        {
            uint8_t dummy[1];
            co_await asio::async_read(*s, asio::buffer(dummy, 1), asio::as_tuple(asio::use_awaitable));
            co_await asio::async_read(*s, asio::buffer(h, 5), asio::as_tuple(asio::use_awaitable));
        }

        auto flen = static_cast<uint16_t>((h[3] << 8) | h[4]);
        std::vector<uint8_t> data(flen);
        auto [re4, rn4] = co_await asio::async_read(*s, asio::buffer(data), asio::as_tuple(asio::use_awaitable));
        if (re4)
        {
            LOG_ERROR("srv {} read client finished body error {}", conn_id, re4.message());
            co_return false;
        }

        std::vector<uint8_t> cth(5 + flen);
        std::memcpy(cth.data(), h, 5);
        std::memcpy(cth.data() + 5, data.data(), flen);
        uint8_t ctype;
        auto pt = reality::tls_record_layer::decrypt_record(EVP_aes_128_gcm(), c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);

        if (ec || ctype != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("srv {} client finished verification failed type {}", conn_id, static_cast<int>(ctype));
            co_return false;
        }

        auto expected_fin_verify =
            reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), EVP_sha256(), ec);
        if (pt.size() < expected_fin_verify.size() + 4 || std::memcmp(pt.data() + 4, expected_fin_verify.data(), expected_fin_verify.size()) != 0)
        {
            LOG_ERROR("srv {} client finished hmac verification failed", conn_id);
            co_return false;
        }
        co_return true;
    }
    std::pair<std::string, std::string> find_fallback_target_by_sni(const std::string &sni) const
    {
        if (!sni.empty())
        {
            for (const auto &fb : fallbacks_)
            {
                if (fb.sni == sni)
                {
                    return std::make_pair(fb.host, fb.port);
                }
            }
        }

        for (const auto &fb : fallbacks_)
        {
            if (fb.sni.empty() || fb.sni == "*")
            {
                return std::make_pair(fb.host, fb.port);
            }
        }
        return {};
    }
    static asio::awaitable<void> fallback_failed_timer(uint32_t conn_id, asio::any_io_executor ex)
    {
        asio::steady_timer fallback_timer(ex);
        constexpr auto max_wait_ms = 120 * 1000;
        auto wait_ms = random() % max_wait_ms;
        fallback_timer.expires_after(std::chrono::milliseconds(wait_ms));
        auto [ec] = co_await fallback_timer.async_wait(asio::as_tuple(asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("{} fallback failed timer {} ms error {}", conn_id, wait_ms, ec.message());
        }
        LOG_DEBUG("{} fallback failed timer {} ms ", conn_id, wait_ms);
    }

    static asio::awaitable<void> fallback_failed(const std::shared_ptr<asio::ip::tcp::socket> &s)
    {
        char d[4096] = {0};
        for (;;)
        {
            auto [re, n] = co_await s->async_read_some(asio::buffer(d), asio::as_tuple(asio::use_awaitable));
            if (re || n == 0)
            {
                break;
            }
        }

        std::error_code ignore;
        ignore = s->shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
    }

    asio::awaitable<void> handle_fallback(const std::shared_ptr<asio::ip::tcp::socket> &s,
                                          std::vector<uint8_t> buf,
                                          uint32_t conn_id,
                                          const std::string &sni)
    {
        auto fallback_target = find_fallback_target_by_sni(sni);
        if (fallback_target.first.empty())
        {
            LOG_INFO("srv {} fallback no target for sni {}", conn_id, sni.empty() ? "empty" : sni);
            using asio::experimental::awaitable_operators::operator||;
            co_await (fallback_failed(s) || fallback_failed_timer(conn_id, s->get_executor()));
            LOG_INFO("srv {} fallback done", conn_id);
            co_return;
        }
        auto target_host = fallback_target.first;
        auto target_port = fallback_target.second;
        asio::ip::tcp::socket t(s->get_executor());
        asio::ip::tcp::resolver r(s->get_executor());

        LOG_INFO("srv {} fallback proxying sni {} to {}:{}", conn_id, sni, target_host, target_port);

        auto [er, eps] = co_await r.async_resolve(target_host, target_port, asio::as_tuple(asio::use_awaitable));
        if (er)
        {
            LOG_WARN("srv {} fallback resolve failed {}", conn_id, er.message());
            co_return;
        }

        auto [ec_c, ep_c] = co_await asio::async_connect(t, eps, asio::as_tuple(asio::use_awaitable));
        if (ec_c)
        {
            LOG_WARN("srv {} fallback connect failed {}", conn_id, ec_c.message());
            co_return;
        }

        if (!buf.empty())
        {
            auto [we, wn] = co_await asio::async_write(t, asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (we)
            {
                LOG_WARN("srv {} fallback forward initial data failed {}", conn_id, we.message());
                co_return;
            }
        }

        auto xfer = [](auto &f, auto &t) -> asio::awaitable<void>
        {
            char d[4096];
            for (;;)
            {
                auto [re, n] = co_await f.async_read_some(asio::buffer(d), asio::as_tuple(asio::use_awaitable));
                if (re || n == 0)
                {
                    break;
                }
                auto [we, wn] = co_await asio::async_write(t, asio::buffer(d, n), asio::as_tuple(asio::use_awaitable));
                if (we)
                {
                    break;
                }
            }
            std::error_code ignore;
            f.shutdown(asio::ip::tcp::socket::shutdown_receive, ignore);
            t.shutdown(asio::ip::tcp::socket::shutdown_send, ignore);
        };
        using asio::experimental::awaitable_operators::operator||;
        co_await (xfer(*s, t) || xfer(t, *s));
    }

   private:
    io_context_pool &pool_;
    asio::ip::tcp::acceptor acceptor_;

    std::vector<uint8_t> private_key_;
    reality::cert_manager cert_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
    replay_cache replay_cache_;
    reality::key_rotator key_rotator_;
    std::mutex tunnels_mutex_;
    std::vector<config::fallback_entry> fallbacks_;
    std::vector<std::weak_ptr<mux_tunnel_impl<asio::ip::tcp::socket>>> active_tunnels_;
};
}    
#endif
