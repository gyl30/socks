#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <vector>
#include <mutex>
#include <unordered_set>

#include "protocol.h"
#include "ch_parser.h"
#include "mux_tunnel.h"
#include "key_rotator.h"
#include "replay_cache.h"
#include "cert_manager.h"
#include "context_pool.h"
#include "remote_session.h"
#include "tls_record_layer.h"
#include "reality_messages.h"
#include "remote_udp_session.h"

namespace mux
{
class remote_server : public std::enable_shared_from_this<remote_server>
{
   public:
    remote_server(io_context_pool &pool, uint16_t port, std::string fb_h, std::string fb_p, const std::string &key)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fb_host_(std::move(fb_h)),
          fb_port_(std::move(fb_p))
    {
        private_key_ = reality::crypto_util::hex_to_bytes(key);
        boost::system::error_code ignore;
        auto pub = reality::crypto_util::extract_public_key(private_key_, ignore);
        LOG_INFO("server public key {}", reality::crypto_util::bytes_to_hex(pub));
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

    void stop()
    {
        LOG_INFO("remote server stopping");
        boost::system::error_code ignore;
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
    boost::asio::awaitable<void> accept_loop()
    {
        LOG_INFO("remote server listening for connections");
        for (;;)
        {
            auto s = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [e] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                boost::system::error_code ec;
                ec = s->set_option(boost::asio::ip::tcp::no_delay(true), ec);
                (void)ec;
                const uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);

                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, s, self = shared_from_this(), conn_id = conn_id]() { return handle(s, conn_id); },
                    boost::asio::detached);
            }
            else
            {
                if (e == boost::asio::error::operation_aborted)
                {
                    LOG_INFO("acceptor closed, stopping loop");
                    break;
                }
                LOG_WARN("accept error {}", e.message());
            }
        }
    }

    boost::asio::awaitable<void> handle(std::shared_ptr<boost::asio::ip::tcp::socket> s, uint32_t conn_id)
    {
        auto [ok, buf] = co_await read_initial_and_validate(s, conn_id);
        if (!ok)
        {
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        auto info = ch_parser::parse(buf);
        auto [auth_ok, auth_key] = authenticate_client(info, buf, conn_id);

        if (!auth_ok)
        {
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        LOG_INFO("srv {} authorized proceeding sni {}", conn_id, info.sni);
        const reality::transcript trans;

        if (buf.size() > 5)
        {
            trans.update(std::vector<uint8_t>(buf.begin() + 5, buf.end()));
        }
        else
        {
            LOG_ERROR("srv {} buffer too short for transcript", conn_id);
            co_return;
        }

        boost::system::error_code ec;
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

        auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("srv {} tunnel start", conn_id);
        reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);
        auto tunnel = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*s), std::move(engine), false, conn_id);

        {
            const std::scoped_lock lock(tunnels_mutex_);
            std::erase_if(active_tunnels_, [](const auto &wp) { return wp.expired(); });
            active_tunnels_.push_back(tunnel);
        }

        tunnel->get_connection()->set_syn_callback(
            [this, tunnel, conn_id](uint32_t id, const std::vector<uint8_t> &p)
            {
                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, tunnel, conn_id, id, p = p]() { return process_stream_request(tunnel, conn_id, id, p); },
                    boost::asio::detached);
            });

        co_await tunnel->run();
    }

    boost::asio::awaitable<void> process_stream_request(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel,
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

    static boost::asio::awaitable<std::pair<bool, std::vector<uint8_t>>> read_initial_and_validate(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                                                   uint32_t conn_id)
    {
        std::vector<uint8_t> buf(4096);
        auto [re, n] = co_await s->async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
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
            auto [re2, n2] = co_await boost::asio::async_read(*s, boost::asio::buffer(tmp), boost::asio::as_tuple(boost::asio::use_awaitable));
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
            LOG_WARN("srv {} not tls1.3 or invalid session id len {}", conn_id, info.session_id.size());
            return {false, {}};
        }

        if (!replay_cache_.check_and_insert(info.session_id))
        {
            LOG_WARN("srv {} replay attack detected for sid", conn_id);
            return {false, {}};
        }

        boost::system::error_code ec;
        auto shared = reality::crypto_util::x25519_derive(private_key_, info.x25519_pub, ec);
        if (ec)
        {
            LOG_ERROR("srv {} x25519 derive failed", conn_id);
            return {false, {}};
        }

        auto salt = std::vector<uint8_t>(info.random.begin(), info.random.begin() + 20);
        auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459");
        auto prk = reality::crypto_util::hkdf_extract(salt, shared, ec);
        auto auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 32, ec);

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

        auto pt = reality::crypto_util::aes_gcm_decrypt(
            auth_key, std::vector<uint8_t>(info.random.begin() + 20, info.random.end()), info.session_id, aad, ec);

        if (ec || pt.size() != 16)
        {
            LOG_WARN("srv {} auth decryption failed or bad size", conn_id);
            return {false, {}};
        }

        const uint32_t timestamp = (static_cast<uint32_t>(pt[4]) << 24) | (static_cast<uint32_t>(pt[5]) << 16) | (static_cast<uint32_t>(pt[6]) << 8) |
                                   static_cast<uint32_t>(pt[7]);
        auto now = static_cast<uint32_t>(time(nullptr));
        if (timestamp > now + 120 || timestamp < now - 120)
        {
            LOG_WARN("srv {} auth failed replay check ts {} now {}", conn_id, timestamp, now);
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

    boost::asio::awaitable<server_handshake_res> perform_handshake_response(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                                            const client_hello_info_t &info,
                                                                            const reality::transcript &trans,
                                                                            const std::vector<uint8_t> &auth_key,
                                                                            uint32_t conn_id,
                                                                            boost::system::error_code &ec)
    {
        auto key_pair = key_rotator_.get_current_key();
        const uint8_t *public_key = key_pair->public_key;
        const uint8_t *private_key = key_pair->private_key;
        std::vector<uint8_t> srand(32);
        RAND_bytes(srand.data(), 32);

        LOG_TRACE("srv {} generated ephemeral key {}", conn_id, reality::crypto_util::bytes_to_hex(std::vector<uint8_t>(public_key, public_key + 32)));

        auto sh_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(private_key, private_key + 32), info.x25519_pub, ec);
        auto sh_msg = reality::construct_server_hello(srand, info.session_id, 0x1301, std::vector<uint8_t>(public_key, public_key + 32));
        trans.update(sh_msg);
        auto hs_keys = reality::tls_key_schedule::derive_handshake_keys(sh_shared, trans.finish(), ec);
        auto c_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::tls_key_schedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        auto enc_ext = reality::construct_encrypted_extensions();
        trans.update(enc_ext);
        auto cert_der = cert_manager_.generate_reality_cert(auth_key);
        auto cert = reality::construct_certificate(cert_der);
        trans.update(cert);
        auto cv = reality::construct_certificate_verify(cert_manager_.get_key(), trans.finish());
        trans.update(cv);
        auto s_fin_verify = reality::tls_key_schedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), ec);
        auto s_fin = reality::construct_finished(s_fin_verify);
        trans.update(s_fin);

        std::vector<uint8_t> flight2_plain;
        flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
        flight2_plain.insert(flight2_plain.end(), cert.begin(), cert.end());
        flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
        flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());

        auto flight2_enc =
            reality::tls_record_layer::encrypt_record(s_hs_keys.first, s_hs_keys.second, 0, flight2_plain, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out_sh;
        auto sh_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, static_cast<uint16_t>(sh_msg.size()));
        out_sh.insert(out_sh.end(), sh_rec.begin(), sh_rec.end());
        out_sh.insert(out_sh.end(), sh_msg.begin(), sh_msg.end());
        out_sh.insert(out_sh.end(), {0x14, 0x03, 0x03, 0x00, 0x01, 0x01});
        out_sh.insert(out_sh.end(), flight2_enc.begin(), flight2_enc.end());

        LOG_DEBUG("srv {} sending server hello flight size {}", conn_id, out_sh.size());
        auto [we, wn] = co_await boost::asio::async_write(*s, boost::asio::buffer(out_sh), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            ec = we;
            co_return server_handshake_res{.ok = false, .hs_keys = {}, .s_hs_keys = {}, .c_hs_keys = {}};
        }

        co_return server_handshake_res{.ok = true, .hs_keys = hs_keys, .s_hs_keys = s_hs_keys, .c_hs_keys = c_hs_keys};
    }

    static boost::asio::awaitable<bool> verify_client_finished(std::shared_ptr<boost::asio::ip::tcp::socket> s,
                                                               const std::pair<std::vector<uint8_t>, std::vector<uint8_t>> &c_hs_keys,
                                                               const reality::handshake_keys &hs_keys,
                                                               const reality::transcript &trans,
                                                               uint32_t conn_id,
                                                               boost::system::error_code &ec)
    {
        uint8_t h[5];
        auto [re3, rn3] = co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re3)
        {
            LOG_ERROR("srv {} read client finished header error {}", conn_id, re3.message());
            co_return false;
        }

        if (h[0] == 0x14)
        {
            uint8_t dummy[1];
            co_await boost::asio::async_read(*s, boost::asio::buffer(dummy, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        }

        auto flen = static_cast<uint16_t>((h[3] << 8) | h[4]);
        std::vector<uint8_t> data(flen);
        auto [re4, rn4] = co_await boost::asio::async_read(*s, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re4)
        {
            LOG_ERROR("srv {} read client finished body error {}", conn_id, re4.message());
            co_return false;
        }

        std::vector<uint8_t> cth(5 + flen);
        std::memcpy(cth.data(), h, 5);
        std::memcpy(cth.data() + 5, data.data(), flen);
        uint8_t ctype;
        auto pt = reality::tls_record_layer::decrypt_record(c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);

        if (ec || ctype != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("srv {} client finished verification failed type {}", conn_id, static_cast<int>(ctype));
            co_return false;
        }

        auto expected_fin_verify =
            reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), ec);
        if (pt.size() < expected_fin_verify.size() + 4 || std::memcmp(pt.data() + 4, expected_fin_verify.data(), expected_fin_verify.size()) != 0)
        {
            LOG_ERROR("srv {} client finished hmac verification failed", conn_id);
            co_return false;
        }
        co_return true;
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::vector<uint8_t> buf, uint32_t conn_id) const
    {
        boost::asio::ip::tcp::socket t(s->get_executor());
        boost::asio::ip::tcp::resolver r(s->get_executor());
        auto [er, eps] = co_await r.async_resolve(fb_host_, fb_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_WARN("srv {} fallback resolve failed {}", conn_id, er.message());
            co_return;
        }

        auto [ec_c, ep_c] = co_await boost::asio::async_connect(t, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_c)
        {
            LOG_WARN("srv {} fallback connect failed {}", conn_id, ec_c.message());
            co_return;
        }

        LOG_INFO("srv {} fallback proxying to {}:{}", conn_id, fb_host_, fb_port_);
        auto [we, wn] = co_await boost::asio::async_write(t, boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (we)
        {
            LOG_WARN("srv {} fallback forward initial data failed {}", conn_id, we.message());
            co_return;
        }

        auto xfer = [](auto &f, auto &t) -> boost::asio::awaitable<void>
        {
            char d[4096];
            for (;;)
            {
                auto [re, n] = co_await f.async_read_some(boost::asio::buffer(d), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (re || n == 0)
                {
                    break;
                }
                auto [we, wn] = co_await boost::asio::async_write(t, boost::asio::buffer(d, n), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (we)
                {
                    break;
                }
            }
            boost::system::error_code ignore;
            f.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ignore);
            t.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
        };
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (xfer(*s, t) || xfer(t, *s));
    }

   private:
    io_context_pool &pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fb_host_, fb_port_;
    std::vector<uint8_t> private_key_;
    reality::cert_manager cert_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
    replay_cache replay_cache_;
    reality::key_rotator key_rotator_;
    std::mutex tunnels_mutex_;
    std::vector<std::weak_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>>> active_tunnels_;
};

}    // namespace mux

#endif
