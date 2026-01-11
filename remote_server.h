#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include "mux_tunnel.h"
#include "protocol.h"
#include "context_pool.h"
#include "reality_messages.h"

namespace mux
{

struct client_hello_info_t
{
    std::vector<uint8_t> session_id_, random_, x25519_pub_;
    std::string sni_;
    bool is_tls13_ = false;
    uint32_t sid_offset_ = 0;
};

class ch_parser
{
   public:
    [[nodiscard]] static client_hello_info_t parse(const std::vector<uint8_t>& buf)
    {
        client_hello_info_t info;
        const uint8_t* p = buf.data();
        size_t len = buf.size();
        if (len >= 5 && p[0] == 0x16 && p[1] == 0x03)
        {
            p += 5;
            len -= 5;
        }
        if (len < 6 || p[0] != 0x01)
        {
            return info;
        }

        p += 6;
        len -= 6;
        if (len < 32)
        {
            return info;
        }
        info.random_.assign(p, p + 32);
        p += 32;
        len -= 32;

        const uint8_t sid_len = *p;
        info.sid_offset_ = static_cast<uint32_t>((p - buf.data()) + 1);
        p++;
        len--;
        if (len < sid_len)
        {
            return info;
        }
        if (sid_len > 0)
        {
            info.session_id_.assign(p, p + sid_len);
        }
        p += sid_len;
        len -= sid_len;

        if (len < 2)
        {
            return info;
        }
        const size_t cs_len = static_cast<uint16_t>((p[0] << 8) | p[1]);
        if (len < 2 + cs_len + 1)
        {
            return info;
        }
        p += 2 + cs_len;
        len -= 2 + cs_len;

        const size_t comp_len = *p;
        if (len < 1 + comp_len + 2)
        {
            return info;
        }
        p += 1 + comp_len;
        len -= 1 + comp_len;

        const auto ext_len = static_cast<uint16_t>((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
        const uint8_t* ext_end = p + ext_len;

        while (p + 4 <= ext_end)
        {
            const auto etype = static_cast<uint16_t>((p[0] << 8) | p[1]);
            const auto elen = static_cast<uint16_t>((p[2] << 8) | p[3]);
            p += 4;

            if (etype == 0x0000 && elen >= 5)
            {
                const uint8_t* sp = p;

                if (sp + 5 <= p + elen)
                {
                    const uint8_t name_type = sp[2];
                    auto name_len = static_cast<uint16_t>((sp[3] << 8) | sp[4]);

                    if (name_type == 0x00 && sp + 5 + name_len <= p + elen)
                    {
                        info.sni_.assign(reinterpret_cast<const char*>(sp + 5), name_len);
                    }
                }
            }

            else if (etype == 0x0033)
            {
                const uint8_t* sp = p + 2;
                while (sp + 4 <= p + elen)
                {
                    const auto grp = static_cast<uint16_t>((sp[0] << 8) | sp[1]);
                    const auto klen = static_cast<uint16_t>((sp[2] << 8) | sp[3]);
                    if (grp == 0x001d && klen == 32)
                    {
                        info.x25519_pub_.assign(sp + 4, sp + 4 + 32);
                        info.is_tls13_ = true;
                        break;
                    }
                    sp += 4 + klen;
                }
            }
            p += elen;
        }
        return info;
    }
};

class remote_session : public mux_stream_interface, public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_connection> connection, uint32_t id, const boost::asio::any_io_executor& ex)
        : connection_(std::move(connection)), id_(id), resolver_(ex), target_socket_(ex), recv_channel_(ex, 128)
    {
    }

    boost::asio::awaitable<void> start(std::vector<uint8_t> syn_data)
    {
        syn_payload syn;
        if (!syn_payload::decode(syn_data.data(), syn_data.size(), syn))
        {
            co_await connection_->send_async(id_, CMD_RST, {});
            co_return;
        }

        LOG_INFO("remote tcp {} connect target {} port {}", id_, syn.addr_, syn.port_);
        auto [er, eps] = co_await resolver_.async_resolve(syn.addr_, std::to_string(syn.port_), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            const ack_payload ack{.socks_rep_ = socks::REP_HOST_UNREACH, .bnd_addr_ = "", .bnd_port_ = 0};
            co_await connection_->send_async(id_, CMD_ACK, ack.encode());
            co_return;
        }

        auto [ec_conn, ep_conn] = co_await boost::asio::async_connect(target_socket_, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_conn)
        {
            const ack_payload ack{.socks_rep_ = socks::REP_CONN_REFUSED, .bnd_addr_ = "", .bnd_port_ = 0};
            co_await connection_->send_async(id_, CMD_ACK, ack.encode());
            co_return;
        }

        boost::system::error_code ec_sock;
        ec_sock = target_socket_.set_option(tcp::no_delay(true), ec_sock);

        const ack_payload ack_pl{.socks_rep_ = socks::REP_SUCCESS, .bnd_addr_ = ep_conn.address().to_string(), .bnd_port_ = ep_conn.port()};
        co_await connection_->send_async(id_, CMD_ACK, ack_pl.encode());

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (upstream() && downstream());

        boost::system::error_code ignore;
        ignore = target_socket_.close(ignore);
        if (manager_)
        {
            manager_->remove_stream(id_);
        }
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(boost::system::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        boost::system::error_code ec;
        ec = target_socket_.shutdown(tcp::socket::shutdown_send, ec);
    }
    void on_reset() override
    {
        recv_channel_.close();
        target_socket_.close();
    }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<tcp::socket>>& m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> upstream()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec || data.empty())
            {
                boost::system::error_code ignore;
                ignore = target_socket_.shutdown(tcp::socket::shutdown_send, ignore);
                break;
            }
            auto [we, wn] =
                co_await boost::asio::async_write(target_socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
    }

    boost::asio::awaitable<void> downstream()
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            boost::system::error_code re;
            const uint32_t n =
                co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::redirect_error(boost::asio::use_awaitable, re));
            if (re || n == 0)
            {
                break;
            }
            if (co_await connection_->send_async(id_, CMD_DAT, std::vector<uint8_t>(buf.begin(), buf.begin() + n)))
            {
                break;
            }
        }
        co_await connection_->send_async(id_, CMD_FIN, {});
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    tcp::resolver resolver_;
    tcp::socket target_socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<tcp::socket>> manager_;
};

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const boost::asio::any_io_executor& ex)
        : connection_(std::move(connection)), id_(id), udp_socket_(ex), udp_resolver_(ex), recv_channel_(ex, 128)
    {
    }

    boost::asio::awaitable<void> start()
    {
        boost::system::error_code ec;
        ec = udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (!ec)
        {
            ec = udp_socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0), ec);
        }

        if (ec)
        {
            LOG_ERROR("srv {} udp open/bind failed {}", id_, ec.message());
            ack_payload const ack{.socks_rep_ = socks::REP_GEN_FAIL, .bnd_addr_ = "", .bnd_port_ = 0};
            co_await connection_->send_async(id_, CMD_ACK, ack.encode());
            co_return;
        }

        const ack_payload ack_pl{.socks_rep_ = socks::REP_SUCCESS, .bnd_addr_ = "0.0.0.0", .bnd_port_ = 0};
        co_await connection_->send_async(id_, CMD_ACK, ack_pl.encode());

        using boost::asio::experimental::awaitable_operators::operator&&;
        co_await (mux_to_udp() && udp_to_mux());

        if (manager_)
        {
            manager_->remove_stream(id_);
        }
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(boost::system::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        boost::system::error_code ignore;
        ignore = udp_socket_.close(ignore);
    }
    void on_reset() override { on_close(); }
    void set_manager(const std::shared_ptr<mux_tunnel_impl<tcp::socket>>& m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> mux_to_udp()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec || data.empty())
            {
                break;
            }
            socks_udp_header h;
            if (!socks_udp_header::decode(data.data(), data.size(), h))
            {
                continue;
            }

            auto [er, eps] =
                co_await udp_resolver_.async_resolve(h.addr_, std::to_string(h.port_), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!er)
            {
                auto [se, sn] = co_await udp_socket_.async_send_to(boost::asio::buffer(data.data() + h.header_len_, data.size() - h.header_len_),
                                                                   *eps.begin(),
                                                                   boost::asio::as_tuple(boost::asio::use_awaitable));
                if (se)
                {
                    LOG_WARN("srv {} udp send error {}", id_, se.message());
                }
            }
            else
            {
                LOG_WARN("srv {} udp resolve error {}", id_, er.message());
            }
        }
    }

    boost::asio::awaitable<void> udp_to_mux()
    {
        std::vector<uint8_t> buf(65535);
        boost::asio::ip::udp::endpoint ep;
        for (;;)
        {
            auto [re, n] = co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), ep, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re)
            {
                if (re != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("srv {} udp receive error {}", id_, re.message());
                }
                break;
            }
            socks_udp_header h;
            h.addr_ = ep.address().to_string();
            h.port_ = ep.port();
            std::vector<uint8_t> pkt = h.encode();
            pkt.insert(pkt.end(), buf.begin(), buf.begin() + static_cast<uint32_t>(n));
            if (co_await connection_->send_async(id_, CMD_DAT, std::move(pkt)))
            {
                break;
            }
        }
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::ip::udp::resolver udp_resolver_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<tcp::socket>> manager_;
};

class remote_server
{
   public:
    remote_server(io_context_pool& pool, uint16_t port, std::string fb_h, std::string fb_p, const std::string& key, boost::system::error_code& ec)
        : pool_(pool), acceptor_(pool.get_io_context(), tcp::endpoint(tcp::v6(), port)), fb_host_(std::move(fb_h)), fb_port_(std::move(fb_p))
    {
        priv_key_ = reality::crypto_util::hex_to_bytes(key, ec);
        if (!ec)
        {
            boost::system::error_code ignore;
            auto pub = reality::crypto_util::extract_public_key(priv_key_, ignore);
            LOG_INFO("server public key {}", reality::crypto_util::bytes_to_hex(pub));
        }
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

   private:
    class transcript_t
    {
       public:
        transcript_t() : ctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) { EVP_DigestInit(ctx_.get(), EVP_sha256()); }
        void update(const std::vector<uint8_t>& data) const { EVP_DigestUpdate(ctx_.get(), data.data(), data.size()); }
        [[nodiscard]] std::vector<uint8_t> finish() const
        {
            const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            EVP_MD_CTX_copy(c.get(), ctx_.get());
            std::vector<uint8_t> h(EVP_MD_size(EVP_sha256()));
            unsigned int l;
            EVP_DigestFinal(c.get(), h.data(), &l);
            h.resize(l);
            return h;
        }

       private:
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_;
    };

    boost::asio::awaitable<void> accept_loop()
    {
        LOG_INFO("remote server listening for connections");
        for (;;)
        {
            auto s = std::make_shared<tcp::socket>(acceptor_.get_executor());
            auto [e] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                boost::system::error_code ec;
                ec = s->set_option(tcp::no_delay(true), ec);
                const uint32_t conn_id = next_conn_id_.fetch_add(1, std::memory_order_relaxed);

                boost::asio::co_spawn(
                    pool_.get_io_context(), [this, s, conn_id = conn_id]() { return handle(s, conn_id); }, boost::asio::detached);
            }
        }
    }

    boost::asio::awaitable<void> handle(std::shared_ptr<tcp::socket> s, uint32_t conn_id)
    {
        boost::system::error_code ec_ep;
        auto ep = s->remote_endpoint(ec_ep);
        std::string remote_ip = ec_ep ? "unknown" : ep.address().to_string();
        LOG_DEBUG("srv {} new connection from {}", conn_id, remote_ip);

        std::vector<uint8_t> buf(4096);
        auto [re, n] = co_await s->async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re)
        {
            LOG_ERROR("srv {} initial read error {}", conn_id, re.message());
            co_return;
        }
        buf.resize(n);

        if (n < 5 || buf[0] != 0x16)
        {
            LOG_WARN("srv {} not a tls handshake fallback no sni ip {}", conn_id, remote_ip);
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        const size_t rlen = static_cast<uint16_t>((buf[3] << 8) | buf[4]);
        while (buf.size() < 5 + rlen)
        {
            std::vector<uint8_t> tmp(5 + rlen - buf.size());
            auto [re2, n2] = co_await boost::asio::async_read(*s, boost::asio::buffer(tmp), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re2)
            {
                co_return;
            }
            buf.insert(buf.end(), tmp.begin(), tmp.end());
        }

        auto ch_msg = std::vector<uint8_t>(buf.begin() + 5, buf.end());
        auto info = ch_parser::parse(ch_msg);
        boost::system::error_code ec;
        bool authorized = false;
        std::vector<uint8_t> auth_key;

        if (info.is_tls13_ && info.session_id_.size() == 32)
        {
            auto shared = reality::crypto_util::x25519_derive(priv_key_, info.x25519_pub_, ec);
            if (!ec)
            {
                auto salt = std::vector<uint8_t>(info.random_.begin(), info.random_.begin() + 20);
                auto r_info = reality::crypto_util::hex_to_bytes("5245414c495459", ec);
                auto prk = reality::crypto_util::hkdf_extract(salt, shared, ec);
                auth_key = reality::crypto_util::hkdf_expand(prk, r_info, 32, ec);

                auto aad = ch_msg;
                std::fill_n(aad.begin() + info.sid_offset_, 32, 0);
                auto pt = reality::crypto_util::aes_gcm_decrypt(
                    auth_key, std::vector<uint8_t>(info.random_.begin() + 20, info.random_.end()), info.session_id_, aad, ec);
                if (!ec && pt.size() == 16)
                {
                    const uint32_t timestamp = (static_cast<uint32_t>(pt[4]) << 24) | (static_cast<uint32_t>(pt[5]) << 16) |
                                               (static_cast<uint32_t>(pt[6]) << 8) | static_cast<uint32_t>(pt[7]);
                    auto now = static_cast<uint32_t>(time(nullptr));
                    if (timestamp > now + 120 || timestamp < now - 120)
                    {
                        LOG_WARN("srv {} auth failed replay attack detected ts diff", conn_id);
                        authorized = false;
                    }
                    else
                    {
                        authorized = true;
                    }
                }
            }
        }

        if (!authorized)
        {
            if (info.sni_.empty())
            {
                LOG_WARN("srv {} authorization failed fallback no sni ip {}", conn_id, remote_ip);
            }
            else
            {
                LOG_WARN("srv {} authorization failed fallback sni {} ip {}", conn_id, info.sni_, remote_ip);
            }
            co_await handle_fallback(s, buf, conn_id);
            co_return;
        }

        LOG_INFO("srv {} authorized proceeding sni {}", conn_id, info.sni_);
        transcript_t const trans;
        trans.update(ch_msg);

        uint8_t spub[32];
        uint8_t spriv[32];
        reality::crypto_util::generate_x25519_keypair(spub, spriv);
        std::vector<uint8_t> srand(32);
        RAND_bytes(srand.data(), 32);
        auto sh_shared = reality::crypto_util::x25519_derive(std::vector<uint8_t>(spriv, spriv + 32), info.x25519_pub_, ec);

        auto sh_msg = reality::construct_server_hello(srand, info.session_id_, 0x1301, std::vector<uint8_t>(spub, spub + 32));
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

        if (auto [we, wn] = co_await boost::asio::async_write(*s, boost::asio::buffer(out_sh), boost::asio::as_tuple(boost::asio::use_awaitable)); we)
        {
            LOG_ERROR("srv {} write sh flight error {}", conn_id, we.message());
            co_return;
        }

        uint8_t h[5];
        if (auto [re3, rn3] = co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable)); re3)
        {
            LOG_ERROR("srv {} read client finished header error {}", conn_id, re3.message());
            co_return;
        }

        if (h[0] == 0x14)
        {
            uint8_t dummy[1];
            co_await boost::asio::async_read(*s, boost::asio::buffer(dummy, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        }

        auto flen = static_cast<uint16_t>((h[3] << 8) | h[4]);
        std::vector<uint8_t> frec(flen);
        if (auto [re4, rn4] = co_await boost::asio::async_read(*s, boost::asio::buffer(frec), boost::asio::as_tuple(boost::asio::use_awaitable)); re4)
        {
            LOG_ERROR("srv {} read client finished body error {}", conn_id, re4.message());
            co_return;
        }

        std::vector<uint8_t> cth(5 + flen);
        std::memcpy(cth.data(), h, 5);
        std::memcpy(cth.data() + 5, frec.data(), flen);
        uint8_t ctype;
        auto pt = reality::tls_record_layer::decrypt_record(c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);

        if (ec || ctype != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("srv {} client finished verification failed type {} len {}", conn_id, static_cast<int>(ctype), pt.size());
            co_return;
        }

        auto expected_fin_verify =
            reality::tls_key_schedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), ec);
        if (pt.size() < expected_fin_verify.size() + 4 || std::memcmp(pt.data() + 4, expected_fin_verify.data(), expected_fin_verify.size()) != 0)
        {
            LOG_ERROR("srv {} client finished hmac verification failed", conn_id);
            co_return;
        }

        auto app_sec = reality::tls_key_schedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        auto c_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::tls_key_schedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("srv {} tunnel start", conn_id);
        reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);
        auto tunnel = std::make_shared<mux_tunnel_impl<tcp::socket>>(std::move(*s), std::move(engine), false, conn_id);

        tunnel->get_connection()->set_syn_callback(
            [this, tunnel](uint32_t id, const std::vector<uint8_t>& p)
            {
                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, tunnel, id, p = p]() -> boost::asio::awaitable<void>
                    {
                        syn_payload syn;
                        if (!syn_payload::decode(p.data(), p.size(), syn))
                        {
                            co_return;
                        }
                        if (syn.socks_cmd_ == socks::CMD_CONNECT)
                        {
                            auto sess = std::make_shared<remote_session>(tunnel->get_connection(), id, pool_.get_io_context().get_executor());
                            sess->set_manager(tunnel);
                            tunnel->register_stream(id, sess);
                            co_await sess->start(p);
                        }
                        else if (syn.socks_cmd_ == socks::CMD_UDP_ASSOCIATE)
                        {
                            auto sess = std::make_shared<remote_udp_session>(tunnel->get_connection(), id, pool_.get_io_context().get_executor());
                            sess->set_manager(tunnel);
                            tunnel->register_stream(id, sess);
                            co_await sess->start();
                        }
                    },
                    boost::asio::detached);
            });

        co_await tunnel->run();
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<tcp::socket> s, std::vector<uint8_t> buf, uint32_t conn_id) const
    {
        tcp::socket t(s->get_executor());
        tcp::resolver r(s->get_executor());
        auto [er, eps] = co_await r.async_resolve(fb_host_, fb_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_ERROR("srv {} fallback resolve failed {}", conn_id, er.message());
            co_return;
        }

        auto [ec_c, ep_c] = co_await boost::asio::async_connect(t, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_c)
        {
            LOG_ERROR("srv {} fallback connect failed {}", conn_id, ec_c.message());
            co_return;
        }

        co_await boost::asio::async_write(t, boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));

        auto xfer = [](auto& f, auto& t) -> boost::asio::awaitable<void>
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
            f.shutdown(tcp::socket::shutdown_receive, ignore);
            t.shutdown(tcp::socket::shutdown_send, ignore);
        };
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (xfer(*s, t) || xfer(t, *s));
    }

    io_context_pool& pool_;
    tcp::acceptor acceptor_;
    std::string fb_host_, fb_port_;
    std::vector<uint8_t> priv_key_;
    reality::cert_manager cert_manager_;
    std::atomic<uint32_t> next_conn_id_{1};
};

}    // namespace mux

#endif
