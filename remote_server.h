#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include "mux_tunnel.h"
#include "protocol.h"

namespace mux
{

struct client_hello_data
{
    std::vector<uint8_t> session_id, random, x25519_pub;
    bool is_tls13 = false;
    uint32_t sid_offset = 0;
};

class ch_parser
{
   public:
    static client_hello_data parse(const std::vector<uint8_t>& buf)
    {
        client_hello_data info;
        const uint8_t* p = buf.data();
        size_t len = buf.size();
        if (len >= 5 && p[0] == 0x16 && (p[1] == 0x03))
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
        info.random.assign(p, p + 32);
        p += 32;
        len -= 32;
        if (len < 1)
        {
            return info;
        }
        const uint8_t sid_len = *p;
        info.sid_offset = (p - buf.data()) + 1;
        p++;
        len--;
        if (len < sid_len)
        {
            return info;
        }
        if (sid_len > 0)
        {
            info.session_id.assign(p, p + sid_len);
        }
        p += sid_len;
        len -= sid_len;
        if (len < 2)
        {
            return info;
        }
        const uint16_t cs_len = (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
        if (len < cs_len)
        {
            return info;
        }
        p += cs_len;
        len -= cs_len;
        if (len < 1)
        {
            return info;
        }
        const uint8_t comp_len = *p;
        p += 1;
        len -= 1;
        if (len < comp_len)
        {
            return info;
        }
        p += comp_len;
        len -= comp_len;
        if (len < 2)
        {
            return info;
        }
        const uint16_t ext_len = (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
        const uint8_t* ext_end = p + ext_len;
        if (len < ext_len)
        {
            return info;
        }
        while (p + 4 <= ext_end)
        {
            const uint16_t etype = (p[0] << 8) | p[1];
            const uint16_t elen = (p[2] << 8) | p[3];
            p += 4;
            if (p + elen > ext_end)
            {
                break;
            }
            if (etype == 0x0033 && elen >= 2)
            {
                const uint8_t* sp = p + 2;
                const uint8_t* se = std::min(p + elen, ext_end);
                while (sp + 4 <= se)
                {
                    const uint16_t grp = (sp[0] << 8) | sp[1];
                    const uint16_t klen = (sp[2] << 8) | sp[3];
                    sp += 4;
                    if (sp + klen > se)
                    {
                        break;
                    }
                    if (grp == 0x001d && klen == 32)
                    {
                        info.x25519_pub.assign(sp, sp + 32);
                        info.is_tls13 = true;
                        break;
                    }
                    sp += klen;
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
        mux::syn_payload syn;
        if (!mux::syn_payload::decode(syn_data.data(), syn_data.size(), syn))
        {
            LOG_ERROR("remote_tcp {} invalid syn payload", id_);
            co_await connection_->send_async(id_, mux::CMD_RST, {});
            co_return;
        }
        LOG_INFO("remote_tcp {} connect target {}:{}", id_, syn.addr, syn.port);

        auto [er, eps] = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_WARN("remote_tcp {} resolve failed {}", id_, er.message());
            mux::ack_payload ack{socks::REP_HOST_UNREACH, "", 0};
            co_await connection_->send_async(id_, mux::CMD_ACK, ack.encode());
            co_return;
        }
        auto [ec, ep] = co_await boost::asio::async_connect(target_socket_, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_WARN("remote_tcp {} connect failed {}", id_, ec.message());
            mux::ack_payload ack{socks::REP_CONN_REFUSED, "", 0};
            co_await connection_->send_async(id_, mux::CMD_ACK, ack.encode());
            co_return;
        }

        LOG_DEBUG("remote_tcp {} connected sending ack", id_);
        mux::ack_payload ack{socks::REP_SUCCESS, ep.address().to_string(), ep.port()};
        if (co_await connection_->send_async(id_, mux::CMD_ACK, ack.encode()))
        {
            co_return;
        }

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (upstream() || downstream());

        LOG_INFO("remote_tcp {} session finished", id_);
        boost::system::error_code ce;
        target_socket_.close(ce);
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
        target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

    void on_reset() override
    {
        recv_channel_.close();
        target_socket_.close();
    }
    void set_manager(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> m) { manager_ = m; }

   private:
    boost::asio::awaitable<void> upstream()
    {
        for (;;)
        {
            auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec || data.empty())
            {
                break;
            }
            auto [we, wn] =
                co_await boost::asio::async_write(target_socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                break;
            }
        }
        boost::system::error_code ec;
        target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        co_await connection_->send_async(id_, mux::CMD_FIN, {});
    }

    boost::asio::awaitable<void> downstream()
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            auto [re, n] = co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re || n == 0)
            {
                break;
            }
            if (co_await connection_->send_async(id_, mux::CMD_DAT, std::vector<uint8_t>(buf.begin(), buf.begin() + n)))
            {
                break;
            }
        }
        co_await connection_->send_async(id_, mux::CMD_FIN, {});
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket target_socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
};

class remote_udp_session : public mux_stream_interface, public std::enable_shared_from_this<remote_udp_session>
{
   public:
    remote_udp_session(std::shared_ptr<mux_connection> connection, uint32_t id, const boost::asio::any_io_executor& ex)
        : connection_(std::move(connection)), id_(id), udp_socket_(ex), recv_channel_(ex, 128)
    {
    }

    boost::asio::awaitable<void> start()
    {
        boost::system::error_code ec;
        udp_socket_.open(boost::asio::ip::udp::v4(), ec);
        if (ec)
        {
            LOG_ERROR("remote_udp {} failed open socket {}", id_, ec.message());
            mux::ack_payload ack{socks::REP_GEN_FAIL, "", 0};
            co_await connection_->send_async(id_, mux::CMD_ACK, ack.encode());
            co_return;
        }

        LOG_INFO("remote_udp {} started socket open", id_);
        mux::ack_payload ack{socks::REP_SUCCESS, "0.0.0.0", 0};
        if (co_await connection_->send_async(id_, mux::CMD_ACK, ack.encode()))
        {
            co_return;
        }

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (mux_to_udp() || udp_to_mux());

        boost::system::error_code ignore;
        udp_socket_.close(ignore);
        if (manager_)
        {
            manager_->remove_stream(id_);
        }
        LOG_INFO("remote_udp {} finished", id_);
    }

    void on_data(std::vector<uint8_t> data) override { recv_channel_.try_send(boost::system::error_code(), std::move(data)); }
    void on_close() override
    {
        recv_channel_.close();
        boost::system::error_code ec;
        udp_socket_.close(ec);
    }
    void on_reset() override { on_close(); }
    void set_manager(std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> m) { manager_ = m; }

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

            socks_udp_header header;
            if (!socks_udp_header::decode(data.data(), data.size(), header))
            {
                LOG_WARN("remote_udp {} invalid socks udp header", id_);
                continue;
            }

            boost::asio::ip::udp::resolver resolver(udp_socket_.get_executor());
            auto [er, eps] =
                co_await resolver.async_resolve(header.addr, std::to_string(header.port), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (er)
            {
                LOG_WARN("remote_udp {} resolve {} failed {}", id_, header.addr, er.message());
                continue;
            }

            LOG_DEBUG("remote_udp {} sending {} bytes to target {}:{}", id_, data.size() - header.header_len, header.addr, header.port);
            auto [we, wn] = co_await udp_socket_.async_send_to(boost::asio::buffer(data.data() + header.header_len, data.size() - header.header_len),
                                                               *eps.begin(),
                                                               boost::asio::as_tuple(boost::asio::use_awaitable));

            if (we)
            {
                LOG_WARN("remote_udp {} send_to error {}", id_, we.message());
            }
        }
    }

    boost::asio::awaitable<void> udp_to_mux()
    {
        std::vector<uint8_t> buf(65535);
        boost::asio::ip::udp::endpoint sender_ep;
        for (;;)
        {
            auto [re, n] =
                co_await udp_socket_.async_receive_from(boost::asio::buffer(buf), sender_ep, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (re)
            {
                break;
            }

            LOG_DEBUG("remote_udp {} received {} bytes from target {}:{}", id_, n, sender_ep.address().to_string(), sender_ep.port());

            socks_udp_header header;
            header.addr = sender_ep.address().to_string();
            header.port = sender_ep.port();

            std::vector<uint8_t> packet = header.encode();
            packet.insert(packet.end(), buf.begin(), buf.begin() + n);

            if (co_await connection_->send_async(id_, mux::CMD_DAT, std::move(packet)))
            {
                break;
            }
        }
    }

    std::shared_ptr<mux_connection> connection_;
    uint32_t id_;
    boost::asio::ip::udp::socket udp_socket_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> manager_;
};

class remote_server
{
   public:
    remote_server(io_context_pool& pool, uint16_t port, std::string fb_h, std::string fb_p, std::string key, boost::system::error_code& ec)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fb_host(fb_h),
          fb_port(fb_p)
    {
        server_private_key_ = reality::CryptoUtil::hex_to_bytes(key, ec);
        if (!ec)
        {
            boost::system::error_code ec2;
            std::vector<uint8_t> pub = reality::CryptoUtil::extract_public_key(server_private_key_, ec2);
            LOG_INFO("server public key {}", reality::CryptoUtil::bytes_to_hex(pub));
        }
    }
    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

   private:
    struct transcript
    {
        EVP_MD_CTX* ctx;
        transcript()
        {
            ctx = EVP_MD_CTX_new();
            EVP_DigestInit(ctx, EVP_sha256());
        }
        ~transcript() { EVP_MD_CTX_free(ctx); }
        void update(const std::vector<uint8_t>& data) { EVP_DigestUpdate(ctx, data.data(), data.size()); }
        std::vector<uint8_t> finish()
        {
            EVP_MD_CTX* c = EVP_MD_CTX_new();
            EVP_MD_CTX_copy(c, ctx);
            std::vector<uint8_t> h(EVP_MD_size(EVP_sha256()));
            unsigned int l;
            EVP_DigestFinal(c, h.data(), &l);
            h.resize(l);
            EVP_MD_CTX_free(c);
            return h;
        }
    };

    boost::asio::awaitable<void> accept_loop()
    {
        LOG_INFO("remote_server listening on port");
        for (;;)
        {
            auto s = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [e] = co_await acceptor_.async_accept(*s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                boost::system::error_code ec;
                auto ep = s->remote_endpoint(ec);
                LOG_DEBUG("remote_server new connection from {}", ec ? "unknown" : ep.address().to_string());
                boost::asio::co_spawn(
                    pool_.get_io_context(), [this, s]() { return handle(s); }, boost::asio::detached);
            }
        }
    }

    boost::asio::awaitable<void> handle(std::shared_ptr<boost::asio::ip::tcp::socket> s)
    {
        boost::system::error_code ec;
        std::vector<uint8_t> buf(4096);
        auto [re, n] = co_await s->async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (re)
        {
            co_return;
        }
        buf.resize(n);

        if (n < 5 || buf[0] != 0x16)
        {
            LOG_WARN("remote_server not tls handshake byte0={:02x} fallback", buf[0]);
            co_await handle_fallback(s, buf);
            co_return;
        }

        uint16_t rlen = (buf[3] << 8) | buf[4];
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

        std::vector<uint8_t> ch_rec = buf;
        std::vector<uint8_t> ch_msg(buf.begin() + 5, buf.end());
        auto info = ch_parser::parse(ch_msg);

        bool authorized = false;
        std::vector<uint8_t> auth_key;
        if (info.is_tls13 && !info.x25519_pub.empty() && info.session_id.size() == 32)
        {
            auto shared = reality::CryptoUtil::x25519_derive(server_private_key_, info.x25519_pub, ec);
            if (!ec)
            {
                std::vector<uint8_t> salt(info.random.begin(), info.random.begin() + 20);
                std::vector<uint8_t> r_info = reality::CryptoUtil::hex_to_bytes("5245414c495459", ec);
                auto prk = reality::CryptoUtil::hkdf_extract(salt, shared, ec);
                auth_key = reality::CryptoUtil::hkdf_expand(prk, r_info, 32, ec);
                std::vector<uint8_t> nonce(info.random.begin() + 20, info.random.end());
                std::vector<uint8_t> aad = ch_msg;
                std::fill(aad.begin() + info.sid_offset, aad.begin() + info.sid_offset + 32, 0);
                auto pt = reality::CryptoUtil::aes_gcm_decrypt(auth_key, nonce, info.session_id, aad, ec);
                if (!ec && pt.size() == 16)
                {
                    authorized = true;
                    LOG_INFO("remote_server auth success reality handshake proceeding");
                }
            }
        }

        if (!authorized)
        {
            LOG_WARN("remote_server auth failed fallback to {}", fb_host);
            co_await handle_fallback(s, buf);
            co_return;
        }

        transcript trans;
        trans.update(ch_msg);
        uint8_t spub[32], spriv[32];
        X25519_keypair(spub, spriv);
        std::vector<uint8_t> spub_vec(spub, spub + 32);
        std::vector<uint8_t> srand(32);
        RAND_bytes(srand.data(), 32);
        std::vector<uint8_t> sh_shared = reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(spriv, spriv + 32), info.x25519_pub, ec);

        auto sh_msg = reality::construct_server_hello(srand, info.session_id, 0x1301, spub_vec);
        trans.update(sh_msg);
        auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(sh_shared, trans.finish(), ec);
        auto c_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        auto enc_ext = reality::construct_encrypted_extensions();
        trans.update(enc_ext);
        auto cert_der = cert_manager_.generate_reality_cert(auth_key);
        auto cert = reality::construct_certificate(cert_der);
        trans.update(cert);
        auto cv = reality::construct_certificate_verify(cert_manager_.get_key(), trans.finish());
        trans.update(cv);
        auto s_fin_verify = reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, trans.finish(), ec);
        auto s_fin = reality::construct_finished(s_fin_verify);
        trans.update(s_fin);

        std::vector<uint8_t> flight2_plain;
        flight2_plain.insert(flight2_plain.end(), enc_ext.begin(), enc_ext.end());
        flight2_plain.insert(flight2_plain.end(), cert.begin(), cert.end());
        flight2_plain.insert(flight2_plain.end(), cv.begin(), cv.end());
        flight2_plain.insert(flight2_plain.end(), s_fin.begin(), s_fin.end());
        auto flight2_enc =
            reality::TlsRecordLayer::encrypt_record(s_hs_keys.first, s_hs_keys.second, 0, flight2_plain, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> flight2;
        auto sh_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, sh_msg.size());
        flight2.insert(flight2.end(), sh_rec.begin(), sh_rec.end());
        flight2.insert(flight2.end(), sh_msg.begin(), sh_msg.end());
        flight2.push_back(0x14);
        flight2.push_back(3);
        flight2.push_back(3);
        flight2.push_back(0);
        flight2.push_back(1);
        flight2.push_back(1);
        flight2.insert(flight2.end(), flight2_enc.begin(), flight2_enc.end());

        LOG_DEBUG("remote_server sending serverhello flight");
        if (auto [we, wn] = co_await boost::asio::async_write(*s, boost::asio::buffer(flight2), boost::asio::as_tuple(boost::asio::use_awaitable));
            we)
        {
            co_return;
        }

        LOG_DEBUG("remote_server waiting for client finished");
        uint8_t h[5];
        if (auto [re3, rn3] = co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable)); re3)
        {
            co_return;
        }
        if (h[0] == 0x14)
        {
            uint8_t d[1];
            co_await boost::asio::async_read(*s, boost::asio::buffer(d), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await boost::asio::async_read(*s, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        }
        uint16_t flen = (h[3] << 8) | h[4];
        std::vector<uint8_t> frec(flen);
        if (auto [re4, rn4] = co_await boost::asio::async_read(*s, boost::asio::buffer(frec), boost::asio::as_tuple(boost::asio::use_awaitable)); re4)
        {
            co_return;
        }
        std::vector<uint8_t> cth(5 + flen);
        memcpy(cth.data(), h, 5);
        memcpy(cth.data() + 5, frec.data(), flen);
        uint8_t ctype;
        auto pt = reality::TlsRecordLayer::decrypt_record(c_hs_keys.first, c_hs_keys.second, 0, cth, ctype, ec);
        if (ec)
        {
            co_return;
        }

        if (ctype != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("remote_server invalid client finished");
            co_return;
        }

        auto app_sec = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        trans.update(pt);

        auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("remote_server handshake done tunnel start");

        reality_engine engine(c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);
        auto tunnel = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*s), std::move(engine));

        tunnel->get_connection()->set_syn_callback(
            [this, tunnel](uint32_t id, std::vector<uint8_t> p)
            {
                boost::asio::co_spawn(
                    pool_.get_io_context(),
                    [this, tunnel, id, p]() -> boost::asio::awaitable<void>
                    {
                        mux::syn_payload syn;
                        if (!mux::syn_payload::decode(p.data(), p.size(), syn))
                        {
                            LOG_WARN("invalid syn payload for stream {}", id);
                            co_return;
                        }

                        if (syn.socks_cmd == socks::CMD_CONNECT)
                        {
                            auto sess = std::make_shared<remote_session>(tunnel->get_connection(), id, pool_.get_io_context().get_executor());
                            sess->set_manager(tunnel);
                            tunnel->register_stream(id, sess);
                            co_await sess->start(p);
                        }
                        else if (syn.socks_cmd == socks::CMD_UDP_ASSOCIATE)
                        {
                            LOG_INFO("new udp associate request stream {}", id);
                            auto sess = std::make_shared<remote_udp_session>(tunnel->get_connection(), id, pool_.get_io_context().get_executor());
                            sess->set_manager(tunnel);
                            tunnel->register_stream(id, sess);
                            co_await sess->start();
                        }
                        else
                        {
                            LOG_WARN("unsupported cmd {} for stream {}", (int)syn.socks_cmd, id);
                            co_await tunnel->get_connection()->send_async(id, mux::CMD_RST, {});
                        }
                    },
                    boost::asio::detached);
            });

        co_await tunnel->run();
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> s, std::vector<uint8_t> buf)
    {
        boost::asio::ip::tcp::socket t(s->get_executor());
        boost::asio::ip::tcp::resolver r(s->get_executor());
        auto [er, eps] = co_await r.async_resolve(fb_host, fb_port, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            co_return;
        }
        auto [ec, ep] = co_await boost::asio::async_connect(t, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            co_return;
        }
        if (auto [we, wn] = co_await boost::asio::async_write(t, boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable)); we)
        {
            co_return;
        }

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
            f.shutdown(boost::asio::ip::tcp::socket::shutdown_receive, ignore);
            t.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignore);
        };
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (xfer(*s, t) || xfer(t, *s));
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fb_host, fb_port;
    std::vector<uint8_t> server_private_key_;
    reality::CertManager cert_manager_;
};

}    // namespace mux
#endif
