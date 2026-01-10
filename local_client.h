#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <vector>
#include <array>
#include <iostream>
#include <ctime>
#include <iomanip>

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_engine.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"
#include "protocol.h"

namespace mux
{

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager)
        : socket_(std::move(socket)), tunnel_manager_(std::move(tunnel_manager))
    {
    }

    void start()
    {
        auto self = shared_from_this();
        boost::asio::co_spawn(
            socket_.get_executor(), [self]() mutable -> boost::asio::awaitable<void> { co_await self->run(); }, boost::asio::detached);
    }

   private:
    boost::asio::awaitable<void> run()
    {
        uint8_t ver_nmethods[2];
        auto [e1, n1] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(ver_nmethods, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e1 || ver_nmethods[0] != socks::VER)
        {
            LOG_WARN("SOCKS handshake failed: invalid version or read error: {}", e1.message());
            co_return;
        }

        std::vector<uint8_t> methods(ver_nmethods[1]);
        auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e2)
            co_return;

        uint8_t resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [e3, n3] = co_await boost::asio::async_write(socket_, boost::asio::buffer(resp), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e3)
            co_return;

        uint8_t head[4];
        auto [e4, n4] = co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e4)
            co_return;

        if (head[1] != socks::CMD_CONNECT)
        {
            LOG_WARN("SOCKS unsupported command: {}", (int)head[1]);
            uint8_t err[] = {socks::VER, socks::REP_CMD_NOT_SUPPORTED, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_return;
        }

        std::string host;
        if (head[3] == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
                co_return;
            host = boost::asio::ip::address_v4(b).to_string();
        }
        else if (head[3] == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
                co_return;
            host.resize(len);
            auto [e2, n2] = co_await boost::asio::async_read(socket_, boost::asio::buffer(host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e2)
                co_return;
        }
        else if (head[3] == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type b;
            auto [e, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(b), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e)
                co_return;
            host = boost::asio::ip::address_v6(b).to_string();
        }
        else
        {
            LOG_WARN("SOCKS unsupported address type: {}", (int)head[3]);
            uint8_t err[] = {socks::VER, socks::REP_ADDR_TYPE_NOT_SUPPORTED, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_return;
        }

        uint16_t port_n;
        auto [e5, n5] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&port_n, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e5)
            co_return;
        uint16_t port = ntohs(port_n);

        LOG_INFO("SOCKS Request: connect to {}:{}", host, port);

        auto stream = tunnel_manager_->create_stream();
        if (!stream)
        {
            LOG_ERROR("Failed to create mux stream (tunnel might be closed)");
            co_return;
        }

        LOG_DEBUG("Stream {} created, initiating SYN...", stream->id());

        SynPayload syn{socks::CMD_CONNECT, host, port};
        if (auto ec = co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_SYN, syn.encode()))
        {
            LOG_ERROR("Stream {} failed to send SYN: {}", stream->id(), ec.message());
            co_await stream->close();
            co_return;
        }

        LOG_DEBUG("Stream {} waiting for ACK...", stream->id());

        auto [ack_ec, ack_data] = co_await stream->async_read_some();
        if (ack_ec)
        {
            LOG_ERROR("Stream {} wait ACK failed: {}", stream->id(), ack_ec.message());
            co_await stream->close();
            co_return;
        }

        AckPayload ack_payload;
        if (!AckPayload::decode(ack_data.data(), ack_data.size(), ack_payload))
        {
            LOG_ERROR("Stream {} received invalid ACK payload (len={})", stream->id(), ack_data.size());
            co_await stream->close();
            co_return;
        }

        if (ack_payload.socks_rep != socks::REP_SUCCESS)
        {
            LOG_WARN("Stream {} remote connection failed with SOCKS REP: {}", stream->id(), (int)ack_payload.socks_rep);

            uint8_t err[] = {socks::VER, ack_payload.socks_rep, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(err), boost::asio::as_tuple(boost::asio::use_awaitable));
            co_await stream->close();
            co_return;
        }

        LOG_INFO("Stream {} established successfully. Remote bound to {}:{}", stream->id(), ack_payload.bnd_addr, ack_payload.bnd_port);

        uint8_t rep[] = {socks::VER, socks::REP_SUCCESS, 0, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        auto [e6, n6] = co_await boost::asio::async_write(socket_, boost::asio::buffer(rep), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (e6)
        {
            LOG_ERROR("Stream {} failed to send SOCKS success to local: {}", stream->id(), e6.message());
            co_await stream->close();
            co_return;
        }

        LOG_DEBUG("Stream {} SOCKS success sent to local client. Starting data transfer.", stream->id());

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (upstream(stream) || downstream(stream));

        LOG_DEBUG("Stream {} session finished.", stream->id());
        co_await stream->close();
    }

    boost::asio::awaitable<void> upstream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            auto [e, n] = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (e || n == 0)
            {
                if (e != boost::asio::error::eof && e != boost::asio::error::operation_aborted)
                    LOG_DEBUG("Stream {} upstream local read error: {}", stream->id(), e.message());
                break;
            }

            if (auto ec = co_await stream->async_write_some(buf.data(), n))
            {
                LOG_DEBUG("Stream {} upstream tunnel write error: {}", stream->id(), ec.message());
                break;
            }
        }

        LOG_DEBUG("Stream {} upstream EOF, sending FIN.", stream->id());
        co_await tunnel_manager_->get_connection()->send_async(stream->id(), CMD_FIN, {});
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

    boost::asio::awaitable<void> downstream(std::shared_ptr<mux_stream> stream)
    {
        for (;;)
        {
            auto [e, data] = co_await stream->async_read_some();
            if (e)
            {
                if (e != boost::asio::error::eof && e != boost::asio::error::operation_aborted)
                    LOG_DEBUG("Stream {} downstream tunnel read error: {}", stream->id(), e.message());
                break;
            }
            if (data.empty())
            {
                LOG_DEBUG("Stream {} downstream received empty/EOF.", stream->id());
                break;
            }

            auto [we, wn] = co_await boost::asio::async_write(socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (we)
            {
                LOG_DEBUG("Stream {} downstream local write error: {}", stream->id(), we.message());
                break;
            }
        }
        boost::system::error_code ec;
        socket_.close(ec);
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
};

class local_client
{
   public:
    local_client(io_context_pool& pool,
                 std::string host,
                 std::string port,
                 uint16_t l_port,
                 std::string key_hex,
                 std::string sni,
                 boost::system::error_code& ec)
        : pool_(pool), r_host_(std::move(host)), r_port_(std::move(port)), l_port_(l_port), sni_(std::move(sni))
    {
        server_pub_key_ = reality::CryptoUtil::hex_to_bytes(key_hex, ec);
    }

    void start()
    {
        LOG_INFO("LocalClient starting on port {}, targetting {}:{}", l_port_, r_host_, r_port_);
        boost::asio::co_spawn(pool_.get_io_context(), connect_remote(), boost::asio::detached);
        boost::asio::co_spawn(pool_.get_io_context(), accept_local(), boost::asio::detached);
    }

   private:
    struct Transcript
    {
        EVP_MD_CTX* ctx;
        Transcript()
        {
            ctx = EVP_MD_CTX_new();
            EVP_DigestInit(ctx, EVP_sha256());
        }
        ~Transcript() { EVP_MD_CTX_free(ctx); }
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

    boost::asio::awaitable<void> connect_remote()
    {
        LOG_INFO("Initiating Reality Handshake to {}:{}...", r_host_, r_port_);
        boost::system::error_code ec;
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool_.get_io_context());
        boost::asio::ip::tcp::resolver res(pool_.get_io_context());
        auto [er, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (er)
        {
            LOG_ERROR("LocalClient resolve error: {}", er.message());
            co_return;
        }
        auto [ec_conn, ep] = co_await boost::asio::async_connect(*socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_conn)
        {
            LOG_ERROR("LocalClient connect error: {}", ec_conn.message());
            co_return;
        }

        LOG_DEBUG("TCP Connected to remote. Starting TLS handshake.");

        uint8_t cpub[32], cpriv[32];
        X25519_keypair(cpub, cpriv);
        std::vector<uint8_t> cpub_vec(cpub, cpub + 32);
        std::vector<uint8_t> shared = reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), server_pub_key_, ec);
        if (ec)
            co_return;

        std::vector<uint8_t> crand(32);
        RAND_bytes(crand.data(), 32);
        std::vector<uint8_t> salt(crand.begin(), crand.begin() + 20);
        boost::system::error_code ec_hex;
        std::vector<uint8_t> info = reality::CryptoUtil::hex_to_bytes("5245414c495459", ec_hex);
        std::vector<uint8_t> auth_key = reality::CryptoUtil::hkdf_expand(reality::CryptoUtil::hkdf_extract(salt, shared, ec), info, 32, ec);
        if (ec)
            co_return;

        std::vector<uint8_t> payload(16);
        payload[0] = 1;
        payload[1] = 8;
        uint32_t now = time(nullptr);
        payload[4] = (now >> 24) & 0xFF;
        payload[5] = (now >> 16) & 0xFF;
        payload[6] = (now >> 8) & 0xFF;
        payload[7] = now & 0xFF;
        RAND_bytes(payload.data() + 8, 8);

        std::vector<uint8_t> hello_aad = reality::construct_client_hello(crand, std::vector<uint8_t>(32, 0), cpub_vec, sni_);
        std::vector<uint8_t> nonce(crand.begin() + 20, crand.end());
        std::vector<uint8_t> sid = reality::CryptoUtil::aes_gcm_encrypt(auth_key, nonce, payload, hello_aad, ec);
        if (ec || sid.size() != 32)
            co_return;

        std::vector<uint8_t> ch = hello_aad;
        memcpy(ch.data() + 39, sid.data(), 32);
        std::vector<uint8_t> ch_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, ch.size());
        ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());

        if (auto [we, wn] =
                co_await boost::asio::async_write(*socket, boost::asio::buffer(ch_rec), boost::asio::as_tuple(boost::asio::use_awaitable));
            we)
            co_return;

        Transcript trans;
        trans.update(ch);
        uint8_t hbuf[5];
        if (auto [re, rn] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(hbuf, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
            re)
            co_return;
        uint16_t sh_len = (hbuf[3] << 8) | hbuf[4];
        std::vector<uint8_t> sh(sh_len);
        if (auto [re, rn] = co_await boost::asio::async_read(*socket, boost::asio::buffer(sh), boost::asio::as_tuple(boost::asio::use_awaitable)); re)
            co_return;
        trans.update(sh);

        std::vector<uint8_t> spub = reality::extract_server_public_key(sh);
        if (spub.size() != 32)
        {
            LOG_ERROR("Failed to extract server public key from ServerHello.");
            co_return;
        }

        std::vector<uint8_t> hs_shared = reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(cpriv, cpriv + 32), spub, ec);
        if (ec)
            co_return;

        auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(hs_shared, trans.finish(), ec);
        auto c_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        auto s_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);

        std::vector<uint8_t> buf_concat;
        uint64_t seq = 0;
        bool fin = false;
        while (!fin)
        {
            uint8_t rh[5];
            if (auto [re, rn] =
                    co_await boost::asio::async_read(*socket, boost::asio::buffer(rh, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
                re)
                co_return;
            uint16_t rlen = (rh[3] << 8) | rh[4];
            if (rh[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                std::vector<uint8_t> ign(rlen);
                co_await boost::asio::async_read(*socket, boost::asio::buffer(ign), boost::asio::as_tuple(boost::asio::use_awaitable));
                continue;
            }
            std::vector<uint8_t> rec(rlen);
            if (auto [re, rn] =
                    co_await boost::asio::async_read(*socket, boost::asio::buffer(rec), boost::asio::as_tuple(boost::asio::use_awaitable));
                re)
                co_return;

            std::vector<uint8_t> ct_head(5 + rlen);
            memcpy(ct_head.data(), rh, 5);
            memcpy(ct_head.data() + 5, rec.data(), rlen);
            uint8_t type;
            std::vector<uint8_t> pt = reality::TlsRecordLayer::decrypt_record(s_hs_keys.first, s_hs_keys.second, seq++, ct_head, type, ec);
            if (ec)
            {
                LOG_ERROR("Handshake decrypt error: {}", ec.message());
                co_return;
            }

            if (type == reality::CONTENT_TYPE_HANDSHAKE)
                buf_concat.insert(buf_concat.end(), pt.begin(), pt.end());

            size_t off = 0;
            while (off + 4 <= buf_concat.size())
            {
                uint8_t mt = buf_concat[off];
                uint32_t ml = (buf_concat[off + 1] << 16) | (buf_concat[off + 2] << 8) | buf_concat[off + 3];
                if (off + 4 + ml > buf_concat.size())
                    break;
                std::vector<uint8_t> msg(buf_concat.begin() + off, buf_concat.begin() + off + 4 + ml);
                if (mt == 0x08 || mt == 0x0b || mt == 0x0f)
                    trans.update(msg);
                else if (mt == 0x14)
                {
                    trans.update(msg);
                    fin = true;
                }
                if (mt == 0x0b)
                {
                }
                off += 4 + ml;
            }
            buf_concat.erase(buf_concat.begin(), buf_concat.begin() + off);
        }

        auto app_sec = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, trans.finish(), ec);
        auto c_fin_verify = reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, trans.finish(), ec);
        auto c_fin_msg = reality::construct_finished(c_fin_verify);
        auto c_fin_rec =
            reality::TlsRecordLayer::encrypt_record(c_hs_keys.first, c_hs_keys.second, 0, c_fin_msg, reality::CONTENT_TYPE_HANDSHAKE, ec);

        std::vector<uint8_t> out;
        out.push_back(0x14);
        out.push_back(3);
        out.push_back(3);
        out.push_back(0);
        out.push_back(1);
        out.push_back(1);
        out.insert(out.end(), c_fin_rec.begin(), c_fin_rec.end());
        if (auto [we, wn] = co_await boost::asio::async_write(*socket, boost::asio::buffer(out), boost::asio::as_tuple(boost::asio::use_awaitable));
            we)
            co_return;

        auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_sec.first, ec);
        auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_sec.second, ec);

        LOG_INFO("Reality Handshake success. Starting Tunnel.");

        RealityEngine re(s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);
        tunnel_manager_ = std::make_shared<mux_tunnel_impl<boost::asio::ip::tcp::socket>>(std::move(*socket), std::move(re));
        co_await tunnel_manager_->run();

        LOG_WARN("Tunnel connection lost. Reconnecting in 5s...");
        boost::asio::steady_timer timer(pool_.get_io_context());
        timer.expires_after(std::chrono::seconds(5));
        co_await timer.async_wait(boost::asio::use_awaitable);

        boost::asio::co_spawn(pool_.get_io_context(), connect_remote(), boost::asio::detached);
    }

    boost::asio::awaitable<void> accept_local()
    {
        auto ex = pool_.get_io_context().get_executor();
        boost::asio::ip::tcp::acceptor acceptor(ex, {boost::asio::ip::tcp::v4(), l_port_});
        LOG_INFO("Local SOCKS5 listening on {}", l_port_);
        for (;;)
        {
            boost::asio::ip::tcp::socket s(ex);
            auto [e] = co_await acceptor.async_accept(s, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!e)
            {
                if (tunnel_manager_ && tunnel_manager_->get_connection()->is_open())
                {
                    std::make_shared<socks_session>(std::move(s), tunnel_manager_)->start();
                }
                else
                {
                    LOG_WARN("Rejecting local connection: Tunnel not ready.");
                    boost::system::error_code ec;
                    s.close(ec);
                }
            }
        }
    }

    io_context_pool& pool_;
    std::string r_host_, r_port_;
    uint16_t l_port_;
    std::string sni_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_impl<boost::asio::ip::tcp::socket>> tunnel_manager_;
};

}    // namespace mux
#endif
