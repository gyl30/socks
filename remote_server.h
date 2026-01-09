#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <algorithm>
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <ctime>
#include <array>

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_stream.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"

namespace mux
{

struct ClientHelloData
{
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> random;
    std::vector<uint8_t> x25519_pub;
    bool is_tls13 = false;
    uint32_t sid_offset = 0;
};

class CHParser
{
   public:
    static ClientHelloData parse(const std::vector<uint8_t>& buf)
    {
        ClientHelloData info;
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

        info.random.assign(p, p + 32);
        p += 32;
        len -= 32;

        uint8_t sid_len = *p;

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
        uint16_t cs_len = (p[0] << 8) | p[1];
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
        uint8_t comp_len = *p;
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
        uint16_t ext_len = (p[0] << 8) | p[1];
        p += 2;
        len -= 2;

        const uint8_t* ext_end = p + ext_len;
        if (len < ext_len)
        {
            return info;
        }

        while (p + 4 <= ext_end)
        {
            uint16_t etype = (p[0] << 8) | p[1];
            uint16_t elen = (p[2] << 8) | p[3];
            p += 4;

            if (p + elen > ext_end)
            {
                break;
            }

            if (etype == 0x0033)
            {
                if (elen >= 2)
                {
                    const uint8_t* share_ptr = p + 2;
                    const uint8_t* share_end = p + elen;

                    share_end = std::min(share_end, ext_end);

                    while (share_ptr + 4 <= share_end)
                    {
                        uint16_t group = (share_ptr[0] << 8) | share_ptr[1];
                        uint16_t key_len = (share_ptr[2] << 8) | share_ptr[3];
                        share_ptr += 4;

                        if (share_ptr + key_len > share_end)
                        {
                            break;
                        }

                        if (group == 0x001d && key_len == 32)
                        {
                            info.x25519_pub.assign(share_ptr, share_ptr + 32);
                            info.is_tls13 = true;
                            break;
                        }
                        share_ptr += key_len;
                    }
                }
            }
            p += elen;
        }
        return info;
    }
};

class remote_session : public std::enable_shared_from_this<remote_session>
{
   public:
    remote_session(std::shared_ptr<mux_tunnel_interface> tunnel, uint32_t id, const boost::asio::any_io_executor& ex)
        : tunnel_(std::move(tunnel)), id_(id), executor_(ex), resolver_(ex), target_socket_(ex)
    {
    }

    boost::asio::awaitable<void> start(std::vector<uint8_t> syn_data)
    {
        auto stream = tunnel_->accept_stream(id_);
        if (!stream)
        {
            LOG_ERROR("session {} could not accept mux stream", id_);
            co_return;
        }

        mux::SynPayload syn;
        if (!mux::SynPayload::decode(syn_data.data(), syn_data.size(), syn))
        {
            LOG_WARN("session {} received invalid syn payload", id_);
            co_await stream->close();
            co_return;
        }

        LOG_INFO("session {} connecting to {}:{}", id_, syn.addr, syn.port);

        auto [ec_resolve, eps] =
            co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_resolve)
        {
            LOG_ERROR("session {} failed to resolve {}:{}: {}", id_, syn.addr, syn.port, ec_resolve.message());
            co_await stream->close();
            co_return;
        }

        auto [ec_connect, ep] = co_await boost::asio::async_connect(target_socket_, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_connect)
        {
            LOG_ERROR("session {} failed to connect to {}:{}: {}", id_, syn.addr, syn.port, ec_connect.message());
            co_await stream->close();
            co_return;
        }

        LOG_INFO("session {} connected to target successfully", id_);

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (upstream(stream) || downstream(stream));

        boost::system::error_code ec;
        ec = target_socket_.close(ec);
        LOG_INFO("session {} for {}:{} finished", id_, syn.addr, syn.port);
    }

   private:
    boost::asio::awaitable<void> upstream(std::shared_ptr<mux_stream> stream)
    {
        for (;;)
        {
            auto [ec, data] = co_await stream->async_read_some();
            if (ec)
            {
                if (ec != boost::asio::experimental::error::channel_closed)
                {
                    LOG_WARN("session {} upstream read from mux error: {}", id_, ec.message());
                }
                break;
            }
            if (data.empty())
            {
                continue;
            }

            auto [ec_write, n] =
                co_await boost::asio::async_write(target_socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_write)
            {
                if (ec_write != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("session {} upstream write to target error: {}", id_, ec_write.message());
                }
                break;
            }
        }
        boost::system::error_code ec;
        target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }

    boost::asio::awaitable<void> downstream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            auto [ec_read, n] = co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read)
            {
                if (ec_read != boost::asio::error::eof && ec_read != boost::asio::error::operation_aborted)
                {
                    LOG_WARN("session {} downstream read from target error: {}", id_, ec_read.message());
                }
                break;
            }
            auto ec_write = co_await stream->async_write_some(buf.data(), n);
            if (ec_write)
            {
                LOG_WARN("session {} downstream write to mux error: {}", id_, ec_write.message());
                break;
            }
        }
        co_await stream->close();
    }

    std::shared_ptr<mux_tunnel_interface> tunnel_;
    uint32_t id_;
    boost::asio::any_io_executor executor_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket target_socket_;
};

class remote_server
{
   public:
    remote_server(
        io_context_pool& pool, uint16_t port, std::string fb_host, std::string fb_port, std::string auth_key_hex, boost::system::error_code& ec)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fallback_host_(std::move(fb_host)),
          fallback_port_(std::move(fb_port))
    {
        server_private_key_ = reality::CryptoUtil::hex_to_bytes(auth_key_hex, ec);
        if (ec)
        {
            LOG_ERROR("invalid server private key provided not hex: {}", auth_key_hex);
            return;
        }

        std::vector<uint8_t> pub = reality::CryptoUtil::extract_public_key(server_private_key_, ec);
        if (ec)
        {
            LOG_ERROR("could not extract public key from private key: {}", ec.message());
            return;
        }

        LOG_INFO("============================================================");
        LOG_INFO("server private key: {}", auth_key_hex);
        LOG_INFO("server public key : {}", reality::CryptoUtil::bytes_to_hex(pub));
        LOG_INFO("please use this public key for the client");
        LOG_INFO("============================================================");

        LOG_INFO("reality certificate manager initialized");
    }

    void start() { boost::asio::co_spawn(acceptor_.get_executor(), accept_loop(), boost::asio::detached); }

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
            EVP_MD_CTX* ctx_copy = EVP_MD_CTX_new();
            EVP_MD_CTX_copy(ctx_copy, ctx);
            std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));
            unsigned int len;
            EVP_DigestFinal(ctx_copy, hash.data(), &len);
            hash.resize(len);
            EVP_MD_CTX_free(ctx_copy);
            return hash;
        }
    };

    boost::asio::awaitable<void> accept_loop()
    {
        while (true)
        {
            auto sock = std::make_shared<boost::asio::ip::tcp::socket>(acceptor_.get_executor());
            auto [ec] = co_await acceptor_.async_accept(*sock, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec)
            {
                boost::system::error_code ec_ep;
                auto remote_ep = sock->remote_endpoint(ec_ep);
                LOG_INFO("server accepted connection from {}", ec_ep ? "unknown" : remote_ep.address().to_string());
                boost::asio::co_spawn(pool_.get_io_context(), [this, sock]() mutable { return handle_connection(sock); }, boost::asio::detached);
            }
            else
            {
                LOG_ERROR("server accept failed: {}", ec.message());
            }
        }
    }

    boost::asio::awaitable<void> handle_connection(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        boost::system::error_code ec;
        auto remote_ep_str = socket->remote_endpoint(ec).address().to_string();

        std::vector<uint8_t> buffer(4096);
        auto [ec_read, n] = co_await socket->async_read_some(boost::asio::buffer(buffer), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read)
        {
            LOG_ERROR("server failed to read initial data from client {}: {}", remote_ep_str, ec_read.message());
            co_return;
        }
        buffer.resize(n);

        if (n < 5)
        {
            LOG_WARN("server packet too short from client {}", remote_ep_str);
            co_return;
        }

        if (buffer[0] != 0x16)
        {
            LOG_WARN("server not a tls handshake record 0x{:02x} from client {}", buffer[0], remote_ep_str);
            co_await handle_fallback(socket, buffer);
            co_return;
        }

        uint16_t record_len = (buffer[3] << 8) | buffer[4];
        uint32_t full_len = 5 + record_len;

        while (buffer.size() < full_len)
        {
            std::vector<uint8_t> tmp(full_len - buffer.size());
            auto [ec_read_more, n2] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(tmp), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read_more)
            {
                LOG_ERROR("server failed to read full record from client {}: {}", remote_ep_str, ec_read_more.message());
                co_return;
            }
            buffer.insert(buffer.end(), tmp.begin(), tmp.begin() + static_cast<uint32_t>(n2));
        }

        std::vector<uint8_t> handshake_msg(buffer.begin() + 5, buffer.begin() + full_len);

        auto info = CHParser::parse(handshake_msg);
        bool authorized = false;
        std::vector<uint8_t> current_auth_key;

        LOG_DEBUG("server istls13={}, haspub={}, sidlen={}", info.is_tls13, !info.x25519_pub.empty(), info.session_id.size());

        if (info.is_tls13 && !info.x25519_pub.empty() && info.session_id.size() == 32)
        {
            auto shared = reality::CryptoUtil::x25519_derive(server_private_key_, info.x25519_pub, ec);
            if (!ec)
            {
                LOG_DEBUG("server shared secret: {}", reality::CryptoUtil::bytes_to_hex(shared));

                std::vector<uint8_t> salt(info.random.begin(), info.random.begin() + 20);
                std::vector<uint8_t> info_str = reality::CryptoUtil::hex_to_bytes("5245414c495459", ec);

                std::vector<uint8_t> prk = reality::CryptoUtil::hkdf_extract(salt, shared, ec);
                if (!ec)
                {
                    current_auth_key = reality::CryptoUtil::hkdf_expand(prk, info_str, 32, ec);
                }

                if (!ec)
                {
                    LOG_DEBUG("server auth key: {}", reality::CryptoUtil::bytes_to_hex(current_auth_key));

                    std::vector<uint8_t> nonce(info.random.begin() + 20, info.random.end());
                    LOG_DEBUG("server nonce: {}", reality::CryptoUtil::bytes_to_hex(nonce));

                    std::vector<uint8_t> aad = handshake_msg;
                    if (info.sid_offset + 32 <= aad.size())
                    {
                        std::fill(aad.begin() + info.sid_offset, aad.begin() + info.sid_offset + 32, 0);
                    }
                    else
                    {
                        LOG_ERROR("server invalid sid offset: {} vs size: {}", info.sid_offset, aad.size());
                    }

                    auto plaintext = reality::CryptoUtil::aes_gcm_decrypt(current_auth_key, nonce, info.session_id, aad, ec);

                    if (!ec && plaintext.size() == 16)
                    {
                        uint32_t ts = (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7];
                        auto now = static_cast<uint32_t>(std::time(nullptr));
                        uint32_t diff = (ts > now) ? (ts - now) : (now - ts);
                        LOG_INFO("server decrypted ok from client {} timediff={}s", remote_ep_str, diff);
                        if (diff < 120)
                        {
                            authorized = true;
                        }
                        else
                        {
                            LOG_WARN("server reality auth failed for {}: timestamp out of sync diff={}s", remote_ep_str, diff);
                        }
                    }
                    else
                    {
                        LOG_INFO("server reality payload decryption failed for client {} this is expected for non-proxy clients", remote_ep_str);
                    }
                }
                else
                {
                    LOG_WARN("server failed to derive auth key for client {}: {}", remote_ep_str, ec.message());
                }
            }
            else
            {
                LOG_WARN("server ecdh failed for client {}: {}", remote_ep_str, ec.message());
            }
        }

        if (authorized)
        {
            LOG_INFO("server identified reality client from {}, starting proxy handshake", remote_ep_str);
            std::vector<uint8_t> exact_record(buffer.begin(), buffer.begin() + full_len);
            co_await handle_reality_handshake(socket, exact_record, info, current_auth_key);
        }
        else
        {
            co_await handle_fallback(socket, buffer);
        }
    }

    boost::asio::awaitable<void> handle_reality_handshake(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                                          const std::vector<uint8_t>& client_hello_record,
                                                          const ClientHelloData& ch_info,
                                                          const std::vector<uint8_t>& auth_key)
    {
        boost::system::error_code ec;
        Transcript transcript;
        if (client_hello_record.size() > 5)
        {
            std::vector<uint8_t> ch_payload(client_hello_record.begin() + 5, client_hello_record.end());
            transcript.update(ch_payload);
        }

        uint8_t srv_pub[32];
        uint8_t srv_priv[32];
        X25519_keypair(srv_pub, srv_priv);
        std::vector<uint8_t> srv_pub_vec(srv_pub, srv_pub + 32);

        std::vector<uint8_t> srv_random(32);
        RAND_bytes(srv_random.data(), 32);

        std::vector<uint8_t> shared_hs = reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(srv_priv, srv_priv + 32), ch_info.x25519_pub, ec);
        if (ec)
        {
            LOG_ERROR("server handshake ecdh failed: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> server_hello = reality::construct_server_hello(srv_random, ch_info.session_id, 0x1301, srv_pub_vec);
        transcript.update(server_hello);

        auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(shared_hs, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive handshake keys: {}", ec.message());
            co_return;
        }

        auto client_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive client handshake traffic keys: {}", ec.message());
            co_return;
        }

        auto server_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive server handshake traffic keys: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> enc_ext = reality::construct_encrypted_extensions();
        transcript.update(enc_ext);

        std::vector<uint8_t> cert_der = cert_manager_.generate_reality_cert(auth_key);
        std::vector<uint8_t> cert = reality::construct_certificate(cert_der);
        transcript.update(cert);

        std::vector<uint8_t> cert_verify = reality::construct_certificate_verify(cert_manager_.get_key(), transcript.finish());
        transcript.update(cert_verify);

        auto srv_fin_verify = reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("server failed to compute finished verify data: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> server_finished = reality::construct_finished(srv_fin_verify);
        transcript.update(server_finished);

        std::vector<uint8_t> combined_payload;
        combined_payload.insert(combined_payload.end(), enc_ext.begin(), enc_ext.end());
        combined_payload.insert(combined_payload.end(), cert.begin(), cert.end());
        combined_payload.insert(combined_payload.end(), cert_verify.begin(), cert_verify.end());
        combined_payload.insert(combined_payload.end(), server_finished.begin(), server_finished.end());

        std::vector<uint8_t> enc_records = reality::TlsRecordLayer::encrypt_record(
            server_hs_keys.first, server_hs_keys.second, 0, combined_payload, reality::CONTENT_TYPE_HANDSHAKE, ec);
        if (ec)
        {
            LOG_ERROR("server failed to encrypt flight 2: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> flight;
        std::vector<uint8_t> sh_rec = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, server_hello.size());
        flight.insert(flight.end(), sh_rec.begin(), sh_rec.end());
        flight.insert(flight.end(), server_hello.begin(), server_hello.end());
        flight.push_back(reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC);
        flight.push_back(0x03);
        flight.push_back(0x03);
        flight.push_back(0x00);
        flight.push_back(0x01);
        flight.push_back(0x01);
        flight.insert(flight.end(), enc_records.begin(), enc_records.end());

        auto [ec_write_flight, n_write_flight] =
            co_await boost::asio::async_write(*socket, boost::asio::buffer(flight), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write_flight)
        {
            LOG_ERROR("server failed to write handshake flight: {}", ec_write_flight.message());
            co_return;
        }

        uint8_t h[5];
        auto [ec_read_h, n_read_h] =
            co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_h)
        {
            LOG_ERROR("server failed to read client finished header: {}", ec_read_h.message());
            co_return;
        }

        if (h[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        {
            uint8_t dummy;
            auto [ec_read_ccs, n_read_ccs] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(&dummy, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read_ccs)
            {
                LOG_ERROR("server failed to read client ccs body: {}", ec_read_ccs.message());
                co_return;
            }

            auto [ec_read_h2, n_read_h2] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read_h2)
            {
                LOG_ERROR("server failed to read client finished header after ccs: {}", ec_read_h2.message());
                co_return;
            }
        }

        if (h[0] != reality::CONTENT_TYPE_APPLICATION_DATA)
        {
            LOG_ERROR("server expected application data for client finished but got {}", h[0]);
            co_return;
        }
        uint16_t len = (h[3] << 8) | h[4];
        std::vector<uint8_t> record(len);
        auto [ec_read_fin_rec, n_read_fin_rec] =
            co_await boost::asio::async_read(*socket, boost::asio::buffer(record), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_fin_rec)
        {
            LOG_ERROR("server failed to read client finished record: {}", ec_read_fin_rec.message());
            co_return;
        }

        std::vector<uint8_t> ct_with_header(5 + len);
        memcpy(ct_with_header.data(), h, 5);
        memcpy(ct_with_header.data() + 5, record.data(), len);

        uint8_t type;
        std::vector<uint8_t> pt = reality::TlsRecordLayer::decrypt_record(client_hs_keys.first, client_hs_keys.second, 0, ct_with_header, type, ec);
        if (ec)
        {
            LOG_ERROR("server failed to decrypt client finished: {}", ec.message());
            co_return;
        }

        if (type != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("server invalid client finished message");
            co_return;
        }

        auto app_secrets = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive application secrets: {}", ec.message());
            co_return;
        }

        transcript.update(pt);

        auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.first, ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive client app keys: {}", ec.message());
            co_return;
        }

        auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.second, ec);
        if (ec)
        {
            LOG_ERROR("server failed to derive server app keys: {}", ec.message());
            co_return;
        }

        LOG_INFO("server reality handshake complete tunnel start");

        auto reality_socket = std::make_shared<reality::reality_stream<boost::asio::ip::tcp::socket>>(
            std::move(*socket), c_app_keys.first, c_app_keys.second, s_app_keys.first, s_app_keys.second);

        auto tunnel = std::make_shared<mux_tunnel_impl<reality::reality_stream<boost::asio::ip::tcp::socket>>>(std::move(*reality_socket));
        tunnel->set_syn_handler(
            [this, tunnel](uint32_t id, std::vector<uint8_t> p) -> boost::asio::awaitable<void>
            {
                auto& session_ctx = pool_.get_io_context();
                auto session = std::make_shared<remote_session>(tunnel, id, session_ctx.get_executor());

                boost::asio::co_spawn(
                    session_ctx,
                    [session, p = std::move(p)]() mutable -> boost::asio::awaitable<void> { co_await session->start(std::move(p)); },
                    boost::asio::detached);
                co_return;
            });
        co_await tunnel->run();
    }

    boost::asio::awaitable<void> handle_fallback(std::shared_ptr<boost::asio::ip::tcp::socket> client, std::vector<uint8_t> prefix)
    {
        boost::system::error_code ec_ep;
        auto client_ep_str = client->remote_endpoint(ec_ep).address().to_string();
        LOG_INFO("server forwarding non-proxy request from client {} to fallback {}:{}", client_ep_str, fallback_host_, fallback_port_);

        boost::asio::ip::tcp::socket target(client->get_executor());
        boost::asio::ip::tcp::resolver res(client->get_executor());
        auto [ec_resolve, eps] = co_await res.async_resolve(fallback_host_, fallback_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_resolve)
        {
            LOG_ERROR("server fallback resolve failed for {}:{}: {}", fallback_host_, fallback_port_, ec_resolve.message());
            co_return;
        }

        auto [ec_connect, ep] = co_await boost::asio::async_connect(target, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_connect)
        {
            LOG_ERROR("server fallback connect failed for {}:{}: {}", fallback_host_, fallback_port_, ec_connect.message());
            co_return;
        }

        auto [ec_write, n_write] =
            co_await boost::asio::async_write(target, boost::asio::buffer(prefix), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write)
        {
            LOG_ERROR("server fallback failed to write prefix to target: {}", ec_write.message());
            co_return;
        }

        auto transfer = [](boost::asio::ip::tcp::socket& from, boost::asio::ip::tcp::socket& to) -> boost::asio::awaitable<void>
        {
            std::array<char, 8192> data;
            for (;;)
            {
                auto [e, n] = co_await from.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (e)
                {
                    break;
                }
                auto [e2, n2] =
                    co_await boost::asio::async_write(to, boost::asio::buffer(data, n), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (e2)
                {
                    break;
                }
            }
        };
        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (transfer(*client, target) || transfer(target, *client));
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fallback_host_, fallback_port_;
    std::vector<uint8_t> server_private_key_;
    reality::CertManager cert_manager_;
};

}    // namespace mux

#endif
