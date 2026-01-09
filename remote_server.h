#ifndef REMOTE_SERVER_H
#define REMOTE_SERVER_H

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <ctime>
#include <array>
#include <iomanip>

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_stream.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"
#include "prefixed_stream.h"

namespace mux
{

struct ClientHelloData
{
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> random;
    std::vector<uint8_t> x25519_pub;
    bool is_tls13 = false;
    size_t sid_offset = 0;
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
            return info;

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
            return info;
        if (sid_len > 0)
        {
            info.session_id.assign(p, p + sid_len);
        }
        p += sid_len;
        len -= sid_len;

        if (len < 2)
            return info;
        uint16_t cs_len = (p[0] << 8) | p[1];
        p += 2;
        len -= 2;
        if (len < cs_len)
            return info;
        p += cs_len;
        len -= cs_len;

        if (len < 1)
            return info;
        uint8_t comp_len = *p;
        p += 1;
        len -= 1;
        if (len < comp_len)
            return info;
        p += comp_len;
        len -= comp_len;

        if (len < 2)
            return info;
        uint16_t ext_len = (p[0] << 8) | p[1];
        p += 2;
        len -= 2;

        const uint8_t* ext_end = p + ext_len;
        if (len < ext_len)
            return info;

        while (p + 4 <= ext_end)
        {
            uint16_t etype = (p[0] << 8) | p[1];
            uint16_t elen = (p[2] << 8) | p[3];
            p += 4;

            if (p + elen > ext_end)
                break;

            if (etype == 0x0033)
            {
                if (elen >= 2)
                {
                    uint16_t client_shares_len = (p[0] << 8) | p[1];
                    const uint8_t* share_ptr = p + 2;
                    const uint8_t* share_end = p + elen;

                    if (share_end > ext_end)
                        share_end = ext_end;

                    while (share_ptr + 4 <= share_end)
                    {
                        uint16_t group = (share_ptr[0] << 8) | share_ptr[1];
                        uint16_t key_len = (share_ptr[2] << 8) | share_ptr[3];
                        share_ptr += 4;

                        if (share_ptr + key_len > share_end)
                            break;

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
    remote_session(std::shared_ptr<mux_tunnel_interface> tunnel, uint32_t id, boost::asio::any_io_executor ex)
        : tunnel_(std::move(tunnel)), id_(id), executor_(ex), resolver_(ex), target_socket_(ex)
    {
    }

    boost::asio::awaitable<void> start(std::vector<uint8_t> syn_data)
    {
        auto stream = tunnel_->accept_stream(id_);
        if (!stream)
            co_return;

        mux::SynPayload syn;
        if (!mux::SynPayload::decode(syn_data.data(), syn_data.size(), syn))
        {
            LOG_WARN("Session {} invalid syn payload", id_);
            co_await stream->close();
            co_return;
        }

        LOG_INFO("Session {} connecting to {}:{}", id_, syn.addr, syn.port);

        bool connected = false;
        try
        {
            auto eps = co_await resolver_.async_resolve(syn.addr, std::to_string(syn.port), boost::asio::use_awaitable);
            co_await boost::asio::async_connect(target_socket_, eps, boost::asio::use_awaitable);
            connected = true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Session {} connect failed: {}", id_, e.what());
        }

        if (!connected)
        {
            co_await stream->close();
            co_return;
        }

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (upstream(stream) || downstream(stream));

        target_socket_.close();
    }

   private:
    boost::asio::awaitable<void> upstream(std::shared_ptr<mux_stream> stream)
    {
        try
        {
            while (true)
            {
                auto [ec, data] = co_await stream->async_read_some();
                if (ec)
                    break;
                if (data.empty())
                    continue;
                co_await boost::asio::async_write(target_socket_, boost::asio::buffer(data), boost::asio::use_awaitable);
            }
        }
        catch (...)
        {
        }
        target_socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send);
    }

    boost::asio::awaitable<void> downstream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        try
        {
            while (true)
            {
                size_t n = co_await target_socket_.async_read_some(boost::asio::buffer(buf), boost::asio::use_awaitable);
                co_await stream->async_write_some(buf.data(), n);
            }
        }
        catch (...)
        {
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
    remote_server(io_context_pool& pool, uint16_t port, std::string fb_host, std::string fb_port, std::string auth_key_hex)
        : pool_(pool),
          acceptor_(pool.get_io_context(), boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), port)),
          fallback_host_(std::move(fb_host)),
          fallback_port_(std::move(fb_port))
    {
        server_private_key_ = reality::CryptoUtil::hex_to_bytes(auth_key_hex);

        std::vector<uint8_t> pub = reality::CryptoUtil::extract_public_key(server_private_key_);
        LOG_INFO("============================================================");
        LOG_INFO("Server Private Key: {}", auth_key_hex);
        LOG_INFO("Server Public Key : {}", reality::CryptoUtil::bytes_to_hex(pub));
        LOG_INFO("PLEASE USE THIS PUBLIC KEY FOR THE CLIENT!");
        LOG_INFO("============================================================");

        LOG_INFO("REALITY Certificate Manager Initialized (Synthetic Ed25519).");
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
                LOG_INFO("[Server] Accepted connection from {}", sock->remote_endpoint().address().to_string());
                boost::asio::co_spawn(pool_.get_io_context(), [this, sock]() mutable { return handle_connection(sock); }, boost::asio::detached);
            }
            else
            {
                LOG_ERROR("[Server] Accept failed: {}", ec.message());
            }
        }
    }

    boost::asio::awaitable<void> handle_connection(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    {
        std::vector<uint8_t> buffer(4096);
        auto [ec, n] = co_await socket->async_read_some(boost::asio::buffer(buffer), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
        {
            LOG_ERROR("Read failed: {}", ec.message());
            co_return;
        }
        buffer.resize(n);

        if (n < 5)
        {
            LOG_ERROR("Packet too short");
            co_return;
        }

        if (buffer[0] != 0x16)
        {
            LOG_WARN("[Server] Not a TLS Handshake Record (0x{:02x})", buffer[0]);
            co_await handle_fallback(socket, buffer);
            co_return;
        }

        uint16_t record_len = (buffer[3] << 8) | buffer[4];
        size_t full_len = 5 + record_len;

        while (buffer.size() < full_len)
        {
            std::vector<uint8_t> tmp(full_len - buffer.size());
            auto [ec2, n2] = co_await boost::asio::async_read(*socket, boost::asio::buffer(tmp), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
                break;
            buffer.insert(buffer.end(), tmp.begin(), tmp.begin() + n2);
        }

        if (buffer.size() < full_len)
        {
            LOG_ERROR("Incomplete record");
            co_return;
        }

        std::vector<uint8_t> handshake_msg(buffer.begin() + 5, buffer.begin() + full_len);

        auto info = CHParser::parse(handshake_msg);
        bool authorized = false;
        std::vector<uint8_t> current_auth_key;

        LOG_INFO("[Server] IsTLS13={}, HasPub={}, SIDLen={}", info.is_tls13, !info.x25519_pub.empty(), info.session_id.size());

        if (info.is_tls13 && !info.x25519_pub.empty() && info.session_id.size() == 32)
        {
            auto shared = reality::CryptoUtil::x25519_derive(server_private_key_, info.x25519_pub);
            if (!shared.empty())
            {
                LOG_INFO("[Server] Shared Secret: {}", reality::CryptoUtil::bytes_to_hex(shared));

                std::vector<uint8_t> salt(info.random.begin(), info.random.begin() + 20);
                std::vector<uint8_t> info_str = reality::CryptoUtil::hex_to_bytes("5245414c495459");
                std::vector<uint8_t> prk = reality::CryptoUtil::hkdf_extract(salt, shared);
                current_auth_key = reality::CryptoUtil::hkdf_expand(prk, info_str, 32);

                LOG_INFO("[Server] Auth Key: {}", reality::CryptoUtil::bytes_to_hex(current_auth_key));

                std::vector<uint8_t> nonce(info.random.begin() + 20, info.random.end());
                LOG_INFO("[Server] Nonce: {}", reality::CryptoUtil::bytes_to_hex(nonce));

                std::vector<uint8_t> aad = handshake_msg;

                if (info.sid_offset + 32 <= aad.size())
                {
                    std::fill(aad.begin() + info.sid_offset, aad.begin() + info.sid_offset + 32, 0);
                }
                else
                {
                    LOG_ERROR("Invalid SID Offset: {} vs Size: {}", info.sid_offset, aad.size());
                }

                auto plaintext = reality::CryptoUtil::aes_gcm_decrypt(current_auth_key, nonce, info.session_id, aad);

                if (plaintext.size() == 16)
                {
                    uint32_t ts = (plaintext[4] << 24) | (plaintext[5] << 16) | (plaintext[6] << 8) | plaintext[7];
                    uint32_t now = static_cast<uint32_t>(std::time(nullptr));
                    uint32_t diff = (ts > now) ? (ts - now) : (now - ts);
                    LOG_INFO("[Server] Decrypted OK. TimeDiff={}s", diff);
                    if (diff < 120)
                        authorized = true;
                }
                else
                {
                    LOG_WARN("[Server] Decryption Failed.");
                }
            }
            else
            {
                LOG_WARN("[Server] ECDH Failed");
            }
        }

        if (authorized)
        {
            LOG_INFO("[Server] Hijacking connection...");
            std::vector<uint8_t> exact_record(buffer.begin(), buffer.begin() + full_len);
            co_await handle_reality_handshake(socket, exact_record, info, current_auth_key);
        }
        else
        {
            LOG_INFO("[Server] Falling back...");
            co_await handle_fallback(socket, buffer);
        }
    }

    boost::asio::awaitable<void> handle_reality_handshake(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                                                          const std::vector<uint8_t>& client_hello_record,
                                                          const ClientHelloData& ch_info,
                                                          const std::vector<uint8_t>& auth_key)
    {
        Transcript transcript;
        if (client_hello_record.size() > 5)
        {
            std::vector<uint8_t> ch_payload(client_hello_record.begin() + 5, client_hello_record.end());
            transcript.update(ch_payload);
        }

        uint8_t srv_pub[32], srv_priv[32];
        X25519_keypair(srv_pub, srv_priv);
        std::vector<uint8_t> srv_pub_vec(srv_pub, srv_pub + 32);

        std::vector<uint8_t> srv_random(32);
        RAND_bytes(srv_random.data(), 32);

        std::vector<uint8_t> shared_hs = reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(srv_priv, srv_priv + 32), ch_info.x25519_pub);

        std::vector<uint8_t> server_hello = reality::construct_server_hello(srv_random, ch_info.session_id, 0x1301, srv_pub_vec);
        transcript.update(server_hello);

        auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(shared_hs, transcript.finish());
        auto client_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret);
        auto server_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret);

        std::vector<uint8_t> enc_ext = reality::construct_encrypted_extensions();
        transcript.update(enc_ext);

        std::vector<uint8_t> cert_der = cert_manager_.generate_reality_cert(auth_key);
        std::vector<uint8_t> cert = reality::construct_certificate(cert_der);
        transcript.update(cert);

        std::vector<uint8_t> cert_verify = reality::construct_certificate_verify(cert_manager_.get_key(), transcript.finish());
        transcript.update(cert_verify);

        std::vector<uint8_t> server_finished = reality::construct_finished(
            reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.server_handshake_traffic_secret, transcript.finish()));
        transcript.update(server_finished);

        std::vector<uint8_t> combined_payload;
        combined_payload.insert(combined_payload.end(), enc_ext.begin(), enc_ext.end());
        combined_payload.insert(combined_payload.end(), cert.begin(), cert.end());
        combined_payload.insert(combined_payload.end(), cert_verify.begin(), cert_verify.end());
        combined_payload.insert(combined_payload.end(), server_finished.begin(), server_finished.end());

        std::vector<uint8_t> enc_records = reality::TlsRecordLayer::encrypt_record(
            server_hs_keys.first, server_hs_keys.second, 0, combined_payload, reality::CONTENT_TYPE_HANDSHAKE);

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

        co_await boost::asio::async_write(*socket, boost::asio::buffer(flight), boost::asio::use_awaitable);

        uint8_t h[5];
        co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::use_awaitable);

        if (h[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        {
            uint8_t dummy;
            co_await boost::asio::async_read(*socket, boost::asio::buffer(&dummy, 1), boost::asio::use_awaitable);
            co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::use_awaitable);
        }

        if (h[0] != reality::CONTENT_TYPE_APPLICATION_DATA)
        {
            LOG_ERROR("Exp AppData for Client Fin");
            co_return;
        }
        uint16_t len = (h[3] << 8) | h[4];
        std::vector<uint8_t> record(len);
        co_await boost::asio::async_read(*socket, boost::asio::buffer(record), boost::asio::use_awaitable);

        std::vector<uint8_t> ct_with_header(5 + len);
        memcpy(ct_with_header.data(), h, 5);
        memcpy(ct_with_header.data() + 5, record.data(), len);

        uint8_t type;
        std::vector<uint8_t> pt = reality::TlsRecordLayer::decrypt_record(client_hs_keys.first, client_hs_keys.second, 0, ct_with_header, type);

        if (type != reality::CONTENT_TYPE_HANDSHAKE || pt.empty() || pt[0] != 0x14)
        {
            LOG_ERROR("Invalid Client Finished");
            co_return;
        }

        auto app_secrets = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, transcript.finish());

        transcript.update(pt);

        auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.first);
        auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.second);

        LOG_INFO("[Server] REALITY Handshake Complete. Tunnel Start.");

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
        boost::asio::ip::tcp::socket target(client->get_executor());
        boost::asio::ip::tcp::resolver res(client->get_executor());
        auto [ec, eps] = co_await res.async_resolve(fallback_host_, fallback_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (!ec)
        {
            auto [ec2, ep] = co_await boost::asio::async_connect(target, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (!ec2)
            {
                co_await boost::asio::async_write(target, boost::asio::buffer(prefix), boost::asio::as_tuple(boost::asio::use_awaitable));
                auto transfer = [](boost::asio::ip::tcp::socket& from, boost::asio::ip::tcp::socket& to) -> boost::asio::awaitable<void>
                {
                    std::array<char, 8192> data;
                    while (true)
                    {
                        auto [e, n] = co_await from.async_read_some(boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
                        if (e)
                            break;
                        co_await boost::asio::async_write(to, boost::asio::buffer(data, n), boost::asio::as_tuple(boost::asio::use_awaitable));
                    }
                };
                using boost::asio::experimental::awaitable_operators::operator||;
                co_await (transfer(*client, target) || transfer(target, *client));
            }
            else
            {
                LOG_ERROR("[Server] Fallback connect failed: {}", ec2.message());
            }
        }
        else
        {
            LOG_ERROR("[Server] Fallback resolve failed: {}", ec.message());
        }
    }

    io_context_pool& pool_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::string fallback_host_, fallback_port_;
    std::vector<uint8_t> server_private_key_;
    reality::CertManager cert_manager_;
};

}    // namespace mux

#endif
