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
#include "reality_stream.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"
#include "protocol.h"

namespace mux
{

class socks_session : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket, std::shared_ptr<mux_tunnel_interface> tunnel)
        : socket_(std::move(socket)), tunnel_(std::move(tunnel))
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
        try
        {
            uint8_t version;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::use_awaitable);
            if (version != socks::VER)
                co_return;

            uint8_t nmethods;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::use_awaitable);
            std::vector<uint8_t> methods(nmethods);
            co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::use_awaitable);

            uint8_t method_resp[] = {socks::VER, socks::METHOD_NO_AUTH};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(method_resp), boost::asio::use_awaitable);

            uint8_t head[4];
            co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::use_awaitable);
            if (head[1] != socks::CMD_CONNECT)
                co_return;

            std::string target_host;
            uint16_t target_port = 0;

            if (head[3] == socks::ATYP_IPV4)
            {
                boost::asio::ip::address_v4::bytes_type bytes;
                co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
                target_host = boost::asio::ip::address_v4(bytes).to_string();
            }
            else if (head[3] == socks::ATYP_DOMAIN)
            {
                uint8_t len;
                co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::use_awaitable);
                target_host.resize(len);
                co_await boost::asio::async_read(socket_, boost::asio::buffer(target_host), boost::asio::use_awaitable);
            }
            else if (head[3] == socks::ATYP_IPV6)
            {
                boost::asio::ip::address_v6::bytes_type bytes;
                co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::use_awaitable);
                target_host = boost::asio::ip::address_v6(bytes).to_string();
            }
            else
            {
                co_return;
            }

            uint16_t port_n;
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&port_n, 2), boost::asio::use_awaitable);
            target_port = ntohs(port_n);

            LOG_INFO("Socks request to {}:{}", target_host, target_port);

            auto stream = tunnel_->create_stream();
            if (!stream)
            {
                LOG_ERROR("Failed to create mux stream");
                co_return;
            }

            SynPayload syn;
            syn.socks_cmd = socks::CMD_CONNECT;
            syn.addr = target_host;
            syn.port = target_port;
            auto syn_bytes = syn.encode();

            FrameHeader h;
            h.stream_id = stream->id();
            h.length = static_cast<uint16_t>(syn_bytes.size());
            h.command = CMD_SYN;

            boost::system::error_code ec = co_await tunnel_->send_frame(h, std::move(syn_bytes));
            if (ec)
            {
                LOG_ERROR("Failed to send SYN frame: {}", ec.message());
                co_return;
            }

            uint8_t reply[] = {socks::VER, socks::REP_SUCCESS, 0x00, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
            co_await boost::asio::async_write(socket_, boost::asio::buffer(reply), boost::asio::use_awaitable);

            using boost::asio::experimental::awaitable_operators::operator||;
            co_await (upstream(stream) || downstream(stream));
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG("Socks session error: {}", e.what());
        }
    }

    boost::asio::awaitable<void> upstream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        try
        {
            while (true)
            {
                auto n = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::use_awaitable);
                co_await stream->async_write_some(buf.data(), n);
            }
        }
        catch (...)
        {
        }
        co_await stream->close();
    }

    boost::asio::awaitable<void> downstream(std::shared_ptr<mux_stream> stream)
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
                co_await boost::asio::async_write(socket_, boost::asio::buffer(data), boost::asio::use_awaitable);
            }
        }
        catch (...)
        {
        }
        socket_.close();
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
};

class local_client
{
   public:
    local_client(io_context_pool& pool, std::string host, std::string port, uint16_t l_port, std::string key_hex)
        : pool_(pool), r_host_(std::move(host)), r_port_(std::move(port)), l_port_(l_port)
    {
        server_pub_key_ = reality::CryptoUtil::hex_to_bytes(key_hex);
    }

    void start()
    {
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

    boost::asio::awaitable<void> connect_remote()
    {
        try
        {
            LOG_INFO("[Client] Connecting to {}:{}", r_host_, r_port_);

            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool_.get_io_context());
            boost::asio::ip::tcp::resolver res(pool_.get_io_context());
            auto [ec, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_ERROR("Resolve failed: {}", ec.message());
                co_return;
            }

            auto [ec2, ep] = co_await boost::asio::async_connect(*socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
            {
                LOG_ERROR("Connect failed: {}", ec2.message());
                co_return;
            }

            LOG_INFO("[Client] Connected. Starting REALITY Handshake...");

            uint8_t client_pub[32], client_priv[32];
            X25519_keypair(client_pub, client_priv);
            std::vector<uint8_t> client_pub_vec(client_pub, client_pub + 32);

            std::vector<uint8_t> shared_secret =
                reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(client_priv, client_priv + 32), server_pub_key_);

            if (shared_secret.empty())
            {
                LOG_ERROR("ECDH failed");
                co_return;
            }
            LOG_DEBUG("[Client] Shared Secret: {}", reality::CryptoUtil::bytes_to_hex(shared_secret));

            std::vector<uint8_t> client_random(32);
            RAND_bytes(client_random.data(), 32);

            std::vector<uint8_t> salt(client_random.begin(), client_random.begin() + 20);
            std::vector<uint8_t> auth_key = reality::CryptoUtil::hkdf_extract(salt, shared_secret);
            auth_key = reality::CryptoUtil::hkdf_expand(auth_key, reality::CryptoUtil::hex_to_bytes("5245414c495459"), 32);
            LOG_DEBUG("[Client] Auth Key: {}", reality::CryptoUtil::bytes_to_hex(auth_key));

            std::vector<uint8_t> payload(16);
            payload[0] = 1;
            payload[1] = 8;
            payload[2] = 0;
            payload[3] = 0;
            uint32_t now = static_cast<uint32_t>(std::time(nullptr));
            payload[4] = (now >> 24) & 0xFF;
            payload[5] = (now >> 16) & 0xFF;
            payload[6] = (now >> 8) & 0xFF;
            payload[7] = now & 0xFF;
            RAND_bytes(payload.data() + 8, 8);

            std::vector<uint8_t> zero_sid(32, 0);
            std::vector<uint8_t> aad = reality::construct_client_hello(client_random, zero_sid, client_pub_vec, r_host_);

            LOG_DEBUG("[Client] AAD Size: {}, Header: {:02x} {:02x} {:02x} {:02x} {:02x}", aad.size(), aad[0], aad[1], aad[2], aad[3], aad[4]);

            std::vector<uint8_t> nonce(client_random.begin() + 20, client_random.end());
            LOG_DEBUG("[Client] Nonce: {}", reality::CryptoUtil::bytes_to_hex(nonce));

            std::vector<uint8_t> enc_sid = reality::CryptoUtil::aes_gcm_encrypt(auth_key, nonce, payload, aad);

            if (enc_sid.size() != 32)
            {
                LOG_ERROR("Encrypted SID wrong size");
                co_return;
            }

            std::vector<uint8_t> client_hello = reality::construct_client_hello(client_random, enc_sid, client_pub_vec, r_host_);

            std::vector<uint8_t> ch_record;
            ch_record.reserve(5 + client_hello.size());
            std::vector<uint8_t> header = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, client_hello.size());
            ch_record.insert(ch_record.end(), header.begin(), header.end());
            ch_record.insert(ch_record.end(), client_hello.begin(), client_hello.end());

            LOG_DEBUG("[Client] Sending ClientHello...");
            co_await boost::asio::async_write(*socket, boost::asio::buffer(ch_record), boost::asio::use_awaitable);
            LOG_DEBUG("[Client] ClientHello sent. Waiting for ServerHello...");

            Transcript transcript;
            transcript.update(client_hello);

            uint8_t head_buf[5];
            co_await boost::asio::async_read(*socket, boost::asio::buffer(head_buf, 5), boost::asio::use_awaitable);
            if (head_buf[0] != reality::CONTENT_TYPE_HANDSHAKE)
            {
                LOG_ERROR("Expected Handshake(22), got {}", head_buf[0]);
                co_return;
            }
            uint16_t sh_len = (head_buf[3] << 8) | head_buf[4];
            LOG_DEBUG("[Client] Got ServerHello Header. Body Length: {}", sh_len);

            std::vector<uint8_t> server_hello(sh_len);
            co_await boost::asio::async_read(*socket, boost::asio::buffer(server_hello), boost::asio::use_awaitable);
            LOG_DEBUG("[Client] Read ServerHello Body.");

            transcript.update(server_hello);

            std::vector<uint8_t> server_ephemeral_pub = reality::extract_server_public_key(server_hello);
            if (server_ephemeral_pub.size() != 32)
            {
                LOG_ERROR("Server KeyShare not found");
                co_return;
            }

            std::vector<uint8_t> shared_secret_hs =
                reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(client_priv, client_priv + 32), server_ephemeral_pub);
            if (shared_secret_hs.empty())
            {
                LOG_ERROR("HS ECDH failed");
                co_return;
            }

            auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(shared_secret_hs, transcript.finish());
            auto client_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret);
            auto server_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret);

            LOG_DEBUG("[Client] Handshake Keys Derived. Reading Encrypted Messages...");

            std::vector<uint8_t> buffer;
            uint64_t server_seq = 0;
            bool finished_received = false;

            while (!finished_received)
            {
                uint8_t h[5];
                co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::use_awaitable);
                uint16_t len = (h[3] << 8) | h[4];
                LOG_DEBUG("[Client] Read Record Header. Type: {}, Len: {}", h[0], len);

                if (h[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
                {
                    std::vector<uint8_t> ignore(len);
                    co_await boost::asio::async_read(*socket, boost::asio::buffer(ignore), boost::asio::use_awaitable);
                    LOG_DEBUG("[Client] Ignored CCS");
                    continue;
                }

                std::vector<uint8_t> record(len);
                co_await boost::asio::async_read(*socket, boost::asio::buffer(record), boost::asio::use_awaitable);

                if (h[0] == reality::CONTENT_TYPE_APPLICATION_DATA)
                {
                    std::vector<uint8_t> ct_with_header(5 + len);
                    memcpy(ct_with_header.data(), h, 5);
                    memcpy(ct_with_header.data() + 5, record.data(), len);

                    uint8_t content_type;
                    try
                    {
                        std::vector<uint8_t> pt = reality::TlsRecordLayer::decrypt_record(
                            server_hs_keys.first, server_hs_keys.second, server_seq++, ct_with_header, content_type);

                        if (content_type == reality::CONTENT_TYPE_HANDSHAKE)
                        {
                            buffer.insert(buffer.end(), pt.begin(), pt.end());
                        }
                        else
                        {
                            LOG_ERROR("Unexpected inner content type: {}", content_type);
                            co_return;
                        }
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR("Decrypt error: {}", e.what());
                        co_return;
                    }
                }
                else
                {
                    LOG_ERROR("Unexpected record type: {}", h[0]);
                    co_return;
                }

                size_t offset = 0;
                while (offset + 4 <= buffer.size())
                {
                    uint8_t type = buffer[offset];
                    uint32_t len = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
                    if (offset + 4 + len > buffer.size())
                        break;

                    std::vector<uint8_t> msg(buffer.begin() + offset, buffer.begin() + offset + 4 + len);

                    if (type == 0x08)
                    {
                        LOG_DEBUG("[Client] Got EncryptedExtensions");
                        transcript.update(msg);
                    }
                    else if (type == 0x0b)
                    {
                        LOG_DEBUG("[Client] Got Certificate");
                        transcript.update(msg);

                        size_t c_pos = 4;
                        uint8_t ctx_len = msg[c_pos++];
                        c_pos += ctx_len + 3;
                        if (c_pos + 3 > msg.size())
                        {
                            LOG_ERROR("Cert msg malformed");
                            co_return;
                        }
                        uint32_t cert_len = (msg[c_pos] << 16) | (msg[c_pos + 1] << 8) | msg[c_pos + 2];
                        c_pos += 3;

                        const uint8_t* p = msg.data() + c_pos;
                        X509* cert = d2i_X509(NULL, &p, cert_len);
                        if (!cert)
                        {
                            LOG_ERROR("Failed to parse cert");
                            co_return;
                        }

                        EVP_PKEY* pub = X509_get0_pubkey(cert);
                        uint8_t pub_raw[32];
                        size_t pub_len = 32;
                        EVP_PKEY_get_raw_public_key(pub, pub_raw, &pub_len);

                        uint8_t hmac_sig[64];
                        unsigned int hmac_len;
                        HMAC(EVP_sha512(), auth_key.data(), auth_key.size(), pub_raw, 32, hmac_sig, &hmac_len);

                        const ASN1_BIT_STRING* sig;
                        const X509_ALGOR* alg;
                        X509_get0_signature(&sig, &alg, cert);

                        bool verified = (sig && sig->length == 64 && memcmp(sig->data, hmac_sig, 64) == 0);
                        X509_free(cert);

                        if (!verified)
                        {
                            LOG_ERROR("REALITY HMAC Verification Failed!");
                            co_return;
                        }
                        LOG_INFO("[Client] REALITY Auth Success!");
                    }
                    else if (type == 0x0f)
                    {
                        LOG_DEBUG("[Client] Got CertificateVerify");
                        transcript.update(msg);
                    }
                    else if (type == 0x14)
                    {
                        LOG_DEBUG("[Client] Got Finished");
                        transcript.update(msg);
                        finished_received = true;
                    }

                    offset += 4 + len;
                }
                buffer.erase(buffer.begin(), buffer.begin() + offset);
            }

            auto app_secrets = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, transcript.finish());

            auto client_verify_data =
                reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, transcript.finish());
            std::vector<uint8_t> client_fin_msg = reality::construct_finished(client_verify_data);

            std::vector<uint8_t> client_fin_rec = reality::TlsRecordLayer::encrypt_record(
                client_hs_keys.first, client_hs_keys.second, 0, client_fin_msg, reality::CONTENT_TYPE_HANDSHAKE);

            std::vector<uint8_t> output;
            output.push_back(reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC);
            output.push_back(0x03);
            output.push_back(0x03);
            output.push_back(0x00);
            output.push_back(0x01);
            output.push_back(0x01);
            output.insert(output.end(), client_fin_rec.begin(), client_fin_rec.end());

            LOG_DEBUG("[Client] Sending Client Finished...");
            co_await boost::asio::async_write(*socket, boost::asio::buffer(output), boost::asio::use_awaitable);

            auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.first);
            auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.second);

            LOG_INFO("[Client] REALITY Tunnel Established.");

            auto reality_socket = std::make_shared<reality::reality_stream<boost::asio::ip::tcp::socket>>(
                std::move(*socket), s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);

            tunnel_ = std::make_shared<mux_tunnel_impl<reality::reality_stream<boost::asio::ip::tcp::socket>>>(std::move(*reality_socket));
            co_await tunnel_->run();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("[Client] Connection Exception: {}", e.what());
        }
    }

    boost::asio::awaitable<void> accept_local()
    {
        auto executor = pool_.get_io_context().get_executor();
        boost::asio::ip::tcp::acceptor acceptor(executor, {boost::asio::ip::tcp::v4(), l_port_});
        LOG_INFO("Socks5 listening on {}", l_port_);

        while (true)
        {
            boost::asio::ip::tcp::socket sock(executor);
            auto [ec] = co_await acceptor.async_accept(sock, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
                continue;

            if (tunnel_)
            {
                auto session = std::make_shared<socks_session>(std::move(sock), tunnel_);
                session->start();
            }
            else
            {
                sock.close();
            }
        }
    }

    io_context_pool& pool_;
    std::string r_host_, r_port_;
    uint16_t l_port_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
};

}    // namespace mux

#endif
