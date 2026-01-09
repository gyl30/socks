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
        : socket_(std::move(socket)), tunnel_(std::move(tunnel)), remote_endpoint_str_(get_remote_endpoint_string())
    {
    }

    void start()
    {
        auto self = shared_from_this();
        boost::asio::co_spawn(
            socket_.get_executor(), [self]() mutable -> boost::asio::awaitable<void> { co_await self->run(); }, boost::asio::detached);
    }

   private:
    std::string get_remote_endpoint_string()
    {
        boost::system::error_code ec;
        auto ep = socket_.remote_endpoint(ec);
        if (ec)
        {
            return "unknown";
        }
        return ep.address().to_string() + ":" + std::to_string(ep.port());
    }

    boost::asio::awaitable<void> run()
    {
        uint8_t version;
        auto [ec_read_ver, n_read_ver] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&version, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_ver)
        {
            LOG_ERROR("socks5 session {}: failed to read version: {}", remote_endpoint_str_, ec_read_ver.message());
            co_return;
        }
        if (version != socks::VER)
        {
            LOG_WARN("socks5 session {}: unsupported version {}", remote_endpoint_str_, version);
            co_return;
        }

        uint8_t nmethods;
        auto [ec_read_nmethods, n_read_nmethods] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&nmethods, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_nmethods)
        {
            LOG_ERROR("socks5 session {}: failed to read nmethods: {}", remote_endpoint_str_, ec_read_nmethods.message());
            co_return;
        }
        std::vector<uint8_t> methods(nmethods);
        auto [ec_read_methods, n_read_methods] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(methods), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_methods)
        {
            LOG_ERROR("socks5 session {}: failed to read methods: {}", remote_endpoint_str_, ec_read_methods.message());
            co_return;
        }

        uint8_t method_resp[] = {socks::VER, socks::METHOD_NO_AUTH};
        auto [ec_write_method, n_write_method] =
            co_await boost::asio::async_write(socket_, boost::asio::buffer(method_resp), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write_method)
        {
            LOG_ERROR("socks5 session {}: failed to write method response: {}", remote_endpoint_str_, ec_write_method.message());
            co_return;
        }

        uint8_t head[4];
        auto [ec_read_head, n_read_head] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(head), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_head)
        {
            LOG_ERROR("socks5 session {}: failed to read request head: {}", remote_endpoint_str_, ec_read_head.message());
            co_return;
        }

        if (head[1] != socks::CMD_CONNECT)
        {
            LOG_WARN("socks5 session {}: unsupported command {}", remote_endpoint_str_, head[1]);
            co_return;
        }

        std::string target_host;
        uint16_t target_port = 0;

        if (head[3] == socks::ATYP_IPV4)
        {
            boost::asio::ip::address_v4::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_ERROR("socks5 session {}: failed to read ipv4 address: {}", remote_endpoint_str_, ec.message());
                co_return;
            }
            target_host = boost::asio::ip::address_v4(bytes).to_string();
        }
        else if (head[3] == socks::ATYP_DOMAIN)
        {
            uint8_t len;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(&len, 1), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_ERROR("socks5 session {}: failed to read domain length: {}", remote_endpoint_str_, ec.message());
                co_return;
            }
            target_host.resize(len);
            auto [ec2, n2] =
                co_await boost::asio::async_read(socket_, boost::asio::buffer(target_host), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec2)
            {
                LOG_ERROR("socks5 session {}: failed to read domain: {}", remote_endpoint_str_, ec2.message());
                co_return;
            }
        }
        else if (head[3] == socks::ATYP_IPV6)
        {
            boost::asio::ip::address_v6::bytes_type bytes;
            auto [ec, n] = co_await boost::asio::async_read(socket_, boost::asio::buffer(bytes), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_ERROR("socks5 session {}: failed to read ipv6 address: {}", remote_endpoint_str_, ec.message());
                co_return;
            }
            target_host = boost::asio::ip::address_v6(bytes).to_string();
        }
        else
        {
            LOG_WARN("socks5 session {}: unsupported address type {}", remote_endpoint_str_, head[3]);
            co_return;
        }

        uint16_t port_n;
        auto [ec_read_port, n_read_port] =
            co_await boost::asio::async_read(socket_, boost::asio::buffer(&port_n, 2), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_port)
        {
            LOG_ERROR("socks5 session {}: failed to read port: {}", remote_endpoint_str_, ec_read_port.message());
            co_return;
        }
        target_port = ntohs(port_n);

        LOG_INFO("socks request from {} to {}:{}", remote_endpoint_str_, target_host, target_port);

        auto stream = tunnel_->create_stream();
        if (!stream)
        {
            LOG_ERROR("socks5 session {}: failed to create mux stream for target {}:{}", remote_endpoint_str_, target_host, target_port);
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

        boost::system::error_code ec_send_frame = co_await tunnel_->send_frame(h, std::move(syn_bytes));
        if (ec_send_frame)
        {
            LOG_ERROR("socks5 session {}: failed to send syn frame for target {}:{}: {}",
                      remote_endpoint_str_,
                      target_host,
                      target_port,
                      ec_send_frame.message());
            co_return;
        }

        uint8_t reply[] = {socks::VER, socks::REP_SUCCESS, 0x00, socks::ATYP_IPV4, 0, 0, 0, 0, 0, 0};
        auto [ec_write_reply, n_write_reply] =
            co_await boost::asio::async_write(socket_, boost::asio::buffer(reply), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write_reply)
        {
            LOG_ERROR("socks5 session {}: failed to write reply for target {}:{}: {}",
                      remote_endpoint_str_,
                      target_host,
                      target_port,
                      ec_write_reply.message());
            co_return;
        }

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (upstream(stream) || downstream(stream));

        LOG_INFO("socks5 session {} for {}:{} finished.", remote_endpoint_str_, target_host, target_port);
    }

    boost::asio::awaitable<void> upstream(std::shared_ptr<mux_stream> stream)
    {
        std::vector<uint8_t> buf(8192);
        for (;;)
        {
            auto [ec_read, n] = co_await socket_.async_read_some(boost::asio::buffer(buf), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read)
            {
                if (ec_read != boost::asio::error::eof)
                {
                    LOG_WARN("socks5 session {}: upstream read error: {}", remote_endpoint_str_, ec_read.message());
                }
                break;
            }

            auto ec_write = co_await stream->async_write_some(buf.data(), n);
            if (ec_write)
            {
                LOG_WARN("socks5 session {}: upstream write to mux error: {}", remote_endpoint_str_, ec_write.message());
                break;
            }
        }
        co_await stream->close();
    }

    boost::asio::awaitable<void> downstream(std::shared_ptr<mux_stream> stream)
    {
        for (;;)
        {
            auto [ec_read, data] = co_await stream->async_read_some();
            if (ec_read)
            {
                if (ec_read != boost::asio::experimental::error::channel_closed)
                {
                    LOG_WARN("socks5 session {}: downstream read from mux error: {}", remote_endpoint_str_, ec_read.message());
                }
                break;
            }

            if (data.empty())
                continue;

            auto [ec_write, n] =
                co_await boost::asio::async_write(socket_, boost::asio::buffer(data), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_write)
            {
                LOG_WARN("socks5 session {}: downstream write error: {}", remote_endpoint_str_, ec_write.message());
                break;
            }
        }
        boost::system::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
    const std::string remote_endpoint_str_;
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
        if (ec)
        {
            LOG_ERROR("invalid server public key provided not hex: {}", key_hex);
        }
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
        boost::system::error_code ec;
        LOG_INFO("client connecting to {}:{} sni: {}", r_host_, r_port_, sni_);

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(pool_.get_io_context());
        boost::asio::ip::tcp::resolver res(pool_.get_io_context());
        auto [ec_resolve, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_resolve)
        {
            LOG_ERROR("client resolve failed for {}:{}: {}", r_host_, r_port_, ec_resolve.message());
            co_return;
        }

        auto [ec_connect, ep] = co_await boost::asio::async_connect(*socket, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_connect)
        {
            LOG_ERROR("client connect failed to {}:{}: {}", r_host_, r_port_, ec_connect.message());
            co_return;
        }

        LOG_INFO("client connected starting reality handshake");

        uint8_t client_pub[32], client_priv[32];
        X25519_keypair(client_pub, client_priv);
        std::vector<uint8_t> client_pub_vec(client_pub, client_pub + 32);

        std::vector<uint8_t> shared_secret =
            reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(client_priv, client_priv + 32), server_pub_key_, ec);
        if (ec)
        {
            LOG_ERROR("client ecdh failed during initial key exchange: {}", ec.message());
            co_return;
        }
        LOG_DEBUG("client shared secret: {}", reality::CryptoUtil::bytes_to_hex(shared_secret));

        std::vector<uint8_t> client_random(32);
        RAND_bytes(client_random.data(), 32);

        std::vector<uint8_t> salt(client_random.begin(), client_random.begin() + 20);

        boost::system::error_code ec_hex_to_bytes;
        std::vector<uint8_t> reality_info_bytes = reality::CryptoUtil::hex_to_bytes("5245414c495459", ec_hex_to_bytes);

        std::vector<uint8_t> auth_key = reality::CryptoUtil::hkdf_extract(salt, shared_secret, ec);
        if (ec)
        {
            LOG_ERROR("client hkdf extract failed: {}", ec.message());
            co_return;
        }

        auth_key = reality::CryptoUtil::hkdf_expand(auth_key, reality_info_bytes, 32, ec);
        if (ec)
        {
            LOG_ERROR("client hkdf expand failed: {}", ec.message());
            co_return;
        }

        LOG_DEBUG("client auth key: {}", reality::CryptoUtil::bytes_to_hex(auth_key));

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
        std::vector<uint8_t> client_hello_aad = reality::construct_client_hello(client_random, zero_sid, client_pub_vec, sni_);

        if (client_hello_aad.size() < 39 + 32 || client_hello_aad[38] != 32)
        {
            LOG_ERROR("client generated clienthello structure mismatch");
            co_return;
        }

        std::vector<uint8_t> nonce(client_random.begin() + 20, client_random.end());
        LOG_DEBUG("client nonce: {}", reality::CryptoUtil::bytes_to_hex(nonce));

        std::vector<uint8_t> enc_sid = reality::CryptoUtil::aes_gcm_encrypt(auth_key, nonce, payload, client_hello_aad, ec);
        if (ec)
        {
            LOG_ERROR("client sid encryption failed: {}", ec.message());
            co_return;
        }

        if (enc_sid.size() != 32)
        {
            LOG_ERROR("client encrypted sid wrong size");
            co_return;
        }

        std::vector<uint8_t> client_hello = client_hello_aad;
        std::memcpy(client_hello.data() + 39, enc_sid.data(), 32);

        std::vector<uint8_t> ch_record;
        ch_record.reserve(5 + client_hello.size());

        std::vector<uint8_t> header = reality::write_record_header(reality::CONTENT_TYPE_HANDSHAKE, client_hello.size());
        ch_record.insert(ch_record.end(), header.begin(), header.end());
        ch_record.insert(ch_record.end(), client_hello.begin(), client_hello.end());

        LOG_DEBUG("client sending clienthello");
        auto [ec_write_ch, n_write_ch] =
            co_await boost::asio::async_write(*socket, boost::asio::buffer(ch_record), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write_ch)
        {
            LOG_ERROR("client failed to send clienthello: {}", ec_write_ch.message());
            co_return;
        }

        LOG_DEBUG("client clienthello sent waiting for serverhello");

        Transcript transcript;
        transcript.update(client_hello);

        uint8_t head_buf[5];
        auto [ec_read_sh_head, n_read_sh_head] =
            co_await boost::asio::async_read(*socket, boost::asio::buffer(head_buf, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_sh_head)
        {
            LOG_ERROR("client failed to read serverhello header: {}", ec_read_sh_head.message());
            co_return;
        }

        if (head_buf[0] != reality::CONTENT_TYPE_HANDSHAKE)
        {
            LOG_ERROR("client expected handshake record type 22 got {}", head_buf[0]);
            co_return;
        }
        uint16_t sh_len = (head_buf[3] << 8) | head_buf[4];
        LOG_DEBUG("client got serverhello header body length: {}", sh_len);

        std::vector<uint8_t> server_hello(sh_len);
        auto [ec_read_sh, n_read_sh] =
            co_await boost::asio::async_read(*socket, boost::asio::buffer(server_hello), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_read_sh)
        {
            LOG_ERROR("client failed to read serverhello body: {}", ec_read_sh.message());
            co_return;
        }
        LOG_DEBUG("client read serverhello body");

        transcript.update(server_hello);

        std::vector<uint8_t> server_ephemeral_pub = reality::extract_server_public_key(server_hello);
        if (server_ephemeral_pub.size() != 32)
        {
            LOG_ERROR("client server keyshare not found");
            co_return;
        }

        std::vector<uint8_t> shared_secret_hs =
            reality::CryptoUtil::x25519_derive(std::vector<uint8_t>(client_priv, client_priv + 32), server_ephemeral_pub, ec);
        if (ec)
        {
            LOG_ERROR("client handshake ecdh failed: {}", ec.message());
            co_return;
        }

        auto hs_keys = reality::TlsKeySchedule::derive_handshake_keys(shared_secret_hs, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive handshake keys: {}", ec.message());
            co_return;
        }

        auto client_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.client_handshake_traffic_secret, ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive client handshake traffic keys: {}", ec.message());
            co_return;
        }

        auto server_hs_keys = reality::TlsKeySchedule::derive_traffic_keys(hs_keys.server_handshake_traffic_secret, ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive server handshake traffic keys: {}", ec.message());
            co_return;
        }

        LOG_DEBUG("client handshake keys derived reading encrypted messages");

        std::vector<uint8_t> buffer;
        uint64_t server_seq = 0;
        bool finished_received = false;

        while (!finished_received)
        {
            uint8_t h[5];
            auto [ec_read_rec_head, n_read_rec_head] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(h, 5), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read_rec_head)
            {
                LOG_ERROR("client failed to read record header: {}", ec_read_rec_head.message());
                co_return;
            }

            uint16_t len = (h[3] << 8) | h[4];
            LOG_DEBUG("client read record header type: {}, len: {}", h[0], len);

            if (h[0] == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
            {
                std::vector<uint8_t> ignore(len);
                auto [ec_read_ignore, n_read_ignore] =
                    co_await boost::asio::async_read(*socket, boost::asio::buffer(ignore), boost::asio::as_tuple(boost::asio::use_awaitable));
                if (ec_read_ignore)
                {
                    LOG_ERROR("client failed to read ccs body: {}", ec_read_ignore.message());
                    co_return;
                }
                LOG_DEBUG("client ignored ccs");
                continue;
            }

            std::vector<uint8_t> record(len);
            auto [ec_read_record, n_read_record] =
                co_await boost::asio::async_read(*socket, boost::asio::buffer(record), boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec_read_record)
            {
                LOG_ERROR("client failed to read record body: {}", ec_read_record.message());
                co_return;
            }

            if (h[0] == reality::CONTENT_TYPE_APPLICATION_DATA)
            {
                std::vector<uint8_t> ct_with_header(5 + len);
                memcpy(ct_with_header.data(), h, 5);
                memcpy(ct_with_header.data() + 5, record.data(), len);

                uint8_t content_type;
                std::vector<uint8_t> pt = reality::TlsRecordLayer::decrypt_record(
                    server_hs_keys.first, server_hs_keys.second, server_seq++, ct_with_header, content_type, ec);

                if (ec)
                {
                    LOG_ERROR("client handshake message decryption failed: {}", ec.message());
                    co_return;
                }

                if (content_type == reality::CONTENT_TYPE_HANDSHAKE)
                {
                    buffer.insert(buffer.end(), pt.begin(), pt.end());
                }
                else
                {
                    LOG_ERROR("client unexpected inner content type: {}", content_type);
                    co_return;
                }
            }
            else
            {
                LOG_ERROR("client unexpected record type: {}", h[0]);
                co_return;
            }

            size_t offset = 0;
            while (offset + 4 <= buffer.size())
            {
                uint8_t type = buffer[offset];
                uint32_t msg_len = (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3];
                if (offset + 4 + msg_len > buffer.size())
                    break;

                std::vector<uint8_t> msg(buffer.begin() + offset, buffer.begin() + offset + 4 + msg_len);

                if (type == 0x08)
                {
                    LOG_DEBUG("client got encryptedextensions");
                    transcript.update(msg);
                }
                else if (type == 0x0b)
                {
                    LOG_DEBUG("client got certificate");
                    transcript.update(msg);

                    size_t c_pos = 4;
                    if (c_pos >= msg.size())
                    {
                        LOG_ERROR("client cert msg malformed at context len");
                        co_return;
                    }
                    uint8_t ctx_len = msg[c_pos++];
                    c_pos += ctx_len + 3;
                    if (c_pos + 3 > msg.size())
                    {
                        LOG_ERROR("client cert msg malformed at cert list len");
                        co_return;
                    }
                    uint32_t cert_len = (msg[c_pos] << 16) | (msg[c_pos + 1] << 8) | msg[c_pos + 2];
                    c_pos += 3;

                    const uint8_t* p = msg.data() + c_pos;
                    X509* cert = d2i_X509(NULL, &p, cert_len);
                    if (!cert)
                    {
                        LOG_ERROR("client failed to parse cert");
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
                        LOG_ERROR("client reality hmac verification failed");
                        co_return;
                    }
                    LOG_INFO("client reality auth success");
                }
                else if (type == 0x0f)
                {
                    LOG_DEBUG("client got certificateverify");
                    transcript.update(msg);
                }
                else if (type == 0x14)
                {
                    LOG_DEBUG("client got finished");
                    transcript.update(msg);
                    finished_received = true;
                }

                offset += 4 + msg_len;
            }
            buffer.erase(buffer.begin(), buffer.begin() + offset);
        }

        auto app_secrets = reality::TlsKeySchedule::derive_application_secrets(hs_keys.master_secret, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive application secrets: {}", ec.message());
            co_return;
        }

        auto client_verify_data =
            reality::TlsKeySchedule::compute_finished_verify_data(hs_keys.client_handshake_traffic_secret, transcript.finish(), ec);
        if (ec)
        {
            LOG_ERROR("client failed to compute finished verify data: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> client_fin_msg = reality::construct_finished(client_verify_data);

        std::vector<uint8_t> client_fin_rec = reality::TlsRecordLayer::encrypt_record(
            client_hs_keys.first, client_hs_keys.second, 0, client_fin_msg, reality::CONTENT_TYPE_HANDSHAKE, ec);
        if (ec)
        {
            LOG_ERROR("client failed to encrypt finished record: {}", ec.message());
            co_return;
        }

        std::vector<uint8_t> output;
        output.push_back(reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC);
        output.push_back(0x03);
        output.push_back(0x03);
        output.push_back(0x00);
        output.push_back(0x01);
        output.push_back(0x01);
        output.insert(output.end(), client_fin_rec.begin(), client_fin_rec.end());

        LOG_DEBUG("client sending client finished");
        auto [ec_write_fin, n_write_fin] =
            co_await boost::asio::async_write(*socket, boost::asio::buffer(output), boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec_write_fin)
        {
            LOG_ERROR("client failed to send finished message: {}", ec_write_fin.message());
            co_return;
        }

        auto c_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.first, ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive client application keys: {}", ec.message());
            co_return;
        }

        auto s_app_keys = reality::TlsKeySchedule::derive_traffic_keys(app_secrets.second, ec);
        if (ec)
        {
            LOG_ERROR("client failed to derive server application keys: {}", ec.message());
            co_return;
        }

        LOG_INFO("client reality tunnel established");

        auto reality_socket = std::make_shared<reality::reality_stream<boost::asio::ip::tcp::socket>>(
            std::move(*socket), s_app_keys.first, s_app_keys.second, c_app_keys.first, c_app_keys.second);

        tunnel_ = std::make_shared<mux_tunnel_impl<reality::reality_stream<boost::asio::ip::tcp::socket>>>(std::move(*reality_socket));
        co_await tunnel_->run();
    }

    boost::asio::awaitable<void> accept_local()
    {
        auto executor = pool_.get_io_context().get_executor();
        boost::asio::ip::tcp::acceptor acceptor(executor, {boost::asio::ip::tcp::v4(), l_port_});
        LOG_INFO("socks5 listening on port {}", l_port_);

        while (true)
        {
            boost::asio::ip::tcp::socket sock(executor);
            auto [ec] = co_await acceptor.async_accept(sock, boost::asio::as_tuple(boost::asio::use_awaitable));
            if (ec)
            {
                LOG_WARN("socks5 accept failed: {}", ec.message());
                continue;
            }

            if (tunnel_)
            {
                auto session = std::make_shared<socks_session>(std::move(sock), tunnel_);
                session->start();
            }
            else
            {
                LOG_WARN("no remote tunnel available dropping local connection");
                sock.close();
            }
        }
    }

    io_context_pool& pool_;
    std::string r_host_, r_port_;
    uint16_t l_port_;
    std::string sni_;
    std::vector<uint8_t> server_pub_key_;
    std::shared_ptr<mux_tunnel_interface> tunnel_;
};

}    // namespace mux

#endif
