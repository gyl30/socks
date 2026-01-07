#ifndef LOCAL_CLIENT_H
#define LOCAL_CLIENT_H

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "reality_core.h"
#include "mux_tunnel.h"
#include "log.h"
#include "context_pool.h"

namespace mux
{

class local_client
{
   public:
    local_client(io_context_pool& pool, std::string host, std::string port, uint16_t lport, std::string key_hex)
        : pool_(pool), r_host_(host), r_port_(port), ctx_(boost::asio::ssl::context::tlsv13_client)
    {
        auth_key_ = reality::CryptoUtil::hex_to_bytes(key_hex);

        ctx_.set_verify_mode(boost::asio::ssl::verify_peer);
        ctx_.set_verify_callback(
            [this](bool preverified, boost::asio::ssl::verify_context& ctx)
            {
                X509* cert = X509_STORE_CTX_get0_cert(ctx.native_handle());
                EVP_PKEY* pub = X509_get0_pubkey(cert);
                uint8_t pub_raw[32];
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pub, pub_raw, &len);

                uint8_t hmac_sig[64];
                unsigned int hmac_len;
                HMAC(EVP_sha512(), auth_key_.data(), auth_key_.size(), pub_raw, 32, hmac_sig, &hmac_len);

                const ASN1_BIT_STRING* sig;
                const X509_ALGOR* alg;
                X509_get0_signature(&sig, &alg, cert);

                if (memcmp(sig->data, hmac_sig, 64) == 0)
                {
                    LOG_INFO("REALITY Server Authenticated via HMAC!");
                    return true;
                }

                LOG_ERROR("REALITY Server Auth Failed!");
                return false;
            });
    }

    void start() { boost::asio::co_spawn(pool_.get_io_context(), run(), boost::asio::detached); }

   private:
    boost::asio::awaitable<void> run()
    {
        uint8_t client_pub[32], client_priv[32];
        X25519_keypair(client_pub, client_priv);

        uint8_t shared[32];
        if (!X25519(shared, client_priv, auth_key_.data()))
        {
            co_return;
        }

        uint8_t random[32];
        RAND_bytes(random, 32);

        uint8_t aead_key[32];
        std::vector<uint8_t> info_str(reality::K_REALITY_INFO, reality::K_REALITY_INFO + 7);
        HKDF(aead_key, 32, EVP_sha256(), shared, 32, random, 20, info_str.data(), info_str.size());

        boost::asio::ip::tcp::socket sock(pool_.get_io_context());
        boost::asio::ip::tcp::resolver res(pool_.get_io_context());
        auto [ec, eps] = co_await res.async_resolve(r_host_, r_port_, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec)
            co_return;

        auto [ec2, ep] = co_await boost::asio::async_connect(sock, eps, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec2)
            co_return;

        auto ssl_stream = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(std::move(sock), ctx_);
        SSL_set_tlsext_host_name(ssl_stream->native_handle(), r_host_.c_str());

        auto [ec3] = co_await ssl_stream->async_handshake(boost::asio::ssl::stream_base::client, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (ec3)
        {
            LOG_ERROR("Client Handshake failed: {}", ec3.message());
            co_return;
        }
    }

    io_context_pool& pool_;
    std::string r_host_, r_port_;
    boost::asio::ssl::context ctx_;
    std::vector<uint8_t> auth_key_;
};

}    // namespace mux

#endif
