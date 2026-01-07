#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/curve25519.h>
#include <openssl/hkdf.h>
#include <openssl/aead.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/mem.h>
#include <openssl/asn1.h>
#include <openssl/bytestring.h>

#include "log.h"

namespace reality
{

static const uint8_t K_REALITY_INFO[] = "REALITY";

class CryptoUtil
{
   public:
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex)
    {
        std::vector<uint8_t> bytes;
        for (unsigned int i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::vector<uint8_t> x25519_derive(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& peer_public_key)
    {
        if (private_key.size() != 32 || peer_public_key.size() != 32)
            return {};
        std::vector<uint8_t> shared(32);
        if (!X25519(shared.data(), private_key.data(), peer_public_key.data()))
        {
            return {};
        }
        return shared;
    }

    static std::vector<uint8_t> hkdf_derive(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& info)
    {
        std::vector<uint8_t> out_key(32);
        if (!HKDF(out_key.data(), out_key.size(), EVP_sha256(), secret.data(), secret.size(), salt.data(), salt.size(), info.data(), info.size()))
        {
            return {};
        }
        return out_key;
    }

    static std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad)
    {
        if (ciphertext.size() < 16)
            return {};

        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(EVP_aead_aes_128_gcm(), key.data(), key.size(), 16);
        if (!ctx)
            return {};

        std::vector<uint8_t> plaintext(ciphertext.size());
        size_t out_len;

        if (!EVP_AEAD_CTX_open(ctx,
                               plaintext.data(),
                               &out_len,
                               plaintext.size(),
                               nonce.data(),
                               nonce.size(),
                               ciphertext.data(),
                               ciphertext.size(),
                               aad.data(),
                               aad.size()))
        {
            EVP_AEAD_CTX_free(ctx);
            return {};
        }

        plaintext.resize(out_len);
        EVP_AEAD_CTX_free(ctx);
        return plaintext;
    }

    static std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& aad)
    {
        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(EVP_aead_aes_128_gcm(), key.data(), key.size(), 16);
        if (!ctx)
            return {};

        std::vector<uint8_t> ciphertext(plaintext.size() + 16);
        size_t out_len;

        if (!EVP_AEAD_CTX_seal(ctx,
                               ciphertext.data(),
                               &out_len,
                               ciphertext.size(),
                               nonce.data(),
                               nonce.size(),
                               plaintext.data(),
                               plaintext.size(),
                               aad.data(),
                               aad.size()))
        {
            EVP_AEAD_CTX_free(ctx);
            return {};
        }

        ciphertext.resize(out_len);
        EVP_AEAD_CTX_free(ctx);
        return ciphertext;
    }
};

class CertManager
{
   public:
    CertManager()
    {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &temp_key_);
        EVP_PKEY_CTX_free(pctx);
    }

    ~CertManager()
    {
        if (temp_key_)
            EVP_PKEY_free(temp_key_);
        if (scraped_cert_)
            X509_free(scraped_cert_);
        if (reality_cert_)
            X509_free(reality_cert_);
        if (chain_)
            sk_X509_pop_free(chain_, X509_free);
    }

    bool fetch_real_cert(const std::string& host, const std::string& port)
    {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        SSL* ssl = SSL_new(ctx);

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct hostent* he = gethostbyname(host.c_str());
        if (!he)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(std::stoi(port));

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host.c_str());

        if (SSL_connect(ssl) != 1)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(sock);
            return false;
        }

        const STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
        chain_ = sk_X509_deep_copy(chain, X509_dup, X509_free);
        if (sk_X509_num(chain_) > 0)
        {
            scraped_cert_ = X509_dup(sk_X509_value(chain_, 0));
        }

        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);

        return scraped_cert_ != nullptr;
    }

    void generate_reality_cert(const std::vector<uint8_t>& auth_key)
    {
        if (!scraped_cert_ || !temp_key_)
            return;

        X509* temp_cert = X509_dup(scraped_cert_);
        X509_set_pubkey(temp_cert, temp_key_);
        X509_sign(temp_cert, temp_key_, NULL);

        uint8_t pub_raw[32];
        size_t len = 32;
        EVP_PKEY_get_raw_public_key(temp_key_, pub_raw, &len);

        uint8_t hmac_sig[64];
        unsigned int hmac_len;
        HMAC(EVP_sha512(), auth_key.data(), auth_key.size(), pub_raw, 32, hmac_sig, &hmac_len);

        int len_der = i2d_X509(temp_cert, NULL);
        uint8_t* der = (uint8_t*)OPENSSL_malloc(len_der);
        uint8_t* p = der;
        i2d_X509(temp_cert, &p);
        X509_free(temp_cert);

        if (len_der > 64)
        {
            memcpy(der + len_der - 64, hmac_sig, 64);
        }

        const uint8_t* cp = der;
        reality_cert_ = d2i_X509(NULL, &cp, len_der);
        OPENSSL_free(der);
    }

    void apply_to_ssl(SSL* ssl)
    {
        if (!reality_cert_ || !temp_key_)
            return;
        SSL_use_certificate(ssl, reality_cert_);
        for (size_t i = 1; i < sk_X509_num(chain_); ++i)
        {
            SSL_add1_chain_cert(ssl, sk_X509_value(chain_, i));
        }
        SSL_use_PrivateKey(ssl, temp_key_);
    }

   private:
    EVP_PKEY* temp_key_ = nullptr;
    X509* scraped_cert_ = nullptr;
    X509* reality_cert_ = nullptr;
    STACK_OF(X509) * chain_ = nullptr;
};

}    // namespace reality

#endif
