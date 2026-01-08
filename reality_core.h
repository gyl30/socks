#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <memory>
#include <array>
#include <algorithm>
#include <iomanip>
#include <stdexcept>

// OpenSSL headers
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

// Networking for CertManager scraping
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "log.h"

namespace reality
{

// TLS 1.3 Constants
static const uint8_t K_REALITY_INFO[] = "REALITY";
static const uint8_t TLS1_2_VERSION_MAJOR = 0x03;
static const uint8_t TLS1_2_VERSION_MINOR = 0x03;

static const uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
static const uint8_t CONTENT_TYPE_ALERT = 0x15;
static const uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
static const uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

static const size_t TLS_RECORD_HEADER_SIZE = 5;
static const size_t AEAD_TAG_SIZE = 16;
static const size_t MAX_TLS_PLAINTEXT_LEN = 16384;
static const size_t MAX_TLS_CIPHERTEXT_LEN = 16384 + 256;

class CryptoUtil
{
   public:
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes, size_t max_len = 0)
    {
        std::string str;
        size_t len = bytes.size();
        if (max_len > 0 && len > max_len)
            len = max_len;

        str.reserve(len * 2);
        static const char hex_chars[] = "0123456789abcdef";
        for (size_t i = 0; i < len; ++i)
        {
            uint8_t b = bytes[i];
            str.push_back(hex_chars[b >> 4]);
            str.push_back(hex_chars[b & 0x0F]);
        }
        if (max_len > 0 && bytes.size() > max_len)
            str += "...";
        return str;
    }

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

    // Extract Public Key from Private Key (X25519)
    static std::vector<uint8_t> extract_public_key(const std::vector<uint8_t>& private_key)
    {
        if (private_key.size() != 32)
            return {};

        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key.data(), 32);
        if (!pkey)
            return {};

        size_t len = 32;
        std::vector<uint8_t> public_key(32);
        if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &len) != 1)
        {
            EVP_PKEY_free(pkey);
            return {};
        }
        EVP_PKEY_free(pkey);
        return public_key;
    }

    // X25519 Key Derivation
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

    // Basic HKDF
    static std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm)
    {
        const EVP_MD* md = EVP_sha256();
        std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
        size_t len = EVP_MAX_MD_SIZE;
        if (!HKDF_extract(prk.data(), &len, md, ikm.data(), ikm.size(), salt.data(), salt.size()))
        {
            return {};
        }
        prk.resize(len);
        return prk;
    }

    static std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t len)
    {
        const EVP_MD* md = EVP_sha256();
        std::vector<uint8_t> okm(len);
        if (!HKDF_expand(okm.data(), len, md, prk.data(), prk.size(), info.data(), info.size()))
        {
            return {};
        }
        return okm;
    }

    // TLS 1.3 HKDF-Expand-Label
    static std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                                  const std::string& label,
                                                  const std::vector<uint8_t>& context,
                                                  size_t length)
    {
        std::string full_label = "tls13 " + label;

        std::vector<uint8_t> hkdf_label;
        hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());

        // Length (u16 be)
        hkdf_label.push_back((length >> 8) & 0xFF);
        hkdf_label.push_back(length & 0xFF);

        // Label len + content
        hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
        hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());

        // Context len + content
        hkdf_label.push_back(static_cast<uint8_t>(context.size()));
        hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

        return hkdf_expand(secret, hkdf_label, length);
    }

    // AES-GCM Decrypt
    static std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad)
    {
        if (ciphertext.size() < AEAD_TAG_SIZE)
            return {};

        const EVP_AEAD* aead = nullptr;
        if (key.size() == 16)
            aead = EVP_aead_aes_128_gcm();
        else if (key.size() == 32)
            aead = EVP_aead_aes_256_gcm();
        else
            return {};

        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key.data(), key.size(), AEAD_TAG_SIZE);
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

    // AES-GCM Encrypt
    static std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& aad)
    {
        const EVP_AEAD* aead = nullptr;
        if (key.size() == 16)
            aead = EVP_aead_aes_128_gcm();
        else if (key.size() == 32)
            aead = EVP_aead_aes_256_gcm();
        else
            return {};

        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key.data(), key.size(), AEAD_TAG_SIZE);
        if (!ctx)
            return {};

        std::vector<uint8_t> ciphertext(plaintext.size() + EVP_AEAD_max_overhead(aead));
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

struct HandshakeKeys
{
    std::vector<uint8_t> client_handshake_traffic_secret;
    std::vector<uint8_t> server_handshake_traffic_secret;
    std::vector<uint8_t> master_secret;
};

class TlsKeySchedule
{
   public:
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_traffic_keys(const std::vector<uint8_t>& secret,
                                                                                     size_t key_len = 16,
                                                                                     size_t iv_len = 12)
    {
        std::vector<uint8_t> key = CryptoUtil::hkdf_expand_label(secret, "key", {}, key_len);
        std::vector<uint8_t> iv = CryptoUtil::hkdf_expand_label(secret, "iv", {}, iv_len);
        return {key, iv};
    }

    static HandshakeKeys derive_handshake_keys(const std::vector<uint8_t>& shared_secret, const std::vector<uint8_t>& server_hello_hash)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> zero_salt(hash_len, 0);

        std::vector<uint8_t> early_secret = CryptoUtil::hkdf_extract(zero_salt, zero_salt);

        std::vector<uint8_t> empty_hash(hash_len, 0xe3);
        {
            uint8_t hash[SHA256_DIGEST_LENGTH];
            SHA256(nullptr, 0, hash);
            empty_hash.assign(hash, hash + SHA256_DIGEST_LENGTH);
        }

        std::vector<uint8_t> derived_secret = CryptoUtil::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len);
        std::vector<uint8_t> handshake_secret = CryptoUtil::hkdf_extract(derived_secret, shared_secret);

        std::vector<uint8_t> c_hs_secret = CryptoUtil::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len);
        std::vector<uint8_t> s_hs_secret = CryptoUtil::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len);

        std::vector<uint8_t> derived_secret_2 = CryptoUtil::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len);
        std::vector<uint8_t> master_secret = CryptoUtil::hkdf_extract(derived_secret_2, zero_salt);

        return {c_hs_secret, s_hs_secret, master_secret};
    }

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                            const std::vector<uint8_t>& handshake_hash)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> c_app_secret = CryptoUtil::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len);
        std::vector<uint8_t> s_app_secret = CryptoUtil::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len);
        return {c_app_secret, s_app_secret};
    }

    static std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key, const std::vector<uint8_t>& handshake_hash)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> finished_key = CryptoUtil::hkdf_expand_label(base_key, "finished", {}, hash_len);

        uint8_t hmac_out[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;
        HMAC(EVP_sha256(), finished_key.data(), finished_key.size(), handshake_hash.data(), handshake_hash.size(), hmac_out, &hmac_len);

        return std::vector<uint8_t>(hmac_out, hmac_out + hmac_len);
    }
};

class TlsRecordLayer
{
   public:
    static std::vector<uint8_t> encrypt_record(
        const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, uint64_t seq, const std::vector<uint8_t>& plaintext, uint8_t content_type)
    {
        std::vector<uint8_t> inner_plaintext = plaintext;
        inner_plaintext.push_back(content_type);

        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= (seq >> (8 * i)) & 0xFF;
        }

        uint16_t ciphertext_len = inner_plaintext.size() + AEAD_TAG_SIZE;
        std::vector<uint8_t> header(5);
        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1] = TLS1_2_VERSION_MAJOR;
        header[2] = TLS1_2_VERSION_MINOR;
        header[3] = (ciphertext_len >> 8) & 0xFF;
        header[4] = ciphertext_len & 0xFF;

        std::vector<uint8_t> ciphertext = CryptoUtil::aes_gcm_encrypt(key, nonce, inner_plaintext, header);

        std::vector<uint8_t> record;
        record.reserve(header.size() + ciphertext.size());
        record.insert(record.end(), header.begin(), header.end());
        record.insert(record.end(), ciphertext.begin(), ciphertext.end());

        return record;
    }

    static std::vector<uint8_t> decrypt_record(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& iv,
                                               uint64_t seq,
                                               const std::vector<uint8_t>& ciphertext_with_header,
                                               uint8_t& out_content_type)
    {
        if (ciphertext_with_header.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
            throw std::runtime_error("Record too short");

        std::vector<uint8_t> aad(ciphertext_with_header.begin(), ciphertext_with_header.begin() + 5);
        std::vector<uint8_t> ciphertext(ciphertext_with_header.begin() + 5, ciphertext_with_header.end());

        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= (seq >> (8 * i)) & 0xFF;
        }

        std::vector<uint8_t> plaintext = CryptoUtil::aes_gcm_decrypt(key, nonce, ciphertext, aad);
        if (plaintext.empty())
            throw std::runtime_error("Decryption failed");

        while (!plaintext.empty() && plaintext.back() == 0)
        {
            plaintext.pop_back();
        }

        if (plaintext.empty())
            throw std::runtime_error("Invalid cleartext record (all zeros)");

        out_content_type = plaintext.back();
        plaintext.pop_back();

        return plaintext;
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

    // Changed: Returns a new DER vector for the specific auth_key, does not store state
    std::vector<uint8_t> generate_reality_cert(const std::vector<uint8_t>& auth_key)
    {
        if (!scraped_cert_ || !temp_key_)
            return {};

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

        std::vector<uint8_t> result(der, der + len_der);
        OPENSSL_free(der);
        return result;
    }

    EVP_PKEY* get_key() const { return temp_key_; }

   private:
    EVP_PKEY* temp_key_ = nullptr;
    X509* scraped_cert_ = nullptr;
    X509* reality_cert_ = nullptr;    // Unused now in dynamic gen, but kept for destructor safety
    STACK_OF(X509) * chain_ = nullptr;
};

}    // namespace reality

#endif
