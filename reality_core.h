#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

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
#include <boost/algorithm/hex.hpp>
#include <boost/system/error_code.hpp>

namespace reality
{

static const uint8_t K_REALITY_INFO[] = "REALITY";
static const uint8_t TLS1_2_VERSION_MAJOR = 0x03;
static const uint8_t TLS1_2_VERSION_MINOR = 0x03;
static const uint8_t TLS1_0_VERSION_MINOR = 0x01;

static const uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
static const uint8_t CONTENT_TYPE_ALERT = 0x15;
static const uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
static const uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

static const size_t TLS_RECORD_HEADER_SIZE = 5;
static const size_t AEAD_TAG_SIZE = 16;
static const size_t MAX_TLS_PLAINTEXT_LEN = 16384;
static const size_t MAX_TLS_CIPHERTEXT_LEN = 16384 + 256;

static const std::vector<uint16_t> GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

class CryptoUtil
{
   public:
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes)
    {
        std::string result;
        boost::algorithm::hex(bytes, std::back_inserter(result));
        return result;
    }

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex, boost::system::error_code& ec)
    {
        std::vector<uint8_t> result;
        try
        {
            boost::algorithm::unhex(hex, std::back_inserter(result));
        }
        catch (const std::exception&)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }
        return result;
    }

    static uint16_t get_random_grease()
    {
        uint8_t idx;
        RAND_bytes(&idx, 1);
        return GREASE_VALUES[idx % GREASE_VALUES.size()];
    }

    static std::vector<uint8_t> extract_public_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
    {
        if (private_key.size() != 32)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32);
        if (pkey == nullptr)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        size_t len = 32;
        std::vector<uint8_t> public_key(32);
        if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &len) != 1)
        {
            EVP_PKEY_free(pkey);
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }
        EVP_PKEY_free(pkey);
        return public_key;
    }

    static std::vector<uint8_t> x25519_derive(const std::vector<uint8_t>& private_key,
                                              const std::vector<uint8_t>& peer_public_key,
                                              boost::system::error_code& ec)
    {
        if (private_key.size() != 32 || peer_public_key.size() != 32)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }
        std::vector<uint8_t> shared(32);
        if (X25519(shared.data(), private_key.data(), peer_public_key.data()) == 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }
        return shared;
    }

    static std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm, boost::system::error_code& ec)
    {
        const EVP_MD* md = EVP_sha256();
        std::vector<uint8_t> prk(EVP_MAX_MD_SIZE);
        size_t len = EVP_MAX_MD_SIZE;
        if (HKDF_extract(prk.data(), &len, md, ikm.data(), ikm.size(), salt.data(), salt.size()) == 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }
        prk.resize(len);
        return prk;
    }

    static std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                            const std::vector<uint8_t>& info,
                                            size_t len,
                                            boost::system::error_code& ec)
    {
        const EVP_MD* md = EVP_sha256();
        std::vector<uint8_t> okm(len);
        if (HKDF_expand(okm.data(), len, md, prk.data(), prk.size(), info.data(), info.size()) == 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }
        return okm;
    }

    static std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                                  const std::string& label,
                                                  const std::vector<uint8_t>& context,
                                                  size_t length,
                                                  boost::system::error_code& ec)
    {
        std::string full_label = "tls13 " + label;

        std::vector<uint8_t> hkdf_label;
        hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());

        hkdf_label.push_back((length >> 8) & 0xFF);
        hkdf_label.push_back(length & 0xFF);

        hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
        hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());

        hkdf_label.push_back(static_cast<uint8_t>(context.size()));
        hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

        return hkdf_expand(secret, hkdf_label, length, ec);
    }

    static std::vector<uint8_t> aes_gcm_decrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const std::vector<uint8_t>& aad,
                                                boost::system::error_code& ec)
    {
        if (ciphertext.size() < AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }

        const EVP_AEAD* aead = nullptr;
        if (key.size() == 16)
        {
            aead = EVP_aead_aes_128_gcm();
        }
        else if (key.size() == 32)
        {
            aead = EVP_aead_aes_256_gcm();
        }
        else
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key.data(), key.size(), AEAD_TAG_SIZE);
        if (ctx == nullptr)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        std::vector<uint8_t> plaintext(ciphertext.size());
        size_t out_len;

        if (EVP_AEAD_CTX_open(ctx,
                              plaintext.data(),
                              &out_len,
                              plaintext.size(),
                              nonce.data(),
                              nonce.size(),
                              ciphertext.data(),
                              ciphertext.size(),
                              aad.data(),
                              aad.size()) == 0)
        {
            EVP_AEAD_CTX_free(ctx);
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return {};
        }

        plaintext.resize(out_len);
        EVP_AEAD_CTX_free(ctx);
        return plaintext;
    }

    static std::vector<uint8_t> aes_gcm_encrypt(const std::vector<uint8_t>& key,
                                                const std::vector<uint8_t>& nonce,
                                                const std::vector<uint8_t>& plaintext,
                                                const std::vector<uint8_t>& aad,
                                                boost::system::error_code& ec)
    {
        const EVP_AEAD* aead = nullptr;
        if (key.size() == 16)
        {
            aead = EVP_aead_aes_128_gcm();
        }
        else if (key.size() == 32)
        {
            aead = EVP_aead_aes_256_gcm();
        }
        else
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
            return {};
        }

        EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key.data(), key.size(), AEAD_TAG_SIZE);
        if (ctx == nullptr)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return {};
        }

        std::vector<uint8_t> ciphertext(plaintext.size() + EVP_AEAD_max_overhead(aead));
        size_t out_len;

        if (EVP_AEAD_CTX_seal(ctx,
                              ciphertext.data(),
                              &out_len,
                              ciphertext.size(),
                              nonce.data(),
                              nonce.size(),
                              plaintext.data(),
                              plaintext.size(),
                              aad.data(),
                              aad.size()) == 0)
        {
            EVP_AEAD_CTX_free(ctx);
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
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
                                                                                     boost::system::error_code& ec,
                                                                                     size_t key_len = 16,
                                                                                     size_t iv_len = 12)
    {
        std::vector<uint8_t> key = CryptoUtil::hkdf_expand_label(secret, "key", {}, key_len, ec);
        if (ec)
            return {};
        std::vector<uint8_t> iv = CryptoUtil::hkdf_expand_label(secret, "iv", {}, iv_len, ec);
        if (ec)
            return {};
        return {key, iv};
    }

    static HandshakeKeys derive_handshake_keys(const std::vector<uint8_t>& shared_secret,
                                               const std::vector<uint8_t>& server_hello_hash,
                                               boost::system::error_code& ec)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> zero_salt(hash_len, 0);

        std::vector<uint8_t> early_secret = CryptoUtil::hkdf_extract(zero_salt, zero_salt, ec);
        if (ec)
            return {};

        std::vector<uint8_t> empty_hash(hash_len, 0xe3);
        {
            uint8_t hash[SHA256_DIGEST_LENGTH];
            SHA256(nullptr, 0, hash);
            empty_hash.assign(hash, hash + SHA256_DIGEST_LENGTH);
        }

        std::vector<uint8_t> derived_secret = CryptoUtil::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
            return {};
        std::vector<uint8_t> handshake_secret = CryptoUtil::hkdf_extract(derived_secret, shared_secret, ec);
        if (ec)
            return {};

        std::vector<uint8_t> c_hs_secret = CryptoUtil::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
            return {};
        std::vector<uint8_t> s_hs_secret = CryptoUtil::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
            return {};

        std::vector<uint8_t> derived_secret_2 = CryptoUtil::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
            return {};
        std::vector<uint8_t> master_secret = CryptoUtil::hkdf_extract(derived_secret_2, zero_salt, ec);    // NOLINT
        if (ec)
            return {};

        return {.client_handshake_traffic_secret = c_hs_secret, .server_handshake_traffic_secret = s_hs_secret, .master_secret = master_secret};
    }

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                            const std::vector<uint8_t>& handshake_hash,
                                                                                            boost::system::error_code& ec)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> c_app_secret = CryptoUtil::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, ec);
        if (ec)
            return {};
        std::vector<uint8_t> s_app_secret = CryptoUtil::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, ec);
        if (ec)
            return {};
        return {c_app_secret, s_app_secret};
    }

    static std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key,
                                                             const std::vector<uint8_t>& handshake_hash,
                                                             boost::system::error_code& ec)
    {
        size_t hash_len = 32;
        std::vector<uint8_t> finished_key = CryptoUtil::hkdf_expand_label(base_key, "finished", {}, hash_len, ec);
        if (ec)
            return {};

        uint8_t hmac_out[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;
        HMAC(EVP_sha256(), finished_key.data(), finished_key.size(), handshake_hash.data(), handshake_hash.size(), hmac_out, &hmac_len);

        return {hmac_out, hmac_out + hmac_len};
    }
};

class TlsRecordLayer
{
   public:
    static std::vector<uint8_t> encrypt_record(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& iv,
                                               uint64_t seq,
                                               const std::vector<uint8_t>& plaintext,
                                               uint8_t content_type,
                                               boost::system::error_code& ec)
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

        std::vector<uint8_t> ciphertext = CryptoUtil::aes_gcm_encrypt(key, nonce, inner_plaintext, header, ec);
        if (ec)
            return {};

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
                                               uint8_t& out_content_type,
                                               boost::system::error_code& ec)
    {
        if (ciphertext_with_header.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return {};
        }

        std::vector<uint8_t> aad(ciphertext_with_header.begin(), ciphertext_with_header.begin() + 5);
        std::vector<uint8_t> ciphertext(ciphertext_with_header.begin() + 5, ciphertext_with_header.end());

        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= (seq >> (8 * i)) & 0xFF;
        }

        std::vector<uint8_t> plaintext = CryptoUtil::aes_gcm_decrypt(key, nonce, ciphertext, aad, ec);
        if (ec)
        {
            return {};
        }

        while (!plaintext.empty() && plaintext.back() == 0)
        {
            plaintext.pop_back();
        }

        if (plaintext.empty())
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            return {};
        }

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
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (pctx != nullptr)
        {
            EVP_PKEY_keygen_init(pctx);
            EVP_PKEY_keygen(pctx, &temp_key_);
            EVP_PKEY_CTX_free(pctx);
        }
    }

    ~CertManager()
    {
        if (temp_key_ != nullptr)
        {
            EVP_PKEY_free(temp_key_);
        }
    }

    std::vector<uint8_t> generate_reality_cert(const std::vector<uint8_t>& auth_key)
    {
        if (temp_key_ == nullptr)
        {
            return {};
        }

        X509* x509 = X509_new();
        if (x509 == nullptr)
        {
            return {};
        }

        // 使用 RAII 确保 x509 被释放，防止中间出错导致内存泄漏
        // (虽然你的原始代码手动释放了，这里为了逻辑清晰先保持手动释放风格，或者你可以封装 unique_ptr)

        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 0);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 315360000L);
        X509_set_pubkey(x509, temp_key_);

        // 1. 先进行一次正常的签名
        // 这一步是必须的，它会填充 X509 结构体中的 algorithm 和 signature 字段的元数据
        if (X509_sign(x509, temp_key_, nullptr) == 0)
        {
            X509_free(x509);
            return {};
        }

        // 计算 HMAC (REALITY 认证逻辑)
        uint8_t pub_raw[32];
        size_t len = 32;
        EVP_PKEY_get_raw_public_key(temp_key_, pub_raw, &len);

        uint8_t hmac_sig[64];
        unsigned int hmac_len;
        HMAC(EVP_sha512(), auth_key.data(), auth_key.size(), pub_raw, 32, hmac_sig, &hmac_len);

        // 2. 获取 X509 对象内部的签名结构指针
        const ASN1_BIT_STRING* sig = nullptr;
        const X509_ALGOR* alg = nullptr;
        X509_get0_signature(&sig, &alg, x509);

        if (sig)
        {
            // 3. 修改签名内容
            // X509_get0_signature 返回的是 const 指针，表示该内存归 X509 对象所有
            // 我们需要 const_cast 去除常量性以修改它
            auto* mutable_sig = const_cast<ASN1_BIT_STRING*>(sig);

            // ASN1_BIT_STRING_set 会自动管理内存并设置数据
            // 这比 memcpy 安全，因为它会处理长度字段
            if (!ASN1_BIT_STRING_set(mutable_sig, hmac_sig, 64))
            {
                X509_free(x509);
                return {};
            }

            // 能够确保 unused bits 为 0 (Ed25519 签名是字节对齐的)
            // 虽然 X509_sign 已经设置好了，但为了严谨性说明：
            // ASN1_BIT_STRING 内部结构通常包含 flags，OpenSSL 会自动处理
        }
        else
        {
            X509_free(x509);
            return {};
        }

        // 4. 正规序列化
        // 此时 x509 对象内部已经是持有 HMAC 签名的合法结构了
        // i2d_X509 会自动根据 ASN1_BIT_STRING 的内容生成正确的 Tag, Length 和 UnusedBits
        int len_der = i2d_X509(x509, nullptr);
        if (len_der < 0)
        {
            X509_free(x509);
            return {};
        }

        auto* der = static_cast<uint8_t*>(OPENSSL_malloc(len_der));
        uint8_t* p = der;
        i2d_X509(x509, &p);

        X509_free(x509);

        // 不再需要手动的 memcpy Hack
        std::vector<uint8_t> result(der, der + len_der);
        OPENSSL_free(der);
        return result;
    }

    [[nodiscard]] EVP_PKEY* get_key() const { return temp_key_; }

   private:
    EVP_PKEY* temp_key_ = nullptr;
};

}    // namespace reality

#endif
