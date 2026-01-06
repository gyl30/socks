#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <utility>

namespace reality
{

class CryptoUtil
{
   public:
    static std::vector<uint8_t> aes_cfb_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& plaintext)
    {
        if (key.size() != 32)
            return {};

        std::vector<uint8_t> ciphertext(plaintext.size());
        std::vector<uint8_t> iv(16, 0);
        int len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), nullptr, key.data(), iv.data());
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
        int final_len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext;
    }

    static std::vector<uint8_t> aes_cfb_decrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext)
    {
        if (key.size() != 32)
            return {};

        std::vector<uint8_t> plaintext(ciphertext.size());
        std::vector<uint8_t> iv(16, 0);
        int len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), nullptr, key.data(), iv.data());
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
        int final_len;
        EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        return plaintext;
    }

    static std::pair<X509*, EVP_PKEY*> generate_ephemeral_cert()
    {
        EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        X509* x509 = X509_new();

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"apple.com", -1, -1, 0);
        X509_set_issuer_name(x509, name);

        X509_sign(x509, pkey, EVP_sha256());
        return {x509, pkey};
    }
};

}    // namespace reality

#endif
