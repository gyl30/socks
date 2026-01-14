#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <vector>
#include <string>
#include <memory>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

namespace reality
{
class cert_manager
{
   public:
    cert_manager()
    {
        const openssl_ptrs::evp_pkey_ctx_ptr evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
        if (evp_pkey_ctx)
        {
            EVP_PKEY* raw = nullptr;
            if (EVP_PKEY_keygen_init(evp_pkey_ctx.get()) > 0 && EVP_PKEY_keygen(evp_pkey_ctx.get(), &raw) > 0)
            {
                temp_key_.reset(raw);
            }
            else
            {
                LOG_ERROR("cert manager failed to generate ed25519 key");
            }
        }
    }

    [[nodiscard]] std::vector<uint8_t> generate_reality_cert(const std::vector<uint8_t>& auth_key) const
    {
        if (!temp_key_)
        {
            return {};
        }

        const openssl_ptrs::x509_ptr x509(X509_new());
        if (!x509)
        {
            return {};
        }

        X509_set_version(x509.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 0);
        X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(x509.get()), 315360000L);
        X509_set_pubkey(x509.get(), temp_key_.get());
        X509_sign(x509.get(), temp_key_.get(), nullptr);

        uint8_t pub_raw[32];
        size_t len = 32;
        EVP_PKEY_get_raw_public_key(temp_key_.get(), pub_raw, &len);

        uint8_t hmac_sig[64];
        unsigned int hmac_len;
        HMAC(EVP_sha512(), auth_key.data(), static_cast<int>(auth_key.size()), pub_raw, 32, hmac_sig, &hmac_len);

        const ASN1_BIT_STRING* sig = nullptr;
        const X509_ALGOR* alg = nullptr;
        X509_get0_signature(&sig, &alg, x509.get());
        ASN1_BIT_STRING_set(const_cast<ASN1_BIT_STRING*>(sig), hmac_sig, 64);

        const int len_der = i2d_X509(x509.get(), nullptr);
        std::vector<uint8_t> der(len_der);
        uint8_t* p = der.data();
        i2d_X509(x509.get(), &p);
        return der;
    }

    [[nodiscard]] EVP_PKEY* get_key() const { return temp_key_.get(); }

   private:
    openssl_ptrs::evp_pkey_ptr temp_key_;
};

}    // namespace reality

#endif
