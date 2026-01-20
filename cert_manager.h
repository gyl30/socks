#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include <vector>
#include <string>
#include <memory>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include "log.h"
#include "reality_core.h"

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

    [[nodiscard]] std::vector<uint8_t> generate_reality_cert(const std::string& sni) const
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
        BIGNUM* bn = BN_new();
        BN_pseudo_rand(bn, 64, 0, 0);
        ASN1_INTEGER* serial = X509_get_serialNumber(x509.get());
        BN_to_ASN1_INTEGER(bn, serial);
        BN_free(bn);

        X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
        X509_gmtime_adj(X509_get_notAfter(x509.get()), 315360000L);

        X509_NAME* name = X509_get_subject_name(x509.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(sni.c_str()), -1, -1, 0);
        X509_set_issuer_name(x509.get(), name);

        X509_set_pubkey(x509.get(), temp_key_.get());
        X509_sign(x509.get(), temp_key_.get(), nullptr);

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

}    

#endif
