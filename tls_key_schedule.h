#ifndef TLS_KEY_SCHEDULE_H_
#define TLS_KEY_SCHEDULE_H_

#include <vector>
#include <string>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#include "crypto_util.h"

namespace reality
{
class tls_key_schedule
{
   public:
    [[nodiscard]] static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_traffic_keys(const std::vector<uint8_t>& secret,
                                                                                                   std::error_code& ec,
                                                                                                   size_t key_len = 16,
                                                                                                   size_t iv_len = 12)
    {
        const std::vector<uint8_t> key = crypto_util::hkdf_expand_label(secret, "key", {}, key_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> iv = crypto_util::hkdf_expand_label(secret, "iv", {}, iv_len, ec);
        if (ec)
        {
            return {};
        }
        return {key, iv};
    }

    [[nodiscard]] static handshake_keys derive_handshake_keys(const std::vector<uint8_t>& shared_secret,
                                                              const std::vector<uint8_t>& server_hello_hash,
                                                              std::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> zero_ikm(hash_len, 0);
        const std::vector<uint8_t> early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, ec);
        if (ec)
        {
            return {};
        }

        std::vector<uint8_t> empty_hash(hash_len, 0);
        SHA256(nullptr, 0, empty_hash.data());

        const std::vector<uint8_t> derived_secret = crypto_util::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> handshake_secret = crypto_util::hkdf_extract(derived_secret, shared_secret, ec);
        if (ec)
        {
            return {};
        }

        const std::vector<uint8_t> c_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> s_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }

        const std::vector<uint8_t> derived_secret_2 = crypto_util::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> master_secret = crypto_util::hkdf_extract(derived_secret_2, zero_ikm, ec);
        if (ec)
        {
            return {};
        }

        return {.client_handshake_traffic_secret = c_hs_secret, .server_handshake_traffic_secret = s_hs_secret, .master_secret = master_secret};
    }

    [[nodiscard]] static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                                          const std::vector<uint8_t>& handshake_hash,
                                                                                                          std::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> c_app_secret = crypto_util::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<uint8_t> s_app_secret = crypto_util::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, ec);
        if (ec)
        {
            return {};
        }
        return {c_app_secret, s_app_secret};
    }

    [[nodiscard]] static std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key,
                                                                           const std::vector<uint8_t>& handshake_hash,
                                                                           std::error_code& ec)
    {
        constexpr size_t hash_len = 32;
        const std::vector<uint8_t> finished_key = crypto_util::hkdf_expand_label(base_key, "finished", {}, hash_len, ec);
        if (ec)
        {
            return {};
        }

        uint8_t hmac_out[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;
        HMAC(EVP_sha256(),
             finished_key.data(),
             static_cast<int>(finished_key.size()),
             handshake_hash.data(),
             handshake_hash.size(),
             hmac_out,
             &hmac_len);
        ec.clear();
        return {hmac_out, hmac_out + hmac_len};
    }
};

}    // namespace reality

#endif
