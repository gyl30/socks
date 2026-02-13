#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <system_error>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
}

#include "crypto_util.h"
#include "reality_core.h"

namespace reality
{
class tls_key_schedule
{
   public:
    [[nodiscard]] static std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> derive_traffic_keys(const std::vector<std::uint8_t>& secret,
                                                                                                             std::error_code& ec,
                                                                                                             std::size_t key_len = 16,
                                                                                                             std::size_t iv_len = 12,
                                                                                                             const EVP_MD* md = EVP_sha256())
    {
        const std::vector<std::uint8_t> key = crypto_util::hkdf_expand_label(secret, "key", {}, key_len, md, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<std::uint8_t> iv = crypto_util::hkdf_expand_label(secret, "iv", {}, iv_len, md, ec);
        if (ec)
        {
            return {};
        }
        return {key, iv};
    }

    [[nodiscard]] static handshake_keys derive_handshake_keys(const std::vector<std::uint8_t>& shared_secret,
                                                              const std::vector<std::uint8_t>& server_hello_hash,
                                                              const EVP_MD* md,
                                                              std::error_code& ec)
    {
        const std::size_t hash_len = EVP_MD_size(md);
        const std::vector<std::uint8_t> zero_ikm(hash_len, 0);
        const std::vector<std::uint8_t> early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, md, ec);
        if (ec)
        {
            return {};
        }

        std::vector<std::uint8_t> empty_hash(hash_len);
        unsigned int hl;
        EVP_Digest(nullptr, 0, empty_hash.data(), &hl, md, nullptr);

        const std::vector<std::uint8_t> derived_secret = crypto_util::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len, md, ec);
        if (ec)
        {
            return {};
        }
        const std::vector<std::uint8_t> handshake_secret = crypto_util::hkdf_extract(derived_secret, shared_secret, md, ec);
        if (ec)
        {
            return {};
        }

        const std::vector<std::uint8_t> c_hs_secret =
            crypto_util::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len, md, ec);
        const std::vector<std::uint8_t> s_hs_secret =
            crypto_util::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len, md, ec);

        const std::vector<std::uint8_t> derived_secret_2 = crypto_util::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len, md, ec);
        const std::vector<std::uint8_t> master_secret = crypto_util::hkdf_extract(derived_secret_2, zero_ikm, md, ec);

        return handshake_keys{
            .client_handshake_traffic_secret = c_hs_secret, .server_handshake_traffic_secret = s_hs_secret, .master_secret = master_secret};
    }

    [[nodiscard]] static std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> derive_application_secrets(
        const std::vector<std::uint8_t>& master_secret, const std::vector<std::uint8_t>& handshake_hash, const EVP_MD* md, std::error_code& ec)
    {
        const std::size_t hash_len = EVP_MD_size(md);    // GCOVR_EXCL_LINE
        const std::vector<std::uint8_t> c_app_secret =
            crypto_util::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, md, ec);    // GCOVR_EXCL_LINE
        const std::vector<std::uint8_t> s_app_secret =
            crypto_util::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, md, ec);    // GCOVR_EXCL_LINE
        return {c_app_secret, s_app_secret};    // GCOVR_EXCL_LINE
    }

    [[nodiscard]] static std::vector<std::uint8_t> compute_finished_verify_data(const std::vector<std::uint8_t>& base_key,
                                                                                const std::vector<std::uint8_t>& handshake_hash,
                                                                                const EVP_MD* md,
                                                                                std::error_code& ec)
    {
        const std::size_t hash_len = EVP_MD_size(md);
        const std::vector<std::uint8_t> finished_key = crypto_util::hkdf_expand_label(base_key, "finished", {}, hash_len, md, ec);
        if (ec)
        {
            return {};
        }

        std::uint8_t hmac_out[EVP_MAX_MD_SIZE];
        unsigned int hmac_len;
        HMAC(md, finished_key.data(), static_cast<int>(finished_key.size()), handshake_hash.data(), handshake_hash.size(), hmac_out, &hmac_len);
        ec.clear();
        return {hmac_out, hmac_out + hmac_len};
    }
};
}    // namespace reality

#endif
