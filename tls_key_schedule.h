#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <expected>

#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/detail/errc.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/types.h>
}

#include "crypto_util.h"
#include "reality_core.h"

namespace reality
{
class tls_key_schedule
{
   public:
    [[nodiscard]] static std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code>
    derive_traffic_keys(const std::vector<std::uint8_t>& secret, std::size_t key_len = 16, std::size_t iv_len = 12, const EVP_MD* md = EVP_sha256())
    {
        auto key = crypto_util::hkdf_expand_label(secret, "key", {}, key_len, md);
        if (!key)
        {
            return std::unexpected(key.error());
        }
        auto iv = crypto_util::hkdf_expand_label(secret, "iv", {}, iv_len, md);
        if (!iv)
        {
            return std::unexpected(iv.error());
        }
        return std::pair{std::move(*key), std::move(*iv)};
    }

    [[nodiscard]] static std::expected<handshake_keys, boost::system::error_code> derive_handshake_keys(
        const std::vector<std::uint8_t>& shared_secret, const std::vector<std::uint8_t>& server_hello_hash, const EVP_MD* md)
    {
        const auto hash_len_result = hash_size(md);
        if (!hash_len_result)
        {
            return std::unexpected(hash_len_result.error());
        }
        const std::size_t hash_len = *hash_len_result;
        const std::vector<std::uint8_t> zero_ikm(hash_len, 0);
        auto early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, md);
        if (!early_secret)
        {
            return std::unexpected(early_secret.error());
        }

        std::vector<std::uint8_t> empty_hash(hash_len);
        unsigned int hl = 0;
        if (EVP_Digest(nullptr, 0, empty_hash.data(), &hl, md, nullptr) != 1 || hl != hash_len)
        {
            return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::protocol_error));
        }

        auto derived_secret = crypto_util::hkdf_expand_label(*early_secret, "derived", empty_hash, hash_len, md);
        if (!derived_secret)
        {
            return std::unexpected(derived_secret.error());
        }
        auto handshake_secret = crypto_util::hkdf_extract(*derived_secret, shared_secret, md);
        if (!handshake_secret)
        {
            return std::unexpected(handshake_secret.error());
        }

        auto c_hs_secret = crypto_util::hkdf_expand_label(*handshake_secret, "c hs traffic", server_hello_hash, hash_len, md);
        if (!c_hs_secret)
        {
            return std::unexpected(c_hs_secret.error());
        }
        auto s_hs_secret = crypto_util::hkdf_expand_label(*handshake_secret, "s hs traffic", server_hello_hash, hash_len, md);
        if (!s_hs_secret)
        {
            return std::unexpected(s_hs_secret.error());
        }

        auto derived_secret_2 = crypto_util::hkdf_expand_label(*handshake_secret, "derived", empty_hash, hash_len, md);
        if (!derived_secret_2)
        {
            return std::unexpected(derived_secret_2.error());
        }
        auto master_secret = crypto_util::hkdf_extract(*derived_secret_2, zero_ikm, md);
        if (!master_secret)
        {
            return std::unexpected(master_secret.error());
        }

        return handshake_keys{.client_handshake_traffic_secret = std::move(*c_hs_secret),
                              .server_handshake_traffic_secret = std::move(*s_hs_secret),
                              .master_secret = std::move(*master_secret)};
    }

    [[nodiscard]] static std::expected<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>, boost::system::error_code>
    derive_application_secrets(const std::vector<std::uint8_t>& master_secret, const std::vector<std::uint8_t>& handshake_hash, const EVP_MD* md)
    {
        const auto hash_len_result = hash_size(md);
        if (!hash_len_result)
        {
            return std::pair{std::vector<std::uint8_t>{}, std::vector<std::uint8_t>{}};
        }
        const std::size_t hash_len = *hash_len_result;                                                                      // GCOVR_EXCL_LINE
        auto c_app_secret = crypto_util::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, md);    // GCOVR_EXCL_LINE
        auto s_app_secret = crypto_util::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, md);    // GCOVR_EXCL_LINE
        return std::pair{c_app_secret.value_or(std::vector<std::uint8_t>{}),
                         s_app_secret.value_or(std::vector<std::uint8_t>{})};    // GCOVR_EXCL_LINE
    }

    [[nodiscard]] static std::expected<std::vector<std::uint8_t>, boost::system::error_code> compute_finished_verify_data(
        const std::vector<std::uint8_t>& base_key, const std::vector<std::uint8_t>& handshake_hash, const EVP_MD* md)
    {
        const auto hash_len_result = hash_size(md);
        if (!hash_len_result)
        {
            return std::unexpected(hash_len_result.error());
        }
        const std::size_t hash_len = *hash_len_result;
        auto finished_key = crypto_util::hkdf_expand_label(base_key, "finished", {}, hash_len, md);
        if (!finished_key)
        {
            return std::unexpected(finished_key.error());
        }

        std::uint8_t hmac_out[EVP_MAX_MD_SIZE] = {};
        unsigned int hmac_len = 0;
        if (HMAC(md,
                 finished_key->data(),
                 static_cast<int>(finished_key->size()),
                 handshake_hash.data(),
                 handshake_hash.size(),
                 hmac_out,
                 &hmac_len) == nullptr ||
            hmac_len == 0)
        {
            return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::protocol_error));
        }
        return std::vector<std::uint8_t>{hmac_out, hmac_out + hmac_len};
    }

   private:
    [[nodiscard]] static std::expected<std::size_t, boost::system::error_code> hash_size(const EVP_MD* md)
    {
        const int hash_len = EVP_MD_size(md);
        if (hash_len <= 0)
        {
            return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::protocol_error));
        }
        return static_cast<std::size_t>(hash_len);
    }
};
}    // namespace reality

#endif
