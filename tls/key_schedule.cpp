#include <vector>
#include <cstddef>
#include <utility>

#include <boost/system/errc.hpp>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/hmac.h>
}

#include "tls/key_schedule.h"

namespace tls
{

namespace key_schedule
{

namespace
{

[[nodiscard]] std::size_t hash_size(const EVP_MD* md, boost::system::error_code& ec)
{
    ec.clear();
    const int hash_len = EVP_MD_size(md);
    if (hash_len <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return 0;
    }
    return static_cast<std::size_t>(hash_len);
}

}    // namespace

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_traffic_keys(const std::vector<uint8_t>& secret,
                                                                                     boost::system::error_code& ec,
                                                                                     const std::size_t key_len,
                                                                                     const std::size_t iv_len,
                                                                                     const EVP_MD* md)
{
    ec.clear();
    auto key = crypto_util::hkdf_expand_label(secret, "key", {}, key_len, md, ec);
    if (ec)
    {
        return {};
    }
    auto iv = crypto_util::hkdf_expand_label(secret, "iv", {}, iv_len, md, ec);
    if (ec)
    {
        return {};
    }
    return std::pair{std::move(key), std::move(iv)};
}

handshake_keys derive_handshake_keys(const std::vector<uint8_t>& shared_secret,
                                     const std::vector<uint8_t>& server_hello_hash,
                                     const EVP_MD* md,
                                     boost::system::error_code& ec)
{
    ec.clear();
    const auto hash_len = hash_size(md, ec);
    if (ec)
    {
        return {};
    }
    const std::vector<uint8_t> zero_ikm(hash_len, 0);
    auto early_secret = crypto_util::hkdf_extract(zero_ikm, zero_ikm, md, ec);
    if (ec)
    {
        return {};
    }

    std::vector<uint8_t> empty_hash(hash_len);
    unsigned int hl = 0;
    if (EVP_Digest(nullptr, 0, empty_hash.data(), &hl, md, nullptr) != 1 || hl != hash_len)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    auto derived_secret = crypto_util::hkdf_expand_label(early_secret, "derived", empty_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }
    auto handshake_secret = crypto_util::hkdf_extract(derived_secret, shared_secret, md, ec);
    if (ec)
    {
        return {};
    }

    auto c_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "c hs traffic", server_hello_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }
    auto s_hs_secret = crypto_util::hkdf_expand_label(handshake_secret, "s hs traffic", server_hello_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }

    auto derived_secret_2 = crypto_util::hkdf_expand_label(handshake_secret, "derived", empty_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }
    auto master_secret = crypto_util::hkdf_extract(derived_secret_2, zero_ikm, md, ec);
    if (ec)
    {
        return {};
    }

    return handshake_keys{.client_handshake_traffic_secret = std::move(c_hs_secret),
                          .server_handshake_traffic_secret = std::move(s_hs_secret),
                          .master_secret = std::move(master_secret)};
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> derive_application_secrets(const std::vector<uint8_t>& master_secret,
                                                                                             const std::vector<uint8_t>& handshake_hash,
                                                                                             const EVP_MD* md,
                                                                                             boost::system::error_code& ec)
{
    ec.clear();
    const auto hash_len = hash_size(md, ec);
    if (ec)
    {
        return {};
    }
    auto c_app_secret = crypto_util::hkdf_expand_label(master_secret, "c ap traffic", handshake_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }
    auto s_app_secret = crypto_util::hkdf_expand_label(master_secret, "s ap traffic", handshake_hash, hash_len, md, ec);
    if (ec)
    {
        return {};
    }
    return std::pair{std::move(c_app_secret), std::move(s_app_secret)};
}

std::vector<uint8_t> compute_finished_verify_data(const std::vector<uint8_t>& base_key,
                                                       const std::vector<uint8_t>& handshake_hash,
                                                       const EVP_MD* md,
                                                       boost::system::error_code& ec)
{
    ec.clear();
    const auto hash_len = hash_size(md, ec);
    if (ec)
    {
        return {};
    }
    auto finished_key = crypto_util::hkdf_expand_label(base_key, "finished", {}, hash_len, md, ec);
    if (ec)
    {
        return {};
    }

    uint8_t hmac_out[EVP_MAX_MD_SIZE] = {};
    unsigned int hmac_len = 0;
    if (HMAC(md, finished_key.data(), static_cast<int>(finished_key.size()), handshake_hash.data(), handshake_hash.size(), hmac_out, &hmac_len) ==
            nullptr ||
        hmac_len == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return std::vector<uint8_t>{hmac_out, hmac_out + hmac_len};
}

}    // namespace key_schedule

}    // namespace tls
