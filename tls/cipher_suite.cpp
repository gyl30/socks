#include <optional>

#include <openssl/evp.h>

#include "tls/cipher_suite.h"

namespace tls
{

std::optional<negotiated_tls13_suite> select_tls13_suite(const uint16_t cipher_suite)
{
    if (cipher_suite == 0x1301)
    {
        return negotiated_tls13_suite{.md = EVP_sha256(), .cipher = EVP_aes_128_gcm(), .key_len = 16};
    }
    if (cipher_suite == 0x1302)
    {
        return negotiated_tls13_suite{.md = EVP_sha384(), .cipher = EVP_aes_256_gcm(), .key_len = 32};
    }
    if (cipher_suite == 0x1303)
    {
        return negotiated_tls13_suite{.md = EVP_sha256(), .cipher = EVP_chacha20_poly1305(), .key_len = 32};
    }
    return std::nullopt;
}

}    // namespace tls
