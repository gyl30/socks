#include <optional>
#include <cstdint>

#include "tls_cipher_suite.h"

namespace reality
{

std::optional<negotiated_tls13_suite> select_tls13_suite(const std::uint16_t cipher_suite)
{
    if (cipher_suite == 0x1301)
    {
        return negotiated_tls13_suite{.md = EVP_sha256(), .cipher = EVP_aes_128_gcm()};
    }
    if (cipher_suite == 0x1302)
    {
        return negotiated_tls13_suite{.md = EVP_sha384(), .cipher = EVP_aes_256_gcm()};
    }
    if (cipher_suite == 0x1303)
    {
        return negotiated_tls13_suite{.md = EVP_sha256(), .cipher = EVP_chacha20_poly1305()};
    }
    return std::nullopt;
}

}    // namespace reality
