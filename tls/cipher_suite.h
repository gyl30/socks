#ifndef TLS_CIPHER_SUITE_H
#define TLS_CIPHER_SUITE_H

#include <cstddef>
#include <cstdint>
#include <optional>

extern "C"
{
#include <openssl/types.h>
}

namespace tls
{

struct negotiated_tls13_suite
{
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
    std::size_t key_len = 0;
};

[[nodiscard]] std::optional<negotiated_tls13_suite> select_tls13_suite(std::uint16_t cipher_suite);

}    // namespace tls

#endif
