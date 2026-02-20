#ifndef TLS_CIPHER_SUITE_H
#define TLS_CIPHER_SUITE_H

#include <openssl/types.h>
#include <optional>
#include <cstdint>

extern "C"
{
}

namespace reality
{

struct negotiated_tls13_suite
{
    const EVP_MD* md = nullptr;
    const EVP_CIPHER* cipher = nullptr;
};

[[nodiscard]] std::optional<negotiated_tls13_suite> select_tls13_suite(std::uint16_t cipher_suite);

}    // namespace reality

#endif
