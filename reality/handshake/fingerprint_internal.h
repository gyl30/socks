#ifndef REALITY_FINGERPRINT_INTERNAL_H
#define REALITY_FINGERPRINT_INTERNAL_H

#include <cstdint>
#include "reality/handshake/fingerprint.h"

namespace reality
{

struct fingerprint_instance
{
    std::uint16_t client_version = ::tls::consts::kVer12;
    std::vector<std::uint16_t> cipher_suites;
    std::vector<std::uint8_t> compression_methods = {0x00};
    std::vector<std::shared_ptr<extension_blueprint>> extensions;
};

[[nodiscard]] inline std::uint16_t fingerprint_client_version(const fingerprint_template& spec)
{
    return spec.client_version_;
}

[[nodiscard]] inline const std::vector<std::uint16_t>& fingerprint_cipher_suites(const fingerprint_template& spec)
{
    return spec.cipher_suites_;
}

[[nodiscard]] inline const std::vector<std::uint8_t>& fingerprint_compression_methods(const fingerprint_template& spec)
{
    return spec.compression_methods_;
}

[[nodiscard]] inline const std::vector<std::shared_ptr<extension_blueprint>>& fingerprint_extensions(const fingerprint_template& spec)
{
    return spec.extensions_;
}

[[nodiscard]] inline bool fingerprint_shuffle_extensions_enabled(const fingerprint_template& spec)
{
    return spec.shuffle_extensions_;
}

[[nodiscard]] bool fingerprint_has_key_share_group(const fingerprint_template& spec, std::uint16_t group);

[[nodiscard]] bool fingerprint_has_key_share_group(const fingerprint_instance& spec, std::uint16_t group);

[[nodiscard]] bool fingerprint_has_cipher_suite(const fingerprint_template& spec, std::uint16_t cipher_suite);

[[nodiscard]] fingerprint_instance instantiate_fingerprint_instance(const fingerprint_template& spec);

}    // namespace reality

#endif
