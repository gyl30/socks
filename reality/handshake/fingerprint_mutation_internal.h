#ifndef REALITY_FINGERPRINT_MUTATION_INTERNAL_H
#define REALITY_FINGERPRINT_MUTATION_INTERNAL_H

#include <memory>
#include <vector>

#include "reality/handshake/fingerprint.h"
#include "reality/handshake/fingerprint_blueprint.h"

namespace reality
{

class fingerprint_template_mutation
{
   public:
    static void set_client_version(fingerprint_template& spec, const std::uint16_t client_version) { spec.client_version_ = client_version; }

    [[nodiscard]] static std::vector<std::uint16_t>& cipher_suites(fingerprint_template& spec) { return spec.cipher_suites_; }

    [[nodiscard]] static std::vector<std::shared_ptr<extension_blueprint>>& extensions(fingerprint_template& spec) { return spec.extensions_; }

    static void set_shuffle_extensions(fingerprint_template& spec, const bool enabled) { spec.shuffle_extensions_ = enabled; }
};

}    // namespace reality

#endif
