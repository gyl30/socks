#ifndef REALITY_FINGERPRINT_H
#define REALITY_FINGERPRINT_H

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "reality/handshake/fingerprint_blueprint.h"
#include "tls/core.h"

namespace reality
{

enum class fingerprint_type : uint8_t
{
    kChrome120,
    kChrome120Mlkem768,
    kFirefox120,
    kIOS14,
    kAndroid11OkHttp,
};

struct fingerprint_template_storage
{
   public:
    static void set_client_version(fingerprint_template_storage& spec, uint16_t client_version) { spec.client_version_ = client_version; }

    [[nodiscard]] static std::vector<uint16_t>& mutable_cipher_suites(fingerprint_template_storage& spec) { return spec.cipher_suites_; }

    [[nodiscard]] static std::vector<std::shared_ptr<extension_blueprint>>& mutable_extensions(fingerprint_template_storage& spec)
    {
        return spec.extensions_;
    }

    static void set_shuffle_extensions(fingerprint_template_storage& spec, bool enabled) { spec.shuffle_extensions_ = enabled; }

   private:
    uint16_t client_version_ = tls::consts::kVer12;
    std::vector<uint16_t> cipher_suites_;
    std::vector<uint8_t> compression_methods_ = {0x00};
    std::vector<std::shared_ptr<extension_blueprint>> extensions_;
    bool shuffle_extensions_ = false;

    friend uint16_t fingerprint_client_version(const fingerprint_template_storage& spec);
    friend const std::vector<uint16_t>& fingerprint_cipher_suites(const fingerprint_template_storage& spec);
    friend const std::vector<uint8_t>& fingerprint_compression_methods(const fingerprint_template_storage& spec);
    friend const std::vector<std::shared_ptr<extension_blueprint>>& fingerprint_extensions(const fingerprint_template_storage& spec);
    friend bool fingerprint_shuffle_extensions_enabled(const fingerprint_template_storage& spec);
};

using fingerprint_template = fingerprint_template_storage;

class grease_context
{
   public:
    grease_context();

    [[nodiscard]] uint16_t get_grease(int index) const;

    [[nodiscard]] uint16_t get_extension_grease(int nth_occurrence) const;

   private:
    std::array<uint16_t, 8> seed_;
};

class fingerprint_factory
{
   public:
    static fingerprint_template get(fingerprint_type type);
};

}    // namespace reality

#endif
