#ifndef REALITY_FINGERPRINT_H
#define REALITY_FINGERPRINT_H

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "tls/core.h"

namespace reality
{

class extension_blueprint;
class fingerprint_template_mutation;
struct fingerprint_template_storage;
using fingerprint_template = fingerprint_template_storage;

enum class fingerprint_type : std::uint8_t
{
    kChrome120,
    kChrome120Mlkem768,
    kFirefox120,
    kIOS14,
    kAndroid11OkHttp
};

struct fingerprint_template_storage
{
   private:
    std::uint16_t client_version_ = ::tls::consts::kVer12;
    std::vector<std::uint16_t> cipher_suites_;
    std::vector<std::uint8_t> compression_methods_ = {0x00};
    std::vector<std::shared_ptr<extension_blueprint>> extensions_;
    bool shuffle_extensions_ = false;

    friend std::uint16_t fingerprint_client_version(const fingerprint_template& spec);
    friend const std::vector<std::uint16_t>& fingerprint_cipher_suites(const fingerprint_template& spec);
    friend const std::vector<std::uint8_t>& fingerprint_compression_methods(const fingerprint_template& spec);
    friend const std::vector<std::shared_ptr<extension_blueprint>>& fingerprint_extensions(const fingerprint_template& spec);
    friend bool fingerprint_shuffle_extensions_enabled(const fingerprint_template& spec);
    friend class fingerprint_template_mutation;
};

class grease_context
{
   public:
    grease_context();

    [[nodiscard]] std::uint16_t get_grease(int index) const;

    [[nodiscard]] std::uint16_t get_extension_grease(int nth_occurrence) const;

   private:
    std::array<std::uint16_t, 8> seed_;
};

class fingerprint_factory
{
   public:
    static fingerprint_template get(fingerprint_type type);
};

}    // namespace reality

#endif
