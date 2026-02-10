#ifndef REALITY_FINGERPRINT_H
#define REALITY_FINGERPRINT_H

#include <array>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

extern "C"
{
#include <openssl/rand.h>
}

#include "reality_core.h"

namespace reality
{

enum class fingerprint_type
{
    kChrome120,
    kFirefox120,
    kIOS14,
    kAndroid11OkHttp
};

enum class extension_type
{
    kGrease,
    kSni,
    kExtendedMasterSecret,
    kRenegotiationInfo,
    kSupportedGroups,
    kECPointFormats,
    kSessionTicket,
    kAlpn,
    kStatusRequest,
    kSignatureAlgorithms,
    kSct,
    kKeyShare,
    kPSKKeyExchangeModes,
    kSupportedVersions,
    kCompressCertificate,
    kApplicationSettings,
    kApplicationSettingsNew,
    kGreaseECH,
    kPadding,
    kPreSharedKey,
    kNpn,
    kChannelID,
    kDelegatedCredentials,
    kRecordSizeLimit,
    kGeneric
};

class extension_blueprint
{
   public:
    virtual ~extension_blueprint() = default;
    [[nodiscard]] virtual extension_type type() const = 0;
    [[nodiscard]] virtual bool is_shufflable() const { return true; }
};

class grease_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kGrease; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class sni_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kSni; }
};

class ems_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kExtendedMasterSecret; }
};

class renegotiation_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kRenegotiationInfo; }
};

class supported_groups_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint16_t>& groups() { return groups_; }
    [[nodiscard]] const std::vector<std::uint16_t>& groups() const { return groups_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSupportedGroups; }

   private:
    std::vector<std::uint16_t> groups_;
};

class ec_point_formats_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint8_t>& formats() { return formats_; }
    [[nodiscard]] const std::vector<std::uint8_t>& formats() const { return formats_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kECPointFormats; }

   private:
    std::vector<std::uint8_t> formats_;
};

class session_ticket_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kSessionTicket; }
};

class alpn_blueprint : public extension_blueprint
{
   public:
    std::vector<std::string>& protocols() { return protocols_; }
    [[nodiscard]] const std::vector<std::string>& protocols() const { return protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kAlpn; }

   private:
    std::vector<std::string> protocols_;
};

class status_request_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kStatusRequest; }
};

class signature_algorithms_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSignatureAlgorithms; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class sct_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kSct; }
};

class key_share_blueprint : public extension_blueprint
{
   public:
    struct key_share_entry
    {
        std::uint16_t group;
        std::vector<std::uint8_t> data;
    };
    std::vector<key_share_entry>& key_shares() { return key_shares_; }
    [[nodiscard]] const std::vector<key_share_entry>& key_shares() const { return key_shares_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kKeyShare; }

   private:
    std::vector<key_share_entry> key_shares_;
};

class psk_key_exchange_modes_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint8_t>& modes() { return modes_; }
    [[nodiscard]] const std::vector<std::uint8_t>& modes() const { return modes_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kPSKKeyExchangeModes; }

   private:
    std::vector<std::uint8_t> modes_;
};

class supported_versions_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint16_t>& versions() { return versions_; }
    [[nodiscard]] const std::vector<std::uint16_t>& versions() const { return versions_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSupportedVersions; }

   private:
    std::vector<std::uint16_t> versions_;
};

class compress_cert_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kCompressCertificate; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class application_settings_blueprint : public extension_blueprint
{
   public:
    std::vector<std::string>& supported_protocols() { return supported_protocols_; }
    [[nodiscard]] const std::vector<std::string>& supported_protocols() const { return supported_protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kApplicationSettings; }

   private:
    std::vector<std::string> supported_protocols_;
};

class application_settings_new_blueprint : public extension_blueprint
{
   public:
    std::vector<std::string>& supported_protocols() { return supported_protocols_; }
    [[nodiscard]] const std::vector<std::string>& supported_protocols() const { return supported_protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kApplicationSettingsNew; }

   private:
    std::vector<std::string> supported_protocols_;
};

class grease_ech_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kGreaseECH; }
};

class padding_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kPadding; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class pre_shared_key_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kPreSharedKey; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class npn_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] extension_type type() const override { return extension_type::kNpn; }
};

class channel_id_blueprint : public extension_blueprint
{
   public:
    bool& old_id() { return old_id_; }
    [[nodiscard]] bool old_id() const { return old_id_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kChannelID; }

   private:
    bool old_id_ = false;
};

class delegated_credentials_blueprint : public extension_blueprint
{
   public:
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kDelegatedCredentials; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class record_size_limit_blueprint : public extension_blueprint
{
   public:
    std::uint16_t& limit() { return limit_; }
    [[nodiscard]] std::uint16_t limit() const { return limit_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kRecordSizeLimit; }

   private:
    std::uint16_t limit_ = 0;
};

struct fingerprint_spec
{
    std::uint16_t client_version = tls_consts::kVer12;
    std::vector<std::uint16_t> cipher_suites;
    std::vector<std::uint8_t> compression_methods = {0x00};
    std::vector<std::shared_ptr<extension_blueprint>> extensions;
    bool shuffle_extensions = false;
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
    static fingerprint_spec get(fingerprint_type type);

    static fingerprint_spec get_chrome120();

    static void shuffle_extensions(std::vector<std::shared_ptr<extension_blueprint>>& exts);
};

}    // namespace reality

#endif
