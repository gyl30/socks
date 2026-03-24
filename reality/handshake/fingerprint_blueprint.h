#ifndef REALITY_FINGERPRINT_BLUEPRINT_H
#define REALITY_FINGERPRINT_BLUEPRINT_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "reality/handshake/fingerprint_internal.h"

namespace reality
{

enum class extension_type : std::uint8_t
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
    [[nodiscard]] virtual std::shared_ptr<extension_blueprint> clone() const = 0;
    [[nodiscard]] virtual extension_type type() const = 0;
    [[nodiscard]] virtual bool is_shufflable() const { return true; }
};

class grease_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<grease_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kGrease; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class sni_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<sni_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kSni; }
};

class ems_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<ems_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kExtendedMasterSecret; }
};

class renegotiation_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<renegotiation_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kRenegotiationInfo; }
};

class supported_groups_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<supported_groups_blueprint>(*this); }
    std::vector<std::uint16_t>& groups() { return groups_; }
    [[nodiscard]] const std::vector<std::uint16_t>& groups() const { return groups_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSupportedGroups; }

   private:
    std::vector<std::uint16_t> groups_;
};

class ec_point_formats_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<ec_point_formats_blueprint>(*this); }
    std::vector<std::uint8_t>& formats() { return formats_; }
    [[nodiscard]] const std::vector<std::uint8_t>& formats() const { return formats_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kECPointFormats; }

   private:
    std::vector<std::uint8_t> formats_;
};

class session_ticket_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<session_ticket_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kSessionTicket; }
};

class alpn_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<alpn_blueprint>(*this); }
    std::vector<std::string>& protocols() { return protocols_; }
    [[nodiscard]] const std::vector<std::string>& protocols() const { return protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kAlpn; }

   private:
    std::vector<std::string> protocols_;
};

class status_request_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<status_request_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kStatusRequest; }
};

class signature_algorithms_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<signature_algorithms_blueprint>(*this); }
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSignatureAlgorithms; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class sct_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<sct_blueprint>(*this); }
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

    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<key_share_blueprint>(*this); }
    std::vector<key_share_entry>& key_shares() { return key_shares_; }
    [[nodiscard]] const std::vector<key_share_entry>& key_shares() const { return key_shares_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kKeyShare; }

   private:
    std::vector<key_share_entry> key_shares_;
};

class psk_key_exchange_modes_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<psk_key_exchange_modes_blueprint>(*this); }
    std::vector<std::uint8_t>& modes() { return modes_; }
    [[nodiscard]] const std::vector<std::uint8_t>& modes() const { return modes_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kPSKKeyExchangeModes; }

   private:
    std::vector<std::uint8_t> modes_;
};

class supported_versions_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<supported_versions_blueprint>(*this); }
    std::vector<std::uint16_t>& versions() { return versions_; }
    [[nodiscard]] const std::vector<std::uint16_t>& versions() const { return versions_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kSupportedVersions; }

   private:
    std::vector<std::uint16_t> versions_;
};

class compress_cert_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<compress_cert_blueprint>(*this); }
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kCompressCertificate; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class application_settings_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<application_settings_blueprint>(*this); }
    std::vector<std::string>& supported_protocols() { return supported_protocols_; }
    [[nodiscard]] const std::vector<std::string>& supported_protocols() const { return supported_protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kApplicationSettings; }

   private:
    std::vector<std::string> supported_protocols_;
};

class application_settings_new_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<application_settings_new_blueprint>(*this); }
    std::vector<std::string>& supported_protocols() { return supported_protocols_; }
    [[nodiscard]] const std::vector<std::string>& supported_protocols() const { return supported_protocols_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kApplicationSettingsNew; }

   private:
    std::vector<std::string> supported_protocols_;
};

class grease_ech_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<grease_ech_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kGreaseECH; }
};

class padding_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<padding_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kPadding; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class pre_shared_key_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<pre_shared_key_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kPreSharedKey; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

class npn_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<npn_blueprint>(*this); }
    [[nodiscard]] extension_type type() const override { return extension_type::kNpn; }
};

class channel_id_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<channel_id_blueprint>(*this); }
    bool& old_id() { return old_id_; }
    [[nodiscard]] bool old_id() const { return old_id_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kChannelID; }

   private:
    bool old_id_ = false;
};

class delegated_credentials_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<delegated_credentials_blueprint>(*this); }
    std::vector<std::uint16_t>& algorithms() { return algorithms_; }
    [[nodiscard]] const std::vector<std::uint16_t>& algorithms() const { return algorithms_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kDelegatedCredentials; }

   private:
    std::vector<std::uint16_t> algorithms_;
};

class record_size_limit_blueprint : public extension_blueprint
{
   public:
    [[nodiscard]] std::shared_ptr<extension_blueprint> clone() const override { return std::make_shared<record_size_limit_blueprint>(*this); }
    std::uint16_t& limit() { return limit_; }
    [[nodiscard]] std::uint16_t limit() const { return limit_; }
    [[nodiscard]] extension_type type() const override { return extension_type::kRecordSizeLimit; }

   private:
    std::uint16_t limit_ = 0;
};

}    // namespace reality

#endif
