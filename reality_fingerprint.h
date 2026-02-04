#ifndef REALITY_FINGERPRINT_H
#define REALITY_FINGERPRINT_H

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <openssl/rand.h>

#include "reality_core.h"

namespace reality
{

enum class FingerprintType
{
    Chrome_58,
    Chrome_62,
    Chrome_70,
    Chrome_72,
    Chrome_83,
    Chrome_87,
    Chrome_96,
    Chrome_100,
    Chrome_102,
    Chrome_106_Shuffle,
    Chrome_115_PQ,
    Chrome_120,
    Chrome_120_PQ,
    Chrome_131,
    Chrome_133,
    Firefox_55,
    Firefox_56,
    Firefox_63,
    Firefox_65,
    Firefox_99,
    Firefox_102,
    Firefox_105,
    Firefox_120,
    iOS_11_1,
    iOS_12_1,
    iOS_13,
    iOS_14,
    Android_11_OkHttp,
    Edge_85,
    Edge_106,
    Safari_16_0,
    Browser360_7_5,
    Browser360_11_0,
    QQ_11_1
};

enum class ExtensionType
{
    GREASE,
    SNI,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups,
    ECPointFormats,
    SessionTicket,
    ALPN,
    StatusRequest,
    SignatureAlgorithms,
    SCT,
    KeyShare,
    PSKKeyExchangeModes,
    SupportedVersions,
    CompressCertificate,
    ApplicationSettings,
    ApplicationSettingsNew,
    GreaseECH,
    Padding,
    PreSharedKey,
    NPN,
    ChannelID,
    DelegatedCredentials,
    RecordSizeLimit,
    Generic
};

struct ExtensionBlueprint
{
    virtual ~ExtensionBlueprint() = default;
    [[nodiscard]] virtual ExtensionType type() const = 0;
    [[nodiscard]] virtual bool is_shufflable() const { return true; }
};

struct GreaseBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::GREASE; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

struct SNIBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SNI; }
};

struct EMSBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ExtendedMasterSecret; }
};

struct RenegotiationBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::RenegotiationInfo; }
};

struct SupportedGroupsBlueprint : ExtensionBlueprint
{
    std::vector<std::uint16_t> groups;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SupportedGroups; }
};

struct ECPointFormatsBlueprint : ExtensionBlueprint
{
    std::vector<std::uint8_t> formats;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ECPointFormats; }
};

struct SessionTicketBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SessionTicket; }
};

struct ALPNBlueprint : ExtensionBlueprint
{
    std::vector<std::string> protocols;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ALPN; }
};

struct StatusRequestBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::StatusRequest; }
};

struct SignatureAlgorithmsBlueprint : ExtensionBlueprint
{
    std::vector<std::uint16_t> algorithms;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SignatureAlgorithms; }
};

struct SCTBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SCT; }
};

struct KeyShareBlueprint : ExtensionBlueprint
{
    struct Entry
    {
        std::uint16_t group;
        std::vector<std::uint8_t> data;
    };
    std::vector<Entry> key_shares;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::KeyShare; }
};

struct PSKKeyExchangeModesBlueprint : ExtensionBlueprint
{
    std::vector<std::uint8_t> modes;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::PSKKeyExchangeModes; }
};

struct SupportedVersionsBlueprint : ExtensionBlueprint
{
    std::vector<std::uint16_t> versions;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::SupportedVersions; }
};

struct CompressCertBlueprint : ExtensionBlueprint
{
    std::vector<std::uint16_t> algorithms;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::CompressCertificate; }
};

struct ApplicationSettingsBlueprint : ExtensionBlueprint
{
    std::vector<std::string> supported_protocols;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ApplicationSettings; }
};

struct ApplicationSettingsNewBlueprint : ExtensionBlueprint
{
    std::vector<std::string> supported_protocols;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ApplicationSettingsNew; }
};

struct GreaseECHBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::GreaseECH; }
};

struct PaddingBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::Padding; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

struct PreSharedKeyBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::PreSharedKey; }
    [[nodiscard]] bool is_shufflable() const override { return false; }
};

struct NPNBlueprint : ExtensionBlueprint
{
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::NPN; }
};

struct ChannelIDBlueprint : ExtensionBlueprint
{
    bool old_id = false;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::ChannelID; }
};

struct DelegatedCredentialsBlueprint : ExtensionBlueprint
{
    std::vector<std::uint16_t> algorithms;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::DelegatedCredentials; }
};

struct RecordSizeLimitBlueprint : ExtensionBlueprint
{
    std::uint16_t limit;
    [[nodiscard]] ExtensionType type() const override { return ExtensionType::RecordSizeLimit; }
};

struct FingerprintSpec
{
    std::uint16_t client_version = tls_consts::VER_1_2;
    std::vector<std::uint16_t> cipher_suites;
    std::vector<std::uint8_t> compression_methods = {0x00};
    std::vector<std::shared_ptr<ExtensionBlueprint>> extensions;
    bool shuffle_extensions = false;
};

class GreaseContext
{
   public:
    GreaseContext();

    [[nodiscard]] std::uint16_t get_grease(int index) const;

    [[nodiscard]] std::uint16_t get_extension_grease(int nth_occurrence) const;

   private:
    std::array<std::uint16_t, 8> seed_;
};

class FingerprintFactory
{
   public:
    static FingerprintSpec Get(FingerprintType type);

    static FingerprintSpec GetChrome120();

    static void shuffle_extensions(std::vector<std::shared_ptr<ExtensionBlueprint>>& exts);
};

}    // namespace reality

#endif