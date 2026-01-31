#ifndef REALITY_FINGERPRINT_H
#define REALITY_FINGERPRINT_H

#include <vector>
#include <string>
#include <memory>
#include <random>
#include <algorithm>
#include <cstdint>
#include <array>
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
    virtual ExtensionType type() const = 0;
    virtual bool is_shufflable() const { return true; }
};

struct GreaseBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::GREASE; }
    bool is_shufflable() const override { return false; }
};

struct SNIBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::SNI; }
};

struct EMSBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::ExtendedMasterSecret; }
};

struct RenegotiationBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::RenegotiationInfo; }
};

struct SupportedGroupsBlueprint : ExtensionBlueprint
{
    std::vector<uint16_t> groups;
    ExtensionType type() const override { return ExtensionType::SupportedGroups; }
};

struct ECPointFormatsBlueprint : ExtensionBlueprint
{
    std::vector<uint8_t> formats;
    ExtensionType type() const override { return ExtensionType::ECPointFormats; }
};

struct SessionTicketBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::SessionTicket; }
};

struct ALPNBlueprint : ExtensionBlueprint
{
    std::vector<std::string> protocols;
    ExtensionType type() const override { return ExtensionType::ALPN; }
};

struct StatusRequestBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::StatusRequest; }
};

struct SignatureAlgorithmsBlueprint : ExtensionBlueprint
{
    std::vector<uint16_t> algorithms;
    ExtensionType type() const override { return ExtensionType::SignatureAlgorithms; }
};

struct SCTBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::SCT; }
};

struct KeyShareBlueprint : ExtensionBlueprint
{
    struct Entry
    {
        uint16_t group;
        std::vector<uint8_t> data;
    };
    std::vector<Entry> key_shares;
    ExtensionType type() const override { return ExtensionType::KeyShare; }
};

struct PSKKeyExchangeModesBlueprint : ExtensionBlueprint
{
    std::vector<uint8_t> modes;
    ExtensionType type() const override { return ExtensionType::PSKKeyExchangeModes; }
};

struct SupportedVersionsBlueprint : ExtensionBlueprint
{
    std::vector<uint16_t> versions;
    ExtensionType type() const override { return ExtensionType::SupportedVersions; }
};

struct CompressCertBlueprint : ExtensionBlueprint
{
    std::vector<uint16_t> algorithms;
    ExtensionType type() const override { return ExtensionType::CompressCertificate; }
};

struct ApplicationSettingsBlueprint : ExtensionBlueprint
{
    std::vector<std::string> supported_protocols;
    ExtensionType type() const override { return ExtensionType::ApplicationSettings; }
};

struct ApplicationSettingsNewBlueprint : ExtensionBlueprint
{
    std::vector<std::string> supported_protocols;
    ExtensionType type() const override { return ExtensionType::ApplicationSettingsNew; }
};

struct GreaseECHBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::GreaseECH; }
};

struct PaddingBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::Padding; }
    bool is_shufflable() const override { return false; }
};

struct PreSharedKeyBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::PreSharedKey; }
    bool is_shufflable() const override { return false; }
};

struct NPNBlueprint : ExtensionBlueprint
{
    ExtensionType type() const override { return ExtensionType::NPN; }
};

struct ChannelIDBlueprint : ExtensionBlueprint
{
    bool old_id = false;
    ExtensionType type() const override { return ExtensionType::ChannelID; }
};

struct DelegatedCredentialsBlueprint : ExtensionBlueprint
{
    std::vector<uint16_t> algorithms;
    ExtensionType type() const override { return ExtensionType::DelegatedCredentials; }
};

struct RecordSizeLimitBlueprint : ExtensionBlueprint
{
    uint16_t limit;
    ExtensionType type() const override { return ExtensionType::RecordSizeLimit; }
};

struct FingerprintSpec
{
    uint16_t client_version = tls_consts::VER_1_2;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint8_t> compression_methods = {0x00};
    std::vector<std::shared_ptr<ExtensionBlueprint>> extensions;
    bool shuffle_extensions = false;
};

class GreaseContext
{
   public:
    GreaseContext();

    uint16_t get_grease(int index) const;

    uint16_t get_extension_grease(int nth_occurrence) const;

   private:
    std::array<uint16_t, 8> seed_;
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
