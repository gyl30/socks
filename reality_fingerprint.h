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
    GreaseContext()
    {
        if (RAND_bytes(reinterpret_cast<uint8_t*>(seed_.data()), seed_.size() * 2) != 1)
        {
            for (auto& s : seed_) s = 0x0a0a;
        }
    }

    uint16_t get_grease(int index) const
    {
        static const std::vector<uint16_t> GREASE_VALUES = {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
        uint16_t val = seed_[index % seed_.size()];
        uint8_t idx = (val >> 8) ^ (val & 0xFF);
        return GREASE_VALUES[idx % GREASE_VALUES.size()];
    }

    uint16_t get_extension_grease(int nth_occurrence) const
    {
        uint16_t val1 = get_grease(2);
        uint16_t val2 = get_grease(3);
        if (val1 == val2)
            val2 ^= 0x1010;
        return (nth_occurrence == 0) ? val1 : val2;
    }

   private:
    std::array<uint16_t, 8> seed_;
};

class FingerprintFactory
{
   public:
    static FingerprintSpec Get(FingerprintType type)
    {
        FingerprintSpec spec;
        spec.client_version = tls_consts::VER_1_2;

        auto grease = std::make_shared<GreaseBlueprint>();
        auto sni = std::make_shared<SNIBlueprint>();
        auto ems = std::make_shared<EMSBlueprint>();
        auto reneg = std::make_shared<RenegotiationBlueprint>();
        auto session_ticket = std::make_shared<SessionTicketBlueprint>();
        auto status_req = std::make_shared<StatusRequestBlueprint>();
        auto sct = std::make_shared<SCTBlueprint>();
        auto padding = std::make_shared<PaddingBlueprint>();

        switch (type)
        {
            case FingerprintType::Chrome_120:
            default:
                return GetChrome120();

            case FingerprintType::Chrome_58:
            case FingerprintType::Chrome_62:
            {
                spec.cipher_suites = {
                    GREASE_PLACEHOLDER,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                };
                spec.extensions.push_back(grease);
                spec.extensions.push_back(reneg);
                spec.extensions.push_back(sni);
                spec.extensions.push_back(ems);
                spec.extensions.push_back(session_ticket);

                auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
                sig->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA256,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA256,
                                   tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA384,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA1};
                spec.extensions.push_back(sig);
                spec.extensions.push_back(status_req);
                spec.extensions.push_back(sct);

                auto alpn = std::make_shared<ALPNBlueprint>();
                alpn->protocols = {"h2", "http/1.1"};
                spec.extensions.push_back(alpn);

                auto ch_id = std::make_shared<ChannelIDBlueprint>();
                spec.extensions.push_back(ch_id);

                auto points = std::make_shared<ECPointFormatsBlueprint>();
                points->formats = {0x00};
                spec.extensions.push_back(points);

                auto groups = std::make_shared<SupportedGroupsBlueprint>();
                groups->groups = {GREASE_PLACEHOLDER, tls_consts::group::X25519, tls_consts::group::SECP256R1, tls_consts::group::SECP384R1};
                spec.extensions.push_back(groups);

                spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
                spec.extensions.push_back(padding);
                break;
            }

            case FingerprintType::Chrome_70:
            case FingerprintType::Chrome_72:
            case FingerprintType::Chrome_83:
            case FingerprintType::Chrome_87:
            {
                spec.cipher_suites = {
                    GREASE_PLACEHOLDER,
                    tls_consts::cipher::TLS_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_CHACHA20_POLY1305_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
                };

                spec.extensions.push_back(grease);
                spec.extensions.push_back(sni);
                spec.extensions.push_back(ems);
                spec.extensions.push_back(reneg);

                auto groups = std::make_shared<SupportedGroupsBlueprint>();
                groups->groups = {GREASE_PLACEHOLDER, tls_consts::group::X25519, tls_consts::group::SECP256R1, tls_consts::group::SECP384R1};
                spec.extensions.push_back(groups);

                auto points = std::make_shared<ECPointFormatsBlueprint>();
                points->formats = {0x00};
                spec.extensions.push_back(points);

                spec.extensions.push_back(session_ticket);

                auto alpn = std::make_shared<ALPNBlueprint>();
                alpn->protocols = {"h2", "http/1.1"};
                spec.extensions.push_back(alpn);

                spec.extensions.push_back(status_req);

                auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
                sig->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA256,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA256,
                                   tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA384,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA512};
                spec.extensions.push_back(sig);
                spec.extensions.push_back(sct);

                auto ks = std::make_shared<KeyShareBlueprint>();
                ks->key_shares = {{GREASE_PLACEHOLDER, {}}, {tls_consts::group::X25519, {}}};
                spec.extensions.push_back(ks);

                auto pskm = std::make_shared<PSKKeyExchangeModesBlueprint>();
                pskm->modes = {0x01};
                spec.extensions.push_back(pskm);

                auto vers = std::make_shared<SupportedVersionsBlueprint>();
                vers->versions = {GREASE_PLACEHOLDER, tls_consts::VER_1_3, tls_consts::VER_1_2, tls_consts::VER_1_1, tls_consts::VER_1_0};
                spec.extensions.push_back(vers);

                auto comp = std::make_shared<CompressCertBlueprint>();
                comp->algorithms = {tls_consts::compress::BROTLI};
                spec.extensions.push_back(comp);

                spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
                spec.extensions.push_back(padding);
                break;
            }

            case FingerprintType::Chrome_106_Shuffle:
            {
                auto base = GetChrome120();
                std::erase_if(base.extensions,
                              [](const auto& e) { return e->type() == ExtensionType::ApplicationSettings || e->type() == ExtensionType::GreaseECH; });
                base.shuffle_extensions = true;
                return base;
            }

            case FingerprintType::Chrome_131:
            {
                auto s = GetChrome120();
                for (auto& ext : s.extensions)
                {
                    if (ext->type() == ExtensionType::SupportedGroups)
                    {
                        auto g = std::static_pointer_cast<SupportedGroupsBlueprint>(ext);
                        g->groups = {GREASE_PLACEHOLDER,
                                     tls_consts::group::X25519_MLKEM768,
                                     tls_consts::group::X25519,
                                     tls_consts::group::SECP256R1,
                                     tls_consts::group::SECP384R1};
                    }
                    if (ext->type() == ExtensionType::KeyShare)
                    {
                        auto k = std::static_pointer_cast<KeyShareBlueprint>(ext);
                        k->key_shares = {{GREASE_PLACEHOLDER, {}}, {tls_consts::group::X25519_MLKEM768, {}}, {tls_consts::group::X25519, {}}};
                    }
                }
                return s;
            }

            case FingerprintType::Chrome_133:
            {
                auto s = GetChrome120();

                for (auto& ext : s.extensions)
                {
                    if (ext->type() == ExtensionType::ApplicationSettings)
                    {
                        auto alps = std::make_shared<ApplicationSettingsNewBlueprint>();
                        alps->supported_protocols = {"h2"};
                        ext = alps;
                    }
                    if (ext->type() == ExtensionType::SupportedGroups)
                    {
                        auto g = std::static_pointer_cast<SupportedGroupsBlueprint>(ext);
                        g->groups = {GREASE_PLACEHOLDER,
                                     tls_consts::group::X25519_MLKEM768,
                                     tls_consts::group::X25519,
                                     tls_consts::group::SECP256R1,
                                     tls_consts::group::SECP384R1};
                    }
                    if (ext->type() == ExtensionType::KeyShare)
                    {
                        auto k = std::static_pointer_cast<KeyShareBlueprint>(ext);
                        k->key_shares = {{GREASE_PLACEHOLDER, {}}, {tls_consts::group::X25519_MLKEM768, {}}, {tls_consts::group::X25519, {}}};
                    }
                }
                return s;
            }

            case FingerprintType::Firefox_102:
            case FingerprintType::Firefox_120:
            {
                spec.cipher_suites = {
                    tls_consts::cipher::TLS_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_CHACHA20_POLY1305_SHA256,
                    tls_consts::cipher::TLS_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
                };

                spec.extensions.push_back(sni);
                spec.extensions.push_back(ems);
                spec.extensions.push_back(reneg);

                auto groups = std::make_shared<SupportedGroupsBlueprint>();
                groups->groups = {
                    tls_consts::group::X25519, tls_consts::group::SECP256R1, tls_consts::group::SECP384R1, tls_consts::group::SECP521R1, 256, 257};
                spec.extensions.push_back(groups);

                auto points = std::make_shared<ECPointFormatsBlueprint>();
                points->formats = {0x00};
                spec.extensions.push_back(points);

                spec.extensions.push_back(session_ticket);

                auto alpn = std::make_shared<ALPNBlueprint>();
                alpn->protocols = {"h2", "http/1.1"};
                spec.extensions.push_back(alpn);

                spec.extensions.push_back(status_req);

                auto dc = std::make_shared<DelegatedCredentialsBlueprint>();
                dc->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                                  tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                                  tls_consts::sig_alg::ECDSA_SECP521R1_SHA512,
                                  tls_consts::sig_alg::ECDSA_SHA1};
                spec.extensions.push_back(dc);

                auto ks = std::make_shared<KeyShareBlueprint>();
                ks->key_shares = {{tls_consts::group::X25519, {}}, {tls_consts::group::SECP256R1, {}}};
                spec.extensions.push_back(ks);

                auto vers = std::make_shared<SupportedVersionsBlueprint>();
                vers->versions = {tls_consts::VER_1_3, tls_consts::VER_1_2};
                spec.extensions.push_back(vers);

                auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
                sig->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                                   tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                                   tls_consts::sig_alg::ECDSA_SECP521R1_SHA512,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA256,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA256,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA384,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA512,
                                   tls_consts::sig_alg::ECDSA_SHA1,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA1};
                spec.extensions.push_back(sig);

                auto pskm = std::make_shared<PSKKeyExchangeModesBlueprint>();
                pskm->modes = {0x01};
                spec.extensions.push_back(pskm);

                auto rsl = std::make_shared<RecordSizeLimitBlueprint>();
                rsl->limit = 0x4001;
                spec.extensions.push_back(rsl);

                spec.extensions.push_back(padding);
                break;
            }

            case FingerprintType::iOS_14:
            {
                spec.cipher_suites = {
                    GREASE_PLACEHOLDER,
                    tls_consts::cipher::TLS_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_CHACHA20_POLY1305_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_GCM_SHA384,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_GCM_SHA256,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_CBC_SHA256,
                    tls_consts::cipher::TLS_RSA_WITH_AES_256_CBC_SHA,
                    tls_consts::cipher::TLS_RSA_WITH_AES_128_CBC_SHA,
                };

                spec.extensions.push_back(grease);
                spec.extensions.push_back(sni);
                spec.extensions.push_back(ems);
                spec.extensions.push_back(reneg);

                auto groups = std::make_shared<SupportedGroupsBlueprint>();
                groups->groups = {GREASE_PLACEHOLDER,
                                  tls_consts::group::X25519,
                                  tls_consts::group::SECP256R1,
                                  tls_consts::group::SECP384R1,
                                  tls_consts::group::SECP521R1};
                spec.extensions.push_back(groups);

                auto points = std::make_shared<ECPointFormatsBlueprint>();
                points->formats = {0x00};
                spec.extensions.push_back(points);

                auto alpn = std::make_shared<ALPNBlueprint>();
                alpn->protocols = {"h2", "http/1.1"};
                spec.extensions.push_back(alpn);

                spec.extensions.push_back(status_req);

                auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
                sig->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA256,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA256,
                                   tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                                   tls_consts::sig_alg::ECDSA_SHA1,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA384,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA384,
                                   tls_consts::sig_alg::RSA_PSS_RSAE_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA512,
                                   tls_consts::sig_alg::RSA_PKCS1_SHA1};
                spec.extensions.push_back(sig);
                spec.extensions.push_back(sct);

                auto ks = std::make_shared<KeyShareBlueprint>();
                ks->key_shares = {{GREASE_PLACEHOLDER, {}}, {tls_consts::group::X25519, {}}};
                spec.extensions.push_back(ks);

                auto pskm = std::make_shared<PSKKeyExchangeModesBlueprint>();
                pskm->modes = {0x01};
                spec.extensions.push_back(pskm);

                auto vers = std::make_shared<SupportedVersionsBlueprint>();
                vers->versions = {GREASE_PLACEHOLDER, tls_consts::VER_1_3, tls_consts::VER_1_2, tls_consts::VER_1_1, tls_consts::VER_1_0};
                spec.extensions.push_back(vers);

                spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
                spec.extensions.push_back(padding);
                break;
            }

            case FingerprintType::Browser360_11_0:
            {
                auto s = Get(FingerprintType::Chrome_83);
                auto ch_id = std::make_shared<ChannelIDBlueprint>();
                ch_id->old_id = false;

                s.extensions.insert(s.extensions.end() - 2, ch_id);
                return s;
            }
        }
        return GetChrome120();
    }

    static FingerprintSpec GetChrome120()
    {
        FingerprintSpec spec;
        spec.client_version = tls_consts::VER_1_2;
        spec.cipher_suites = {GREASE_PLACEHOLDER,
                              0x1301,
                              0x1302,
                              0x1303,
                              0xc02b,
                              0xc02f,
                              0xc02c,
                              0xc030,
                              0xcca9,
                              0xcca8,
                              0xc013,
                              0xc014,
                              0x009c,
                              0x009d,
                              0x002f,
                              0x0035};
        spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
        spec.extensions.push_back(std::make_shared<SNIBlueprint>());
        spec.extensions.push_back(std::make_shared<EMSBlueprint>());
        spec.extensions.push_back(std::make_shared<RenegotiationBlueprint>());

        auto curves = std::make_shared<SupportedGroupsBlueprint>();
        curves->groups = {GREASE_PLACEHOLDER, tls_consts::group::X25519, tls_consts::group::SECP256R1, tls_consts::group::SECP384R1};
        spec.extensions.push_back(curves);

        auto points = std::make_shared<ECPointFormatsBlueprint>();
        points->formats = {0x00};
        spec.extensions.push_back(points);
        spec.extensions.push_back(std::make_shared<SessionTicketBlueprint>());

        auto alpn = std::make_shared<ALPNBlueprint>();
        alpn->protocols = {"h2", "http/1.1"};
        spec.extensions.push_back(alpn);

        spec.extensions.push_back(std::make_shared<StatusRequestBlueprint>());

        auto sigs = std::make_shared<SignatureAlgorithmsBlueprint>();
        sigs->algorithms = {tls_consts::sig_alg::ECDSA_SECP256R1_SHA256,
                            tls_consts::sig_alg::RSA_PSS_RSAE_SHA256,
                            tls_consts::sig_alg::RSA_PKCS1_SHA256,
                            tls_consts::sig_alg::ECDSA_SECP384R1_SHA384,
                            tls_consts::sig_alg::RSA_PSS_RSAE_SHA384,
                            tls_consts::sig_alg::RSA_PKCS1_SHA384,
                            tls_consts::sig_alg::RSA_PSS_RSAE_SHA512,
                            tls_consts::sig_alg::RSA_PKCS1_SHA512};
        spec.extensions.push_back(sigs);
        spec.extensions.push_back(std::make_shared<SCTBlueprint>());

        auto ks = std::make_shared<KeyShareBlueprint>();
        ks->key_shares.push_back({GREASE_PLACEHOLDER, {}});
        ks->key_shares.push_back({tls_consts::group::X25519, {}});
        spec.extensions.push_back(ks);

        auto psk_modes = std::make_shared<PSKKeyExchangeModesBlueprint>();
        psk_modes->modes = {0x01};
        spec.extensions.push_back(psk_modes);

        auto vers = std::make_shared<SupportedVersionsBlueprint>();
        vers->versions = {GREASE_PLACEHOLDER, tls_consts::VER_1_3, tls_consts::VER_1_2};
        spec.extensions.push_back(vers);

        auto comp = std::make_shared<CompressCertBlueprint>();
        comp->algorithms = {tls_consts::compress::BROTLI};
        spec.extensions.push_back(comp);

        auto alps = std::make_shared<ApplicationSettingsBlueprint>();
        alps->supported_protocols = {"h2"};
        spec.extensions.push_back(alps);

        spec.extensions.push_back(std::make_shared<GreaseECHBlueprint>());
        spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
        spec.extensions.push_back(std::make_shared<PaddingBlueprint>());

        spec.shuffle_extensions = true;
        return spec;
    }

    static void shuffle_extensions(std::vector<std::shared_ptr<ExtensionBlueprint>>& exts)
    {
        std::vector<size_t> indices;
        std::vector<std::shared_ptr<ExtensionBlueprint>> shufflable_exts;

        for (size_t i = 0; i < exts.size(); ++i)
        {
            if (exts[i]->is_shufflable())
            {
                indices.push_back(i);
                shufflable_exts.push_back(exts[i]);
            }
        }
        if (indices.empty())
        {
            return;
        }

        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(shufflable_exts.begin(), shufflable_exts.end(), g);

        for (size_t i = 0; i < indices.size(); ++i)
        {
            exts[indices[i]] = shufflable_exts[i];
        }
    }
};

}    // namespace reality

#endif
