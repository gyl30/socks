#include <array>
#include <memory>
#include <random>
#include <limits>
#include <vector>
#include <cstdint>
#include <algorithm>

extern "C"
{
#include <openssl/rand.h>
}

#include "reality_core.h"
#include "reality_fingerprint.h"

namespace reality
{

namespace
{

constexpr auto kGreaseValues = std::to_array<std::uint16_t>(
    {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa});

}

static FingerprintSpec BuildChrome70To87Spec()
{
    FingerprintSpec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {
        kGreasePlaceholder,
        tls_consts::cipher::kTlsAes128GcmSha256,
        tls_consts::cipher::kTlsAes256GcmSha384,
        tls_consts::cipher::kTlsChacha20Poly1305Sha256,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        tls_consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsRsaWithAes256CbcSha,
    };

    const auto grease = std::make_shared<GreaseBlueprint>();
    const auto sni = std::make_shared<SNIBlueprint>();
    const auto ems = std::make_shared<EMSBlueprint>();
    const auto reneg = std::make_shared<RenegotiationBlueprint>();
    const auto session_ticket = std::make_shared<SessionTicketBlueprint>();
    const auto status_req = std::make_shared<StatusRequestBlueprint>();
    const auto sct = std::make_shared<SCTBlueprint>();
    const auto padding = std::make_shared<PaddingBlueprint>();

    spec.extensions.push_back(grease);
    spec.extensions.push_back(sni);
    spec.extensions.push_back(ems);
    spec.extensions.push_back(reneg);

    auto groups = std::make_shared<SupportedGroupsBlueprint>();
    groups->groups = {kGreasePlaceholder, tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1};
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
    sig->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                       tls_consts::sig_alg::kRsaPssRsaeSha256,
                       tls_consts::sig_alg::kRsaPkcs1Sha256,
                       tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                       tls_consts::sig_alg::kRsaPssRsaeSha384,
                       tls_consts::sig_alg::kRsaPkcs1Sha384,
                       tls_consts::sig_alg::kRsaPssRsaeSha512,
                       tls_consts::sig_alg::kRsaPkcs1Sha512};
    spec.extensions.push_back(sig);
    spec.extensions.push_back(sct);

    auto ks = std::make_shared<KeyShareBlueprint>();
    ks->key_shares = {{.group = kGreasePlaceholder, .data = {}}, {.group = tls_consts::group::kX25519, .data = {}}};
    spec.extensions.push_back(ks);

    auto pskm = std::make_shared<PSKKeyExchangeModesBlueprint>();
    pskm->modes = {0x01};
    spec.extensions.push_back(pskm);

    auto vers = std::make_shared<SupportedVersionsBlueprint>();
    vers->versions = {kGreasePlaceholder, tls_consts::kVer13, tls_consts::kVer12, tls_consts::kVer11, tls_consts::kVer10};
    spec.extensions.push_back(vers);

    auto comp = std::make_shared<CompressCertBlueprint>();
    comp->algorithms = {tls_consts::compress::kBrotli};
    spec.extensions.push_back(comp);

    spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
    spec.extensions.push_back(padding);

    return spec;
}

GreaseContext::GreaseContext()
{
    const std::size_t seed_len = seed_.size() * sizeof(seed_[0]);
    if (seed_len > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        RAND_bytes(reinterpret_cast<std::uint8_t*>(seed_.data()), static_cast<int>(seed_len)) != 1)
    {
        for (auto& s : seed_)
        {
            s = 0x0a0a;
        }
    }
}

std::uint16_t GreaseContext::get_grease(int index) const
{
    const std::uint16_t val = seed_[static_cast<std::size_t>(index) % seed_.size()];
    const auto idx = static_cast<std::uint8_t>((val >> 8) ^ (val & 0xFF));
    return kGreaseValues[idx % kGreaseValues.size()];
}

std::uint16_t GreaseContext::get_extension_grease(int nth_occurrence) const
{
    const std::uint16_t val1 = get_grease(2);
    std::uint16_t val2 = get_grease(3);
    if (val1 == val2)
    {
        val2 ^= 0x1010;
    }
    return (nth_occurrence == 0) ? val1 : val2;
}

FingerprintSpec FingerprintFactory::Get(FingerprintType type)
{
    FingerprintSpec spec;
    spec.client_version = tls_consts::kVer12;

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
                kGreasePlaceholder,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
                tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
                tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsRsaWithAes128CbcSha,
                tls_consts::cipher::kTlsRsaWithAes256CbcSha,
                tls_consts::cipher::kTlsRsaWith3desEdeCbcSha,
            };
            spec.extensions.push_back(grease);
            spec.extensions.push_back(reneg);
            spec.extensions.push_back(sni);
            spec.extensions.push_back(ems);
            spec.extensions.push_back(session_ticket);

            auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
            sig->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                               tls_consts::sig_alg::kRsaPssRsaeSha256,
                               tls_consts::sig_alg::kRsaPkcs1Sha256,
                               tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                               tls_consts::sig_alg::kRsaPssRsaeSha384,
                               tls_consts::sig_alg::kRsaPkcs1Sha384,
                               tls_consts::sig_alg::kRsaPssRsaeSha512,
                               tls_consts::sig_alg::kRsaPkcs1Sha512,
                               tls_consts::sig_alg::kRsaPkcs1Sha1};
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
            groups->groups = {kGreasePlaceholder, tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1};
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
            return BuildChrome70To87Spec();
        }

        case FingerprintType::Chrome_106_Shuffle:
        {
            auto base = GetChrome120();
            std::erase_if(base.extensions,
                          [](const auto& e) { return e->type() == ExtensionType::kApplicationSettings || e->type() == ExtensionType::kGreaseECH; });
            base.shuffle_extensions = true;
            return base;
        }

        case FingerprintType::Chrome_131:
        {
            auto s = GetChrome120();
            for (auto& ext : s.extensions)
            {
                if (ext->type() == ExtensionType::kSupportedGroups)
                {
                    auto g = std::static_pointer_cast<SupportedGroupsBlueprint>(ext);
                    g->groups = {kGreasePlaceholder,
                                 tls_consts::group::kX25519Mlkem768,
                                 tls_consts::group::kX25519,
                                 tls_consts::group::kSecp256r1,
                                 tls_consts::group::kSecp384r1};
                }
                if (ext->type() == ExtensionType::kKeyShare)
                {
                    auto k = std::static_pointer_cast<KeyShareBlueprint>(ext);
                    k->key_shares = {{.group = kGreasePlaceholder, .data = {}},
                                     {.group = tls_consts::group::kX25519Mlkem768, .data = {}},
                                     {.group = tls_consts::group::kX25519, .data = {}}};
                }
            }
            return s;
        }

        case FingerprintType::Chrome_133:
        {
            auto s = GetChrome120();

            for (auto& ext : s.extensions)
            {
                if (ext->type() == ExtensionType::kApplicationSettings)
                {
                    auto alps = std::make_shared<ApplicationSettingsNewBlueprint>();
                    alps->supported_protocols = {"h2"};
                    ext = alps;
                }
                if (ext->type() == ExtensionType::kSupportedGroups)
                {
                    auto g = std::static_pointer_cast<SupportedGroupsBlueprint>(ext);
                    g->groups = {kGreasePlaceholder,
                                 tls_consts::group::kX25519Mlkem768,
                                 tls_consts::group::kX25519,
                                 tls_consts::group::kSecp256r1,
                                 tls_consts::group::kSecp384r1};
                }
                if (ext->type() == ExtensionType::kKeyShare)
                {
                    auto k = std::static_pointer_cast<KeyShareBlueprint>(ext);
                    k->key_shares = {{.group = kGreasePlaceholder, .data = {}},
                                     {.group = tls_consts::group::kX25519Mlkem768, .data = {}},
                                     {.group = tls_consts::group::kX25519, .data = {}}};
                }
            }
            return s;
        }

        case FingerprintType::Firefox_102:
        case FingerprintType::Firefox_120:
        {
            spec.cipher_suites = {
                tls_consts::cipher::kTlsAes128GcmSha256,
                tls_consts::cipher::kTlsChacha20Poly1305Sha256,
                tls_consts::cipher::kTlsAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha,
                tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
                tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
                tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsRsaWithAes128CbcSha,
                tls_consts::cipher::kTlsRsaWithAes256CbcSha,
            };

            spec.extensions.push_back(sni);
            spec.extensions.push_back(ems);
            spec.extensions.push_back(reneg);

            auto groups = std::make_shared<SupportedGroupsBlueprint>();
            groups->groups = {
                tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1, tls_consts::group::kSecp521r1, 256, 257};
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
            dc->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                              tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                              tls_consts::sig_alg::kEcdsaSecp521r1Sha512,
                              tls_consts::sig_alg::kEcdsaSha1};
            spec.extensions.push_back(dc);

            auto ks = std::make_shared<KeyShareBlueprint>();
            ks->key_shares = {{.group = tls_consts::group::kX25519, .data = {}}, {.group = tls_consts::group::kSecp256r1, .data = {}}};
            spec.extensions.push_back(ks);

            auto vers = std::make_shared<SupportedVersionsBlueprint>();
            vers->versions = {tls_consts::kVer13, tls_consts::kVer12};
            spec.extensions.push_back(vers);

            auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
            sig->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                               tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                               tls_consts::sig_alg::kEcdsaSecp521r1Sha512,
                               tls_consts::sig_alg::kRsaPssRsaeSha256,
                               tls_consts::sig_alg::kRsaPssRsaeSha384,
                               tls_consts::sig_alg::kRsaPssRsaeSha512,
                               tls_consts::sig_alg::kRsaPkcs1Sha256,
                               tls_consts::sig_alg::kRsaPkcs1Sha384,
                               tls_consts::sig_alg::kRsaPkcs1Sha512,
                               tls_consts::sig_alg::kEcdsaSha1,
                               tls_consts::sig_alg::kRsaPkcs1Sha1};
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
                kGreasePlaceholder,
                tls_consts::cipher::kTlsAes128GcmSha256,
                tls_consts::cipher::kTlsAes256GcmSha384,
                tls_consts::cipher::kTlsChacha20Poly1305Sha256,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha256,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha,
                tls_consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha,
                tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha256,
                tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
                tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
                tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
                tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
                tls_consts::cipher::kTlsRsaWithAes128CbcSha256,
                tls_consts::cipher::kTlsRsaWithAes256CbcSha,
                tls_consts::cipher::kTlsRsaWithAes128CbcSha,
            };

            spec.extensions.push_back(grease);
            spec.extensions.push_back(sni);
            spec.extensions.push_back(ems);
            spec.extensions.push_back(reneg);

            auto groups = std::make_shared<SupportedGroupsBlueprint>();
            groups->groups = {kGreasePlaceholder,
                              tls_consts::group::kX25519,
                              tls_consts::group::kSecp256r1,
                              tls_consts::group::kSecp384r1,
                              tls_consts::group::kSecp521r1};
            spec.extensions.push_back(groups);

            auto points = std::make_shared<ECPointFormatsBlueprint>();
            points->formats = {0x00};
            spec.extensions.push_back(points);

            auto alpn = std::make_shared<ALPNBlueprint>();
            alpn->protocols = {"h2", "http/1.1"};
            spec.extensions.push_back(alpn);

            spec.extensions.push_back(status_req);

            auto sig = std::make_shared<SignatureAlgorithmsBlueprint>();
            sig->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                               tls_consts::sig_alg::kRsaPssRsaeSha256,
                               tls_consts::sig_alg::kRsaPkcs1Sha256,
                               tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                               tls_consts::sig_alg::kEcdsaSha1,
                               tls_consts::sig_alg::kRsaPssRsaeSha384,
                               tls_consts::sig_alg::kRsaPkcs1Sha384,
                               tls_consts::sig_alg::kRsaPssRsaeSha512,
                               tls_consts::sig_alg::kRsaPkcs1Sha512,
                               tls_consts::sig_alg::kRsaPkcs1Sha1};
            spec.extensions.push_back(sig);
            spec.extensions.push_back(sct);

            auto ks = std::make_shared<KeyShareBlueprint>();
            ks->key_shares = {{.group = kGreasePlaceholder, .data = {}}, {.group = tls_consts::group::kX25519, .data = {}}};
            spec.extensions.push_back(ks);

            auto pskm = std::make_shared<PSKKeyExchangeModesBlueprint>();
            pskm->modes = {0x01};
            spec.extensions.push_back(pskm);

            auto vers = std::make_shared<SupportedVersionsBlueprint>();
            vers->versions = {kGreasePlaceholder, tls_consts::kVer13, tls_consts::kVer12, tls_consts::kVer11, tls_consts::kVer10};
            spec.extensions.push_back(vers);

            spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
            spec.extensions.push_back(padding);
            break;
        }

        case FingerprintType::Browser360_11_0:
        {
            auto s = BuildChrome70To87Spec();
            auto ch_id = std::make_shared<ChannelIDBlueprint>();
            ch_id->old_id = false;

            s.extensions.insert(s.extensions.end() - 2, ch_id);
            return s;
        }
    }
    return spec;
}

FingerprintSpec FingerprintFactory::GetChrome120()
{
    FingerprintSpec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {kGreasePlaceholder, 0x1301, 0x1302, 0x1303};
    spec.extensions.push_back(std::make_shared<GreaseBlueprint>());
    spec.extensions.push_back(std::make_shared<SNIBlueprint>());
    spec.extensions.push_back(std::make_shared<EMSBlueprint>());
    spec.extensions.push_back(std::make_shared<RenegotiationBlueprint>());

    auto curves = std::make_shared<SupportedGroupsBlueprint>();
    curves->groups = {kGreasePlaceholder, tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1};
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
    sigs->algorithms = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                        tls_consts::sig_alg::kRsaPssRsaeSha256,
                        tls_consts::sig_alg::kRsaPkcs1Sha256,
                        tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                        tls_consts::sig_alg::kRsaPssRsaeSha384,
                        tls_consts::sig_alg::kRsaPkcs1Sha384,
                        tls_consts::sig_alg::kRsaPssRsaeSha512,
                        tls_consts::sig_alg::kRsaPkcs1Sha512};
    spec.extensions.push_back(sigs);
    spec.extensions.push_back(std::make_shared<SCTBlueprint>());

    auto ks = std::make_shared<KeyShareBlueprint>();
    ks->key_shares.push_back({.group = kGreasePlaceholder, .data = {}});
    ks->key_shares.push_back({.group = tls_consts::group::kX25519, .data = {}});
    spec.extensions.push_back(ks);

    auto psk_modes = std::make_shared<PSKKeyExchangeModesBlueprint>();
    psk_modes->modes = {0x01};
    spec.extensions.push_back(psk_modes);

    auto vers = std::make_shared<SupportedVersionsBlueprint>();
    vers->versions = {kGreasePlaceholder, tls_consts::kVer13};
    spec.extensions.push_back(vers);

    auto comp = std::make_shared<CompressCertBlueprint>();
    comp->algorithms = {tls_consts::compress::kBrotli};
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

void FingerprintFactory::shuffle_extensions(std::vector<std::shared_ptr<ExtensionBlueprint>>& exts)
{
    std::vector<std::size_t> indices;
    std::vector<std::shared_ptr<ExtensionBlueprint>> shufflable_exts;

    for (std::size_t i = 0; i < exts.size(); ++i)
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
    std::ranges::shuffle(shufflable_exts, g);

    for (std::size_t i = 0; i < indices.size(); ++i)
    {
        exts[indices[i]] = shufflable_exts[i];
    }
}

}    // namespace reality
