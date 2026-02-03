#include "reality_fingerprint.h"
#include <algorithm>
#include <random>
#include <openssl/rand.h>

namespace reality
{

namespace
{
const std::vector<uint16_t> GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};
}

GreaseContext::GreaseContext()
{
    if (RAND_bytes(reinterpret_cast<uint8_t*>(seed_.data()), seed_.size() * 2) != 1)
    {
        for (auto& s : seed_) s = 0x0a0a;
    }
}

uint16_t GreaseContext::get_grease(int index) const
{
    uint16_t val = seed_[index % seed_.size()];
    uint8_t idx = (val >> 8) ^ (val & 0xFF);
    return GREASE_VALUES[idx % GREASE_VALUES.size()];
}

uint16_t GreaseContext::get_extension_grease(int nth_occurrence) const
{
    uint16_t val1 = get_grease(2);
    uint16_t val2 = get_grease(3);
    if (val1 == val2)
        val2 ^= 0x1010;
    return (nth_occurrence == 0) ? val1 : val2;
}

FingerprintSpec FingerprintFactory::Get(FingerprintType type)
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
    return spec;
}

FingerprintSpec FingerprintFactory::GetChrome120()
{
    FingerprintSpec spec;
    spec.client_version = tls_consts::VER_1_2;
    spec.cipher_suites = {GREASE_PLACEHOLDER, 0x1301, 0x1302, 0x1303};
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
    vers->versions = {GREASE_PLACEHOLDER, tls_consts::VER_1_3};
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

void FingerprintFactory::shuffle_extensions(std::vector<std::shared_ptr<ExtensionBlueprint>>& exts)
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

}    // namespace reality
