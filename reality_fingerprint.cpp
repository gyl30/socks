#include <array>
#include <cstddef>
#include <limits>
#include <memory>
#include <random>
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

grease_context::grease_context()
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

std::uint16_t grease_context::get_grease(int index) const
{
    const std::uint16_t val = seed_[static_cast<std::size_t>(index) % seed_.size()];
    const auto idx = static_cast<std::uint8_t>((val >> 8) ^ (val & 0xFF));
    return kGreaseValues[idx % kGreaseValues.size()];
}

std::uint16_t grease_context::get_extension_grease(int nth_occurrence) const
{
    const std::uint16_t val1 = get_grease(2);
    std::uint16_t val2 = get_grease(3);
    if (val1 == val2)
    {
        val2 ^= 0x1010;
    }
    return (nth_occurrence == 0) ? val1 : val2;
}

namespace
{

fingerprint_spec build_firefox120_spec()
{
    fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
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

    spec.extensions.push_back(std::make_shared<sni_blueprint>());
    spec.extensions.push_back(std::make_shared<ems_blueprint>());
    spec.extensions.push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {
        tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1, tls_consts::group::kSecp521r1, 256, 257};
    spec.extensions.push_back(groups);
    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    spec.extensions.push_back(points);
    spec.extensions.push_back(std::make_shared<session_ticket_blueprint>());

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    spec.extensions.push_back(alpn);
    spec.extensions.push_back(std::make_shared<status_request_blueprint>());

    auto dc = std::make_shared<delegated_credentials_blueprint>();
    dc->algorithms() = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                        tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                        tls_consts::sig_alg::kEcdsaSecp521r1Sha512,
                        tls_consts::sig_alg::kEcdsaSha1};
    spec.extensions.push_back(dc);

    auto key_share = std::make_shared<key_share_blueprint>();
    key_share->key_shares() = {{.group = tls_consts::group::kX25519, .data = {}}, {.group = tls_consts::group::kSecp256r1, .data = {}}};
    spec.extensions.push_back(key_share);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {tls_consts::kVer13, tls_consts::kVer12};
    spec.extensions.push_back(versions);

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
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

    auto psk_mode = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_mode->modes() = {0x01};
    spec.extensions.push_back(psk_mode);

    auto record_size = std::make_shared<record_size_limit_blueprint>();
    record_size->limit() = 0x4001;
    spec.extensions.push_back(record_size);

    spec.extensions.push_back(std::make_shared<grease_ech_blueprint>());
    return spec;
}

fingerprint_spec build_ios14_spec()
{
    fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
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
        tls_consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha384,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha256,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha,
        tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha384,
        tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha256,
        tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsRsaWithAes256CbcSha256,
        tls_consts::cipher::kTlsRsaWithAes128CbcSha256,
        tls_consts::cipher::kTlsRsaWithAes256CbcSha,
        tls_consts::cipher::kTlsRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsEcdheEcdsaWith3desEdeCbcSha,
        tls_consts::cipher::kTlsEcdheRsaWith3desEdeCbcSha,
        tls_consts::cipher::kTlsRsaWith3desEdeCbcSha,
    };

    spec.extensions.push_back(std::make_shared<grease_blueprint>());
    spec.extensions.push_back(std::make_shared<sni_blueprint>());
    spec.extensions.push_back(std::make_shared<ems_blueprint>());
    spec.extensions.push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {
        kGreasePlaceholder, tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1, tls_consts::group::kSecp521r1};
    spec.extensions.push_back(groups);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    spec.extensions.push_back(points);

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    spec.extensions.push_back(alpn);
    spec.extensions.push_back(std::make_shared<status_request_blueprint>());

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                         tls_consts::sig_alg::kRsaPssRsaeSha256,
                         tls_consts::sig_alg::kRsaPkcs1Sha256,
                         tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                         tls_consts::sig_alg::kEcdsaSha1,
                         tls_consts::sig_alg::kRsaPssRsaeSha384,
                         tls_consts::sig_alg::kRsaPssRsaeSha384,
                         tls_consts::sig_alg::kRsaPkcs1Sha384,
                         tls_consts::sig_alg::kRsaPssRsaeSha512,
                         tls_consts::sig_alg::kRsaPkcs1Sha512,
                         tls_consts::sig_alg::kRsaPkcs1Sha1};
    spec.extensions.push_back(sig);
    spec.extensions.push_back(std::make_shared<sct_blueprint>());

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares() = {{.group = kGreasePlaceholder, .data = {}}, {.group = tls_consts::group::kX25519, .data = {}}};
    spec.extensions.push_back(ks);

    auto psk_modes = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_modes->modes() = {0x01};
    spec.extensions.push_back(psk_modes);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {kGreasePlaceholder, tls_consts::kVer13, tls_consts::kVer12, tls_consts::kVer11, tls_consts::kVer10};
    spec.extensions.push_back(versions);

    spec.extensions.push_back(std::make_shared<grease_blueprint>());
    spec.extensions.push_back(std::make_shared<padding_blueprint>());
    return spec;
}

fingerprint_spec build_android11_spec()
{
    fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {
        tls_consts::cipher::kTlsAes128GcmSha256,
        tls_consts::cipher::kTlsAes256GcmSha384,
        tls_consts::cipher::kTlsChacha20Poly1305Sha256,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        tls_consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        tls_consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        tls_consts::cipher::kTlsRsaWithAes128GcmSha256,
        tls_consts::cipher::kTlsRsaWithAes256GcmSha384,
        tls_consts::cipher::kTlsRsaWithAes128CbcSha,
        tls_consts::cipher::kTlsRsaWithAes256CbcSha,
    };

    spec.extensions.push_back(std::make_shared<sni_blueprint>());
    spec.extensions.push_back(std::make_shared<ems_blueprint>());
    spec.extensions.push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1};
    spec.extensions.push_back(groups);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    spec.extensions.push_back(points);
    spec.extensions.push_back(std::make_shared<status_request_blueprint>());

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                         tls_consts::sig_alg::kRsaPssRsaeSha256,
                         tls_consts::sig_alg::kRsaPkcs1Sha256,
                         tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                         tls_consts::sig_alg::kRsaPssRsaeSha384,
                         tls_consts::sig_alg::kRsaPkcs1Sha384,
                         tls_consts::sig_alg::kRsaPssRsaeSha512,
                         tls_consts::sig_alg::kRsaPkcs1Sha512,
                         tls_consts::sig_alg::kRsaPkcs1Sha1};
    spec.extensions.push_back(sig);

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares() = {{.group = tls_consts::group::kX25519, .data = {}}};
    spec.extensions.push_back(ks);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {tls_consts::kVer13, tls_consts::kVer12};
    spec.extensions.push_back(versions);
    return spec;
}

fingerprint_spec build_chrome120_spec()
{
    fingerprint_spec spec;
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

    spec.extensions.push_back(std::make_shared<grease_blueprint>());
    spec.extensions.push_back(std::make_shared<sni_blueprint>());
    spec.extensions.push_back(std::make_shared<ems_blueprint>());
    spec.extensions.push_back(std::make_shared<renegotiation_blueprint>());

    auto curves = std::make_shared<supported_groups_blueprint>();
    curves->groups() = {kGreasePlaceholder, tls_consts::group::kX25519, tls_consts::group::kSecp256r1, tls_consts::group::kSecp384r1};
    spec.extensions.push_back(curves);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    spec.extensions.push_back(points);
    spec.extensions.push_back(std::make_shared<session_ticket_blueprint>());

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    spec.extensions.push_back(alpn);

    spec.extensions.push_back(std::make_shared<status_request_blueprint>());

    auto sigs = std::make_shared<signature_algorithms_blueprint>();
    sigs->algorithms() = {tls_consts::sig_alg::kEcdsaSecp256r1Sha256,
                          tls_consts::sig_alg::kRsaPssRsaeSha256,
                          tls_consts::sig_alg::kRsaPkcs1Sha256,
                          tls_consts::sig_alg::kEcdsaSecp384r1Sha384,
                          tls_consts::sig_alg::kRsaPssRsaeSha384,
                          tls_consts::sig_alg::kRsaPkcs1Sha384,
                          tls_consts::sig_alg::kRsaPssRsaeSha512,
                          tls_consts::sig_alg::kRsaPkcs1Sha512};
    spec.extensions.push_back(sigs);
    spec.extensions.push_back(std::make_shared<sct_blueprint>());

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares().push_back({.group = kGreasePlaceholder, .data = {}});
    ks->key_shares().push_back({.group = tls_consts::group::kX25519, .data = {}});
    spec.extensions.push_back(ks);

    auto psk_modes = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_modes->modes() = {0x01};
    spec.extensions.push_back(psk_modes);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {kGreasePlaceholder, tls_consts::kVer13, tls_consts::kVer12};
    spec.extensions.push_back(versions);

    auto comp = std::make_shared<compress_cert_blueprint>();
    comp->algorithms() = {tls_consts::compress::kBrotli};
    spec.extensions.push_back(comp);

    auto alps = std::make_shared<application_settings_blueprint>();
    alps->supported_protocols() = {"h2"};
    spec.extensions.push_back(alps);

    spec.extensions.push_back(std::make_shared<grease_ech_blueprint>());
    spec.extensions.push_back(std::make_shared<grease_blueprint>());
    spec.extensions.push_back(std::make_shared<padding_blueprint>());
    spec.shuffle_extensions = true;
    return spec;
}

}    // namespace

fingerprint_spec fingerprint_factory::get(const fingerprint_type type)
{
    switch (type)
    {
        case fingerprint_type::kChrome120:
            return build_chrome120_spec();
        case fingerprint_type::kFirefox120:
            return build_firefox120_spec();
        case fingerprint_type::kIOS14:
            return build_ios14_spec();
        case fingerprint_type::kAndroid11OkHttp:
            return build_android11_spec();
        default:
            return build_chrome120_spec();
    }
}

fingerprint_spec fingerprint_factory::get_chrome120() { return build_chrome120_spec(); }

void fingerprint_factory::shuffle_extensions(std::vector<std::shared_ptr<extension_blueprint>>& exts)
{
    std::vector<std::size_t> indices;
    std::vector<std::shared_ptr<extension_blueprint>> shufflable_exts;

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
