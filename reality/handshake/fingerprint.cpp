#include <array>
#include <limits>
#include <memory>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

extern "C"
{
#include <openssl/rand.h>
}

#include "tls/core.h"
#include "reality/handshake/fingerprint.h"
#include "reality/handshake/fingerprint_internal.h"
#include "reality/handshake/fingerprint_patch.h"
#include "reality/handshake/fingerprint_blueprint.h"
#include "reality/handshake/fingerprint_mutation_internal.h"

namespace reality
{

namespace
{

void set_fingerprint_client_version(fingerprint_template& spec, std::uint16_t client_version)
{
    fingerprint_template_mutation::set_client_version(spec, client_version);
}

std::vector<std::uint16_t>& mutable_fingerprint_cipher_suites(fingerprint_template& spec)
{
    return fingerprint_template_mutation::cipher_suites(spec);
}

std::vector<std::shared_ptr<extension_blueprint>>& mutable_fingerprint_extensions(fingerprint_template& spec)
{
    return fingerprint_template_mutation::extensions(spec);
}

void set_fingerprint_shuffle_extensions(fingerprint_template& spec, bool enabled)
{
    fingerprint_template_mutation::set_shuffle_extensions(spec, enabled);
}

key_share_blueprint* find_key_share_blueprint(fingerprint_template& spec)
{
    for (auto& ext_ptr : mutable_fingerprint_extensions(spec))
    {
        auto key_share = std::dynamic_pointer_cast<key_share_blueprint>(ext_ptr);
        if (key_share != nullptr)
        {
            return key_share.get();
        }
    }
    return nullptr;
}

const key_share_blueprint* find_key_share_blueprint(const fingerprint_template& spec)
{
    for (const auto& ext_ptr : fingerprint_extensions(spec))
    {
        auto key_share = std::dynamic_pointer_cast<key_share_blueprint>(ext_ptr);
        if (key_share != nullptr)
        {
            return key_share.get();
        }
    }
    return nullptr;
}

const key_share_blueprint* find_key_share_blueprint(const fingerprint_instance& spec)
{
    for (const auto& ext_ptr : spec.extensions)
    {
        auto key_share = std::dynamic_pointer_cast<key_share_blueprint>(ext_ptr);
        if (key_share != nullptr)
        {
            return key_share.get();
        }
    }
    return nullptr;
}

void shuffle_extensions(std::vector<std::shared_ptr<extension_blueprint>>& exts)
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

constexpr auto kGreaseValues = std::to_array<std::uint16_t>(
    {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa});

}    // namespace

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

fingerprint_template build_firefox120_template()
{
    fingerprint_template spec;
    set_fingerprint_client_version(spec, ::tls::consts::kVer12);
    mutable_fingerprint_cipher_suites(spec) = {
        ::tls::consts::cipher::kTlsAes128GcmSha256,
        ::tls::consts::cipher::kTlsChacha20Poly1305Sha256,
        ::tls::consts::cipher::kTlsAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes256CbcSha,
    };

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sni_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<ems_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {::tls::consts::group::kX25519,
                        ::tls::consts::group::kSecp256r1,
                        ::tls::consts::group::kSecp384r1,
                        ::tls::consts::group::kSecp521r1,
                        256,
                        257};
    mutable_fingerprint_extensions(spec).push_back(groups);
    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    mutable_fingerprint_extensions(spec).push_back(points);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<session_ticket_blueprint>());

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    mutable_fingerprint_extensions(spec).push_back(alpn);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<status_request_blueprint>());

    auto dc = std::make_shared<delegated_credentials_blueprint>();
    dc->algorithms() = {::tls::consts::sig_alg::kEcdsaSecp256r1Sha256,
                        ::tls::consts::sig_alg::kEcdsaSecp384r1Sha384,
                        ::tls::consts::sig_alg::kEcdsaSecp521r1Sha512,
                        ::tls::consts::sig_alg::kEcdsaSha1};
    mutable_fingerprint_extensions(spec).push_back(dc);

    auto key_share = std::make_shared<key_share_blueprint>();
    key_share->key_shares() = {{.group = ::tls::consts::group::kX25519, .data = {}}, {.group = ::tls::consts::group::kSecp256r1, .data = {}}};
    mutable_fingerprint_extensions(spec).push_back(key_share);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {::tls::consts::kVer13, ::tls::consts::kVer12};
    mutable_fingerprint_extensions(spec).push_back(versions);

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {::tls::consts::sig_alg::kEcdsaSecp256r1Sha256,
                         ::tls::consts::sig_alg::kEd25519,
                         ::tls::consts::sig_alg::kEcdsaSecp384r1Sha384,
                         ::tls::consts::sig_alg::kEcdsaSecp521r1Sha512,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha256,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha384,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha512,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha256,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha384,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha512,
                         ::tls::consts::sig_alg::kEcdsaSha1,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha1};
    mutable_fingerprint_extensions(spec).push_back(sig);

    auto psk_mode = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_mode->modes() = {0x01};
    mutable_fingerprint_extensions(spec).push_back(psk_mode);

    auto record_size = std::make_shared<record_size_limit_blueprint>();
    record_size->limit() = 0x4001;
    mutable_fingerprint_extensions(spec).push_back(record_size);

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_ech_blueprint>());
    return spec;
}

fingerprint_template build_ios14_template()
{
    fingerprint_template spec;
    set_fingerprint_client_version(spec, ::tls::consts::kVer12);
    mutable_fingerprint_cipher_suites(spec) = {
        ::tls::kGreasePlaceholder,
        ::tls::consts::cipher::kTlsAes128GcmSha256,
        ::tls::consts::cipher::kTlsAes256GcmSha384,
        ::tls::consts::cipher::kTlsChacha20Poly1305Sha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256CbcSha384,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128CbcSha256,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsRsaWithAes256CbcSha256,
        ::tls::consts::cipher::kTlsRsaWithAes128CbcSha256,
        ::tls::consts::cipher::kTlsRsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheEcdsaWith3desEdeCbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWith3desEdeCbcSha,
        ::tls::consts::cipher::kTlsRsaWith3desEdeCbcSha,
    };

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sni_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<ems_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {::tls::kGreasePlaceholder,
                        ::tls::consts::group::kX25519,
                        ::tls::consts::group::kSecp256r1,
                        ::tls::consts::group::kSecp384r1,
                        ::tls::consts::group::kSecp521r1};
    mutable_fingerprint_extensions(spec).push_back(groups);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    mutable_fingerprint_extensions(spec).push_back(points);

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    mutable_fingerprint_extensions(spec).push_back(alpn);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<status_request_blueprint>());

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {::tls::consts::sig_alg::kEcdsaSecp256r1Sha256,
                         ::tls::consts::sig_alg::kEd25519,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha256,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha256,
                         ::tls::consts::sig_alg::kEcdsaSecp384r1Sha384,
                         ::tls::consts::sig_alg::kEcdsaSha1,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha384,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha384,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha384,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha512,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha512,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha1};
    mutable_fingerprint_extensions(spec).push_back(sig);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sct_blueprint>());

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares() = {{.group = ::tls::kGreasePlaceholder, .data = {}}, {.group = ::tls::consts::group::kX25519, .data = {}}};
    mutable_fingerprint_extensions(spec).push_back(ks);

    auto psk_modes = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_modes->modes() = {0x01};
    mutable_fingerprint_extensions(spec).push_back(psk_modes);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {::tls::kGreasePlaceholder, ::tls::consts::kVer13, ::tls::consts::kVer12, ::tls::consts::kVer11, ::tls::consts::kVer10};
    mutable_fingerprint_extensions(spec).push_back(versions);

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<padding_blueprint>());
    return spec;
}

fingerprint_template build_android11_template()
{
    fingerprint_template spec;
    set_fingerprint_client_version(spec, ::tls::consts::kVer12);
    mutable_fingerprint_cipher_suites(spec) = {
        ::tls::consts::cipher::kTlsAes128GcmSha256,
        ::tls::consts::cipher::kTlsAes256GcmSha384,
        ::tls::consts::cipher::kTlsChacha20Poly1305Sha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes256CbcSha,
    };

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sni_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<ems_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<renegotiation_blueprint>());

    auto groups = std::make_shared<supported_groups_blueprint>();
    groups->groups() = {::tls::consts::group::kX25519, ::tls::consts::group::kSecp256r1, ::tls::consts::group::kSecp384r1};
    mutable_fingerprint_extensions(spec).push_back(groups);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    mutable_fingerprint_extensions(spec).push_back(points);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<status_request_blueprint>());

    auto sig = std::make_shared<signature_algorithms_blueprint>();
    sig->algorithms() = {::tls::consts::sig_alg::kEcdsaSecp256r1Sha256,
                         ::tls::consts::sig_alg::kEd25519,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha256,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha256,
                         ::tls::consts::sig_alg::kEcdsaSecp384r1Sha384,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha384,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha384,
                         ::tls::consts::sig_alg::kRsaPssRsaeSha512,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha512,
                         ::tls::consts::sig_alg::kRsaPkcs1Sha1};
    mutable_fingerprint_extensions(spec).push_back(sig);

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares() = {{.group = ::tls::consts::group::kX25519, .data = {}}};
    mutable_fingerprint_extensions(spec).push_back(ks);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {::tls::consts::kVer13, ::tls::consts::kVer12};
    mutable_fingerprint_extensions(spec).push_back(versions);
    return spec;
}

fingerprint_template build_chrome120_template()
{
    fingerprint_template spec;
    set_fingerprint_client_version(spec, ::tls::consts::kVer12);
    mutable_fingerprint_cipher_suites(spec) = {
        ::tls::kGreasePlaceholder,
        ::tls::consts::cipher::kTlsAes128GcmSha256,
        ::tls::consts::cipher::kTlsAes256GcmSha384,
        ::tls::consts::cipher::kTlsChacha20Poly1305Sha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsEcdheEcdsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithChacha20Poly1305,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsEcdheRsaWithAes256CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes128GcmSha256,
        ::tls::consts::cipher::kTlsRsaWithAes256GcmSha384,
        ::tls::consts::cipher::kTlsRsaWithAes128CbcSha,
        ::tls::consts::cipher::kTlsRsaWithAes256CbcSha,
    };

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sni_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<ems_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<renegotiation_blueprint>());

    auto curves = std::make_shared<supported_groups_blueprint>();
    curves->groups() = {::tls::kGreasePlaceholder, ::tls::consts::group::kX25519, ::tls::consts::group::kSecp256r1, ::tls::consts::group::kSecp384r1};
    mutable_fingerprint_extensions(spec).push_back(curves);

    auto points = std::make_shared<ec_point_formats_blueprint>();
    points->formats() = {0x00};
    mutable_fingerprint_extensions(spec).push_back(points);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<session_ticket_blueprint>());

    auto alpn = std::make_shared<alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    mutable_fingerprint_extensions(spec).push_back(alpn);

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<status_request_blueprint>());

    auto sigs = std::make_shared<signature_algorithms_blueprint>();
    sigs->algorithms() = {::tls::consts::sig_alg::kEcdsaSecp256r1Sha256,
                          ::tls::consts::sig_alg::kEd25519,
                          ::tls::consts::sig_alg::kRsaPssRsaeSha256,
                          ::tls::consts::sig_alg::kRsaPkcs1Sha256,
                          ::tls::consts::sig_alg::kEcdsaSecp384r1Sha384,
                          ::tls::consts::sig_alg::kRsaPssRsaeSha384,
                          ::tls::consts::sig_alg::kRsaPkcs1Sha384,
                          ::tls::consts::sig_alg::kRsaPssRsaeSha512,
                          ::tls::consts::sig_alg::kRsaPkcs1Sha512};
    mutable_fingerprint_extensions(spec).push_back(sigs);
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<sct_blueprint>());

    auto ks = std::make_shared<key_share_blueprint>();
    ks->key_shares().push_back({.group = ::tls::kGreasePlaceholder, .data = {}});
    ks->key_shares().push_back({.group = ::tls::consts::group::kX25519, .data = {}});
    mutable_fingerprint_extensions(spec).push_back(ks);

    auto psk_modes = std::make_shared<psk_key_exchange_modes_blueprint>();
    psk_modes->modes() = {0x01};
    mutable_fingerprint_extensions(spec).push_back(psk_modes);

    auto versions = std::make_shared<supported_versions_blueprint>();
    versions->versions() = {::tls::kGreasePlaceholder, ::tls::consts::kVer13, ::tls::consts::kVer12};
    mutable_fingerprint_extensions(spec).push_back(versions);

    auto comp = std::make_shared<compress_cert_blueprint>();
    comp->algorithms() = {::tls::consts::compress::kBrotli};
    mutable_fingerprint_extensions(spec).push_back(comp);

    auto alps = std::make_shared<application_settings_blueprint>();
    alps->supported_protocols() = {"h2"};
    mutable_fingerprint_extensions(spec).push_back(alps);

    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_ech_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<grease_blueprint>());
    mutable_fingerprint_extensions(spec).push_back(std::make_shared<padding_blueprint>());
    set_fingerprint_shuffle_extensions(spec, true);
    return spec;
}

fingerprint_template build_chrome120_mlkem768_template()
{
    fingerprint_template spec = build_chrome120_template();
    for (auto& ext_ptr : mutable_fingerprint_extensions(spec))
    {
        auto groups = std::dynamic_pointer_cast<supported_groups_blueprint>(ext_ptr);
        if (groups == nullptr)
        {
            continue;
        }

        auto& group_list = groups->groups();
        if (std::ranges::find(group_list, ::tls::consts::group::kX25519MLKEM768) == group_list.end())
        {
            group_list.insert(group_list.begin(), ::tls::consts::group::kX25519MLKEM768);
        }
        break;
    }
    for (auto& ext_ptr : mutable_fingerprint_extensions(spec))
    {
        auto key_share = std::dynamic_pointer_cast<key_share_blueprint>(ext_ptr);
        if (key_share == nullptr)
        {
            continue;
        }

        key_share->key_shares() = {
            {.group = ::tls::kGreasePlaceholder, .data = {}},
            {.group = ::tls::consts::group::kX25519MLKEM768, .data = {}},
        };
        break;
    }
    return spec;
}

}    // namespace

bool fingerprint_has_key_share_group(const fingerprint_template& spec, const std::uint16_t group)
{
    const auto* key_share = find_key_share_blueprint(spec);
    if (key_share == nullptr)
    {
        return false;
    }

    const auto& values = key_share->key_shares();
    return std::ranges::any_of(values, [group](const key_share_blueprint::key_share_entry& entry) { return entry.group == group; });
}

bool fingerprint_has_key_share_group(const fingerprint_instance& spec, const std::uint16_t group)
{
    const auto* key_share = find_key_share_blueprint(spec);
    if (key_share == nullptr)
    {
        return false;
    }

    const auto& values = key_share->key_shares();
    return std::ranges::any_of(values, [group](const key_share_blueprint::key_share_entry& entry) { return entry.group == group; });
}

void fingerprint_append_key_share_group(fingerprint_template& spec, const std::uint16_t group)
{
    auto* key_share = find_key_share_blueprint(spec);
    if (key_share == nullptr || fingerprint_has_key_share_group(spec, group))
    {
        return;
    }

    key_share->key_shares().push_back({.group = group, .data = {}});
}

bool fingerprint_has_cipher_suite(const fingerprint_template& spec, const std::uint16_t cipher_suite)
{
    return std::ranges::find(fingerprint_cipher_suites(spec), cipher_suite) != fingerprint_cipher_suites(spec).end();
}

void fingerprint_append_cipher_suite(fingerprint_template& spec, const std::uint16_t cipher_suite)
{
    if (fingerprint_has_cipher_suite(spec, cipher_suite))
    {
        return;
    }

    mutable_fingerprint_cipher_suites(spec).push_back(cipher_suite);
}

fingerprint_instance instantiate_fingerprint_instance(const fingerprint_template& spec)
{
    fingerprint_instance instance;
    instance.client_version = fingerprint_client_version(spec);
    instance.cipher_suites = fingerprint_cipher_suites(spec);
    instance.compression_methods = fingerprint_compression_methods(spec);
    instance.extensions.reserve(fingerprint_extensions(spec).size());
    for (const auto& ext_ptr : fingerprint_extensions(spec))
    {
        if (ext_ptr == nullptr)
        {
            continue;
        }
        instance.extensions.push_back(ext_ptr->clone());
    }
    if (fingerprint_shuffle_extensions_enabled(spec))
    {
        shuffle_extensions(instance.extensions);
    }
    return instance;
}

fingerprint_template fingerprint_factory::get(const fingerprint_type type)
{
    switch (type)
    {
        case fingerprint_type::kChrome120:
            return build_chrome120_template();
        case fingerprint_type::kChrome120Mlkem768:
            return build_chrome120_mlkem768_template();
        case fingerprint_type::kFirefox120:
            return build_firefox120_template();
        case fingerprint_type::kIOS14:
            return build_ios14_template();
        case fingerprint_type::kAndroid11OkHttp:
            return build_android11_template();
        default:
            return build_chrome120_template();
    }
}

}    // namespace reality
