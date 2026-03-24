#include <array>
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

extern "C"
{
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
}

#include "tls/core.h"
#include "tls/server_name.h"
#include "reality/handshake/fingerprint_blueprint.h"
#include "reality/handshake/client_hello_builder.h"

namespace reality
{

namespace
{

std::vector<std::uint8_t> fallback_secp256r1_public_key()
{
    return {0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
            0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5};
}

std::vector<std::uint8_t> generate_secp256r1_public_key()
{
    const ::tls::openssl_ptrs::evp_pkey_ctx_ptr pkey_ctx_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (pkey_ctx_ptr == nullptr || EVP_PKEY_keygen_init(pkey_ctx_ptr.get()) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx_ptr.get(), NID_X9_62_prime256v1) <= 0)
    {
        return fallback_secp256r1_public_key();
    }

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pkey_ctx_ptr.get(), &raw_pkey) <= 0 || raw_pkey == nullptr)
    {
        return fallback_secp256r1_public_key();
    }
    const ::tls::openssl_ptrs::evp_pkey_ptr pkey(raw_pkey);

    std::size_t key_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &key_len) != 1 || key_len != 65)
    {
        return fallback_secp256r1_public_key();
    }

    std::vector<std::uint8_t> key_data(key_len);
    std::size_t out_len = 0;
    if (EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, key_data.data(), key_data.size(), &out_len) != 1 ||
        out_len != key_data.size() || key_data[0] != 0x04)
    {
        return fallback_secp256r1_public_key();
    }
    return key_data;
}

bool fill_random_bytes(std::vector<std::uint8_t>& buffer)
{
    if (buffer.empty())
    {
        return true;
    }
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1)
    {
        std::ranges::fill(buffer, 0x00);
        return false;
    }
    return true;
}

std::uint16_t select_grease_ech_payload_len()
{
    static constexpr std::array<std::uint16_t, 4> kPayloadLens = {144, 176, 208, 240};
    std::uint8_t random_idx = 0;
    if (RAND_bytes(&random_idx, 1) != 1)
    {
        random_idx = 0;
    }
    return kPayloadLens[random_idx % kPayloadLens.size()];
}

std::size_t boring_padding_len(const std::size_t unpadded_len)
{
    if (unpadded_len <= 0xff || unpadded_len >= 0x200)
    {
        return 0;
    }

    std::size_t padding_len = 0x200 - unpadded_len;
    if (padding_len >= 5)
    {
        padding_len -= 4;
    }
    else
    {
        padding_len = 1;
    }
    return padding_len;
}

struct extension_build_context
{
    const grease_context& grease_ctx;
    int& grease_ext_count;
    const std::vector<std::uint8_t>& x25519_pubkey;
    const std::vector<std::uint8_t>& x25519_mlkem768_key_share;
    const std::string& hostname;
    std::size_t hello_size;
    std::size_t exts_size;
};

}    // namespace

namespace
{

class message_builder
{
   public:
    static void push_u8(std::vector<std::uint8_t>& buf, std::uint8_t val);
    static void push_u16(std::vector<std::uint8_t>& buf, std::uint16_t val);
    static void push_u24(std::vector<std::uint8_t>& buf, std::uint32_t val);
    static void push_u32(std::vector<std::uint8_t>& buf, std::uint32_t val);
    static void push_bytes(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);
    static void push_vector_u8(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);
    static void push_vector_u16(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data);
};

bool build_grease_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const extension_build_context& ctx)
{
    ext_type = ctx.grease_ctx.get_extension_grease(ctx.grease_ext_count++);
    if (ctx.grease_ext_count == 2)
    {
        ext_buffer.push_back(0x00);
    }
    return true;
}

bool build_sni_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const extension_build_context& ctx)
{
    if (!::tls::valid_sni_hostname(ctx.hostname))
    {
        return false;
    }
    ext_type = ::tls::consts::ext::kSni;
    std::vector<std::uint8_t> server_name_list;
    const auto host_len = ctx.hostname.size();
    message_builder::push_u8(server_name_list, 0x00);
    message_builder::push_u16(server_name_list, static_cast<std::uint16_t>(host_len));
    server_name_list.insert(server_name_list.end(), ctx.hostname.begin(), ctx.hostname.end());
    message_builder::push_vector_u16(ext_buffer, server_name_list);
    return true;
}

bool build_supported_groups_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                std::vector<std::uint8_t>& ext_buffer,
                                std::uint16_t& ext_type,
                                const extension_build_context& ctx)
{
    ext_type = ::tls::consts::ext::kSupportedGroups;
    auto bp = std::static_pointer_cast<supported_groups_blueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto g : bp->groups())
    {
        if (g == ::tls::kGreasePlaceholder)
        {
            g = ctx.grease_ctx.get_grease(1);
        }
        message_builder::push_u16(list_data, g);
    }
    message_builder::push_vector_u16(ext_buffer, list_data);
    return true;
}

bool build_ec_point_formats_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kEcPointFormats;
    auto bp = std::static_pointer_cast<ec_point_formats_blueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->formats());
    return true;
}

bool build_alpn_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kAlpn;
    auto bp = std::static_pointer_cast<alpn_blueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->protocols())
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_status_request_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kStatusRequest;
    message_builder::push_u8(ext_buffer, 0x01);
    message_builder::push_u16(ext_buffer, 0x0000);
    message_builder::push_u16(ext_buffer, 0x0000);
    return true;
}

bool build_signature_algorithms_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kSignatureAlg;
    auto bp = std::static_pointer_cast<signature_algorithms_blueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto a : bp->algorithms())
    {
        message_builder::push_u16(list_data, a);
    }
    message_builder::push_vector_u16(ext_buffer, list_data);
    return true;
}

std::uint16_t resolve_key_share_group(const key_share_blueprint::key_share_entry& key_share, const extension_build_context& ctx)
{
    if (key_share.group == ::tls::kGreasePlaceholder)
    {
        return ctx.grease_ctx.get_grease(1);
    }
    return key_share.group;
}

std::vector<std::uint8_t> resolve_key_share_data(const key_share_blueprint::key_share_entry& key_share, const extension_build_context& ctx)
{
    if (!key_share.data.empty())
    {
        return key_share.data;
    }
    if (key_share.group == ::tls::consts::group::kX25519)
    {
        return ctx.x25519_pubkey;
    }
    if (key_share.group == ::tls::consts::group::kX25519MLKEM768)
    {
        return ctx.x25519_mlkem768_key_share;
    }
    if (key_share.group == ::tls::kGreasePlaceholder)
    {
        return {0x00};
    }
    if (key_share.group == ::tls::consts::group::kSecp256r1)
    {
        return generate_secp256r1_public_key();
    }
    return {};
}

bool build_key_share_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                         std::vector<std::uint8_t>& ext_buffer,
                         std::uint16_t& ext_type,
                         const extension_build_context& ctx)
{
    ext_type = ::tls::consts::ext::kKeyShare;
    auto bp = std::static_pointer_cast<key_share_blueprint>(ext_ptr);
    std::vector<std::uint8_t> share_list;
    for (const auto& ks : bp->key_shares())
    {
        message_builder::push_u16(share_list, resolve_key_share_group(ks, ctx));
        auto key_data = resolve_key_share_data(ks, ctx);
        message_builder::push_vector_u16(share_list, key_data);
    }
    message_builder::push_vector_u16(ext_buffer, share_list);
    return true;
}

bool build_psk_key_exchange_modes_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                      std::vector<std::uint8_t>& ext_buffer,
                                      std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kPskKeyExchangeModes;
    auto bp = std::static_pointer_cast<psk_key_exchange_modes_blueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->modes());
    return true;
}

bool build_supported_versions_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                  std::vector<std::uint8_t>& ext_buffer,
                                  std::uint16_t& ext_type,
                                  const extension_build_context& ctx)
{
    ext_type = ::tls::consts::ext::kSupportedVersions;
    auto bp = std::static_pointer_cast<supported_versions_blueprint>(ext_ptr);
    std::vector<std::uint8_t> ver_list;
    for (auto v : bp->versions())
    {
        if (v == ::tls::kGreasePlaceholder)
        {
            v = ctx.grease_ctx.get_grease(4);
        }
        message_builder::push_u16(ver_list, v);
    }
    message_builder::push_vector_u8(ext_buffer, ver_list);
    return true;
}

bool build_compress_certificate_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kCompressCert;
    auto bp = std::static_pointer_cast<compress_cert_blueprint>(ext_ptr);
    std::vector<std::uint8_t> alg_list;
    for (auto a : bp->algorithms())
    {
        message_builder::push_u16(alg_list, a);
    }
    message_builder::push_vector_u8(ext_buffer, alg_list);
    return true;
}

bool build_application_settings_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kApplicationSettings;
    auto bp = std::static_pointer_cast<application_settings_blueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->supported_protocols())
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_application_settings_new_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                        std::vector<std::uint8_t>& ext_buffer,
                                        std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kApplicationSettingsNew;
    auto bp = std::static_pointer_cast<application_settings_new_blueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->supported_protocols())
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_grease_ech_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kGreaseEch;
    ext_buffer.push_back(0x00);
    message_builder::push_u16(ext_buffer, 0x0001);
    message_builder::push_u16(ext_buffer, 0x0001);

    std::uint8_t config_id = 0;
    if (RAND_bytes(&config_id, 1) != 1)
    {
        return false;
    }
    ext_buffer.push_back(config_id);

    std::vector<std::uint8_t> enc_key(32, 0);
    if (!fill_random_bytes(enc_key))
    {
        return false;
    }
    message_builder::push_vector_u16(ext_buffer, enc_key);

    const std::uint16_t payload_len = select_grease_ech_payload_len();
    std::vector<std::uint8_t> payload(payload_len, 0);
    if (!fill_random_bytes(payload))
    {
        return false;
    }
    message_builder::push_vector_u16(ext_buffer, payload);
    return true;
}

bool build_channel_id_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::uint16_t& ext_type)
{
    auto bp = std::static_pointer_cast<channel_id_blueprint>(ext_ptr);
    ext_type = bp->old_id() ? ::tls::consts::ext::kChannelIdLegacy : ::tls::consts::ext::kChannelId;
    return true;
}

bool build_delegated_credentials_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                     std::vector<std::uint8_t>& ext_buffer,
                                     std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kDelegatedCredentials;
    auto bp = std::static_pointer_cast<delegated_credentials_blueprint>(ext_ptr);
    std::vector<std::uint8_t> alg_list;
    for (auto a : bp->algorithms())
    {
        message_builder::push_u16(alg_list, a);
    }
    message_builder::push_vector_u16(ext_buffer, alg_list);
    return true;
}

bool build_record_size_limit_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kRecordSizeLimit;
    auto bp = std::static_pointer_cast<record_size_limit_blueprint>(ext_ptr);
    message_builder::push_u16(ext_buffer, bp->limit());
    return true;
}

bool build_pre_shared_key_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = ::tls::consts::ext::kPreSharedKey;
    std::vector<std::uint8_t> identity(32);
    if (RAND_bytes(identity.data(), static_cast<int>(identity.size())) != 1)
    {
        return false;
    }
    message_builder::push_u16(ext_buffer, 32 + 2 + 4);
    message_builder::push_vector_u16(ext_buffer, identity);
    message_builder::push_u32(ext_buffer, 0);
    std::vector<std::uint8_t> binder(32);
    if (RAND_bytes(binder.data(), static_cast<int>(binder.size())) != 1)
    {
        return false;
    }
    message_builder::push_u16(ext_buffer, 33);
    message_builder::push_vector_u8(ext_buffer, binder);
    return true;
}

bool build_padding_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const extension_build_context& ctx)
{
    ext_type = ::tls::consts::ext::kPadding;
    const auto current_len = ctx.hello_size + 2 + ctx.exts_size + 4;
    const std::size_t padding_len = boring_padding_len(current_len);
    if (padding_len > 0)
    {
        ext_buffer.resize(padding_len, 0x00);
    }
    return true;
}

bool build_simple_extension(extension_type type, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    switch (type)
    {
        case extension_type::kExtendedMasterSecret:
            ext_type = ::tls::consts::ext::kExtMasterSecret;
            return true;
        case extension_type::kRenegotiationInfo:
            ext_type = ::tls::consts::ext::kRenegotiationInfo;
            message_builder::push_u8(ext_buffer, 0x00);
            return true;
        case extension_type::kSessionTicket:
            ext_type = ::tls::consts::ext::kSessionTicket;
            return true;
        case extension_type::kSct:
            ext_type = ::tls::consts::ext::kSct;
            return true;
        case extension_type::kNpn:
            ext_type = ::tls::consts::ext::kNpn;
            return true;
        default:
            return false;
    }
}

using contextual_extension_builder = bool (*)(const std::shared_ptr<extension_blueprint>&,
                                              std::vector<std::uint8_t>&,
                                              std::uint16_t&,
                                              const extension_build_context&);

bool build_contextual_grease(const std::shared_ptr<extension_blueprint>& ext_ptr,
                             std::vector<std::uint8_t>& ext_buffer,
                             std::uint16_t& ext_type,
                             const extension_build_context& ctx)
{
    static_cast<void>(ext_ptr);
    return build_grease_ext(ext_buffer, ext_type, ctx);
}

bool build_contextual_sni(const std::shared_ptr<extension_blueprint>& ext_ptr,
                          std::vector<std::uint8_t>& ext_buffer,
                          std::uint16_t& ext_type,
                          const extension_build_context& ctx)
{
    static_cast<void>(ext_ptr);
    return build_sni_ext(ext_buffer, ext_type, ctx);
}

bool build_contextual_supported_groups(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                       std::vector<std::uint8_t>& ext_buffer,
                                       std::uint16_t& ext_type,
                                       const extension_build_context& ctx)
{
    return build_supported_groups_ext(ext_ptr, ext_buffer, ext_type, ctx);
}

bool build_contextual_key_share(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                std::vector<std::uint8_t>& ext_buffer,
                                std::uint16_t& ext_type,
                                const extension_build_context& ctx)
{
    return build_key_share_ext(ext_ptr, ext_buffer, ext_type, ctx);
}

bool build_contextual_supported_versions(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                         std::vector<std::uint8_t>& ext_buffer,
                                         std::uint16_t& ext_type,
                                         const extension_build_context& ctx)
{
    return build_supported_versions_ext(ext_ptr, ext_buffer, ext_type, ctx);
}

bool build_contextual_padding(const std::shared_ptr<extension_blueprint>& ext_ptr,
                              std::vector<std::uint8_t>& ext_buffer,
                              std::uint16_t& ext_type,
                              const extension_build_context& ctx)
{
    static_cast<void>(ext_ptr);
    return build_padding_ext(ext_buffer, ext_type, ctx);
}

std::optional<contextual_extension_builder> find_contextual_extension_builder(const extension_type type)
{
    struct builder_entry
    {
        extension_type type;
        contextual_extension_builder fn;
    };

    static constexpr std::array<builder_entry, 6> entries = {{
        {.type = extension_type::kGrease, .fn = build_contextual_grease},
        {.type = extension_type::kSni, .fn = build_contextual_sni},
        {.type = extension_type::kSupportedGroups, .fn = build_contextual_supported_groups},
        {.type = extension_type::kKeyShare, .fn = build_contextual_key_share},
        {.type = extension_type::kSupportedVersions, .fn = build_contextual_supported_versions},
        {.type = extension_type::kPadding, .fn = build_contextual_padding},
    }};

    for (const auto& entry : entries)
    {
        if (entry.type == type)
        {
            return entry.fn;
        }
    }
    return std::nullopt;
}

bool build_extension_with_context(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                  std::vector<std::uint8_t>& ext_buffer,
                                  std::uint16_t& ext_type,
                                  const extension_build_context& ctx)
{
    const auto builder = find_contextual_extension_builder(ext_ptr->type());
    if (!builder.has_value())
    {
        return false;
    }
    return (*builder)(ext_ptr, ext_buffer, ext_type, ctx);
}

bool build_extension_without_blueprint(const extension_type type, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    switch (type)
    {
        case extension_type::kStatusRequest:
            return build_status_request_ext(ext_buffer, ext_type);
        case extension_type::kGreaseECH:
            return build_grease_ech_ext(ext_buffer, ext_type);
        case extension_type::kPreSharedKey:
            return build_pre_shared_key_ext(ext_buffer, ext_type);
        default:
            return false;
    }
}

bool build_extension_from_blueprint_group_a(const extension_type type,
                                            const std::shared_ptr<extension_blueprint>& ext_ptr,
                                            std::vector<std::uint8_t>& ext_buffer,
                                            std::uint16_t& ext_type)
{
    switch (type)
    {
        case extension_type::kECPointFormats:
            return build_ec_point_formats_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kAlpn:
            return build_alpn_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kSignatureAlgorithms:
            return build_signature_algorithms_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kPSKKeyExchangeModes:
            return build_psk_key_exchange_modes_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kCompressCertificate:
            return build_compress_certificate_ext(ext_ptr, ext_buffer, ext_type);
        default:
            return false;
    }
}

bool build_extension_from_blueprint_group_b(const extension_type type,
                                            const std::shared_ptr<extension_blueprint>& ext_ptr,
                                            std::vector<std::uint8_t>& ext_buffer,
                                            std::uint16_t& ext_type)
{
    switch (type)
    {
        case extension_type::kApplicationSettings:
            return build_application_settings_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kApplicationSettingsNew:
            return build_application_settings_new_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kChannelID:
            return build_channel_id_ext(ext_ptr, ext_type);
        case extension_type::kDelegatedCredentials:
            return build_delegated_credentials_ext(ext_ptr, ext_buffer, ext_type);
        case extension_type::kRecordSizeLimit:
            return build_record_size_limit_ext(ext_ptr, ext_buffer, ext_type);
        default:
            return false;
    }
}

bool build_extension_from_blueprint(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    const auto type = ext_ptr->type();
    if (build_extension_from_blueprint_group_a(type, ext_ptr, ext_buffer, ext_type))
    {
        return true;
    }
    return build_extension_from_blueprint_group_b(type, ext_ptr, ext_buffer, ext_type);
}

bool build_extension(const std::shared_ptr<extension_blueprint>& ext_ptr,
                     std::vector<std::uint8_t>& ext_buffer,
                     std::uint16_t& ext_type,
                     const extension_build_context& ctx)
{
    const auto type = ext_ptr->type();
    if (build_simple_extension(type, ext_buffer, ext_type))
    {
        return true;
    }
    if (build_extension_without_blueprint(type, ext_buffer, ext_type))
    {
        return true;
    }
    if (build_extension_with_context(ext_ptr, ext_buffer, ext_type, ctx))
    {
        return true;
    }
    return build_extension_from_blueprint(ext_ptr, ext_buffer, ext_type);
}

}    // namespace

void message_builder::push_u8(std::vector<std::uint8_t>& buf, std::uint8_t val) { buf.push_back(val); }

void message_builder::push_u16(std::vector<std::uint8_t>& buf, std::uint16_t val)
{
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
}

void message_builder::push_u24(std::vector<std::uint8_t>& buf, std::uint32_t val)
{
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
}

void message_builder::push_u32(std::vector<std::uint8_t>& buf, std::uint32_t val)
{
    buf.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
}

void message_builder::push_bytes(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    buf.insert(buf.end(), data.begin(), data.end());
}

void message_builder::push_vector_u8(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    constexpr std::size_t kMaxVectorLen = 255;
    const auto vector_len = std::min(data.size(), kMaxVectorLen);
    push_u8(buf, static_cast<std::uint8_t>(vector_len));
    buf.insert(buf.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(vector_len));
}

void message_builder::push_vector_u16(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    constexpr std::size_t kMaxVectorLen = 65535;
    const auto vector_len = std::min(data.size(), kMaxVectorLen);
    push_u16(buf, static_cast<std::uint16_t>(vector_len));
    buf.insert(buf.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(vector_len));
}

std::vector<std::uint8_t> client_hello_builder::build(const fingerprint_template& spec,
                                                      const std::vector<std::uint8_t>& session_id,
                                                      const std::vector<std::uint8_t>& random,
                                                      const std::vector<std::uint8_t>& x25519_pubkey,
                                                      const std::vector<std::uint8_t>& x25519_mlkem768_key_share,
                                                      const std::string& hostname)
{
    const bool has_hostname = !hostname.empty();
    if (has_hostname && !::tls::valid_sni_hostname(hostname))
    {
        return {};
    }

    const auto instance = instantiate_fingerprint_instance(spec);

    std::vector<std::uint8_t> hello;
    const grease_context grease_ctx;
    int grease_ext_count = 0;

    message_builder::push_u8(hello, 0x01);
    message_builder::push_u24(hello, 0);
    message_builder::push_u16(hello, instance.client_version);
    message_builder::push_bytes(hello, random);
    message_builder::push_vector_u8(hello, session_id);

    std::vector<std::uint8_t> ciphers_buf;
    for (auto cs : instance.cipher_suites)
    {
        if (cs == ::tls::kGreasePlaceholder)
        {
            cs = grease_ctx.get_grease(0);
        }
        message_builder::push_u16(ciphers_buf, cs);
    }
    message_builder::push_vector_u16(hello, ciphers_buf);
    message_builder::push_vector_u8(hello, instance.compression_methods);

    std::vector<std::uint8_t> exts;

    for (const auto& ext_ptr : instance.extensions)
    {
        if (ext_ptr->type() == extension_type::kSni && !has_hostname)
        {
            continue;
        }

        std::vector<std::uint8_t> ext_buffer;
        std::uint16_t ext_type = 0;
        const extension_build_context ctx{
            .grease_ctx = grease_ctx,
            .grease_ext_count = grease_ext_count,
            .x25519_pubkey = x25519_pubkey,
            .x25519_mlkem768_key_share = x25519_mlkem768_key_share,
            .hostname = hostname,
            .hello_size = hello.size(),
            .exts_size = exts.size(),
        };
        if (!build_extension(ext_ptr, ext_buffer, ext_type, ctx))
        {
            if (ext_ptr->type() == extension_type::kSni)
            {
                return {};
            }
            continue;
        }

        message_builder::push_u16(exts, ext_type);
        message_builder::push_vector_u16(exts, ext_buffer);
    }

    message_builder::push_vector_u16(hello, exts);

    const auto total_len = static_cast<std::uint32_t>(hello.size() - 4);
    hello[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xFF);
    hello[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    hello[3] = static_cast<std::uint8_t>(total_len & 0xFF);

    return hello;
}

}    // namespace reality
