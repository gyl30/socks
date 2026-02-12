#include <ctime>
#include <array>
#include <algorithm>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_fingerprint.h"

namespace reality
{

namespace
{

struct extension_build_context
{
    const grease_context& grease_ctx;
    int& grease_ext_count;
    const std::vector<std::uint8_t>& x25519_pubkey;
    const std::string& hostname;
    std::size_t hello_size;
    std::size_t exts_size;
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
    ext_type = tls_consts::ext::kSni;
    std::vector<std::uint8_t> server_name_list;
    message_builder::push_u8(server_name_list, 0x00);
    message_builder::push_u16(server_name_list, static_cast<std::uint16_t>(ctx.hostname.size()));
    message_builder::push_string(server_name_list, ctx.hostname);
    message_builder::push_vector_u16(ext_buffer, server_name_list);
    return true;
}

bool build_supported_groups_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                std::vector<std::uint8_t>& ext_buffer,
                                std::uint16_t& ext_type,
                                const extension_build_context& ctx)
{
    ext_type = tls_consts::ext::kSupportedGroups;
    auto bp = std::static_pointer_cast<supported_groups_blueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto g : bp->groups())
    {
        if (g == kGreasePlaceholder)
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
    ext_type = tls_consts::ext::kEcPointFormats;
    auto bp = std::static_pointer_cast<ec_point_formats_blueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->formats());
    return true;
}

bool build_alpn_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::kAlpn;
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
    ext_type = tls_consts::ext::kStatusRequest;
    message_builder::push_u8(ext_buffer, 0x01);
    message_builder::push_u16(ext_buffer, 0x0000);
    message_builder::push_u16(ext_buffer, 0x0000);
    return true;
}

bool build_signature_algorithms_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::kSignatureAlg;
    auto bp = std::static_pointer_cast<signature_algorithms_blueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto a : bp->algorithms())
    {
        message_builder::push_u16(list_data, a);
    }
    message_builder::push_vector_u16(ext_buffer, list_data);
    return true;
}

bool build_key_share_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                         std::vector<std::uint8_t>& ext_buffer,
                         std::uint16_t& ext_type,
                         const extension_build_context& ctx)
{
    ext_type = tls_consts::ext::kKeyShare;
    auto bp = std::static_pointer_cast<key_share_blueprint>(ext_ptr);
    std::vector<std::uint8_t> share_list;
    for (const auto& ks : bp->key_shares())
    {
        std::uint16_t group = ks.group;
        if (group == kGreasePlaceholder)
        {
            group = ctx.grease_ctx.get_grease(1);
        }
        message_builder::push_u16(share_list, group);

        std::vector<std::uint8_t> key_data = ks.data;
        if (key_data.empty())
        {
            if (ks.group == tls_consts::group::kX25519)
            {
                key_data = ctx.x25519_pubkey;
            }
            else if (ks.group == kGreasePlaceholder)
            {
                key_data.push_back(0x00);
            }
            else if (ks.group == tls_consts::group::kSecp256r1)
            {
                key_data.resize(65);
                (void)RAND_bytes(key_data.data(), 65);
            }
        }
        message_builder::push_vector_u16(share_list, key_data);
    }
    message_builder::push_vector_u16(ext_buffer, share_list);
    return true;
}

bool build_psk_key_exchange_modes_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                      std::vector<std::uint8_t>& ext_buffer,
                                      std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::kPskKeyExchangeModes;
    auto bp = std::static_pointer_cast<psk_key_exchange_modes_blueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->modes());
    return true;
}

bool build_supported_versions_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                  std::vector<std::uint8_t>& ext_buffer,
                                  std::uint16_t& ext_type,
                                  const extension_build_context& ctx)
{
    ext_type = tls_consts::ext::kSupportedVersions;
    auto bp = std::static_pointer_cast<supported_versions_blueprint>(ext_ptr);
    std::vector<std::uint8_t> ver_list;
    for (auto v : bp->versions())
    {
        if (v == kGreasePlaceholder)
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
    ext_type = tls_consts::ext::kCompressCert;
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
    ext_type = tls_consts::ext::kApplicationSettings;
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
    ext_type = tls_consts::ext::kApplicationSettingsNew;
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
    ext_type = tls_consts::ext::kGreaseEch;
    ext_buffer.reserve(10);
    ext_buffer.push_back(0x00);
    ext_buffer.push_back(0x0a);
    ext_buffer.push_back(0x0a);
    ext_buffer.push_back(0x0a);
    ext_buffer.push_back(0x0a);
    ext_buffer.push_back(0x00);
    message_builder::push_u16(ext_buffer, 0);
    message_builder::push_u16(ext_buffer, 0);
    return true;
}

bool build_channel_id_ext(const std::shared_ptr<extension_blueprint>& ext_ptr, std::uint16_t& ext_type)
{
    auto bp = std::static_pointer_cast<channel_id_blueprint>(ext_ptr);
    ext_type = bp->old_id() ? tls_consts::ext::kChannelIdLegacy : tls_consts::ext::kChannelId;
    return true;
}

bool build_delegated_credentials_ext(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                     std::vector<std::uint8_t>& ext_buffer,
                                     std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::kDelegatedCredentials;
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
    ext_type = tls_consts::ext::kRecordSizeLimit;
    auto bp = std::static_pointer_cast<record_size_limit_blueprint>(ext_ptr);
    message_builder::push_u16(ext_buffer, bp->limit());
    return true;
}

bool build_pre_shared_key_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::kPreSharedKey;
    std::vector<std::uint8_t> identity(32);
    (void)RAND_bytes(identity.data(), 32);
    message_builder::push_u16(ext_buffer, 32 + 2 + 4);
    message_builder::push_vector_u16(ext_buffer, identity);
    message_builder::push_u32(ext_buffer, 0);
    std::vector<std::uint8_t> binder(32);
    (void)RAND_bytes(binder.data(), 32);
    message_builder::push_u16(ext_buffer, 33);
    message_builder::push_vector_u8(ext_buffer, binder);
    return true;
}

bool build_padding_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const extension_build_context& ctx)
{
    ext_type = tls_consts::ext::kPadding;
    const auto current_len = ctx.hello_size + 2 + ctx.exts_size + 4;
    std::size_t padding_len = 0;
    if (current_len < 512)
    {
        padding_len = 512 - current_len;
    }
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
            ext_type = tls_consts::ext::kExtMasterSecret;
            return true;
        case extension_type::kRenegotiationInfo:
            ext_type = tls_consts::ext::kRenegotiationInfo;
            message_builder::push_u8(ext_buffer, 0x00);
            return true;
        case extension_type::kSessionTicket:
            ext_type = tls_consts::ext::kSessionTicket;
            return true;
        case extension_type::kSct:
            ext_type = tls_consts::ext::kSct;
            return true;
        case extension_type::kNpn:
            ext_type = tls_consts::ext::kNpn;
            return true;
        default:
            return false;
    }
}

bool build_extension_with_context(const std::shared_ptr<extension_blueprint>& ext_ptr,
                                  std::vector<std::uint8_t>& ext_buffer,
                                  std::uint16_t& ext_type,
                                  const extension_build_context& ctx)
{
    switch (ext_ptr->type())
    {
        case extension_type::kGrease:
            return build_grease_ext(ext_buffer, ext_type, ctx);
        case extension_type::kSni:
            return build_sni_ext(ext_buffer, ext_type, ctx);
        case extension_type::kSupportedGroups:
            return build_supported_groups_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case extension_type::kKeyShare:
            return build_key_share_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case extension_type::kSupportedVersions:
            return build_supported_versions_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case extension_type::kPadding:
            return build_padding_ext(ext_buffer, ext_type, ctx);
        default:
            return false;
    }
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

void message_builder::push_bytes(std::vector<std::uint8_t>& buf, const std::uint8_t* data, std::size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

void message_builder::push_string(std::vector<std::uint8_t>& buf, const std::string& str) { buf.insert(buf.end(), str.begin(), str.end()); }

void message_builder::push_vector_u8(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    push_u8(buf, static_cast<std::uint8_t>(data.size()));
    push_bytes(buf, data);
}

void message_builder::push_vector_u16(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    push_u16(buf, static_cast<std::uint16_t>(data.size()));
    push_bytes(buf, data);
}

std::vector<std::uint8_t> client_hello_builder::build(const fingerprint_spec& spec,
                                                      const std::vector<std::uint8_t>& session_id,
                                                      const std::vector<std::uint8_t>& random,
                                                      const std::vector<std::uint8_t>& x25519_pubkey,
                                                      const std::string& hostname)
{
    std::vector<std::uint8_t> hello;
    const grease_context grease_ctx;
    int grease_ext_count = 0;

    message_builder::push_u8(hello, 0x01);
    message_builder::push_u24(hello, 0);
    message_builder::push_u16(hello, spec.client_version);
    message_builder::push_bytes(hello, random);
    message_builder::push_vector_u8(hello, session_id);

    std::vector<std::uint8_t> ciphers_buf;
    for (auto cs : spec.cipher_suites)
    {
        if (cs == kGreasePlaceholder)
        {
            cs = grease_ctx.get_grease(0);
        }
        message_builder::push_u16(ciphers_buf, cs);
    }
    message_builder::push_vector_u16(hello, ciphers_buf);
    message_builder::push_vector_u8(hello, spec.compression_methods);

    fingerprint_spec spec_copy = spec;
    if (spec_copy.shuffle_extensions)
    {
        fingerprint_factory::shuffle_extensions(spec_copy.extensions);
    }

    std::vector<std::uint8_t> exts;

    for (const auto& ext_ptr : spec_copy.extensions)
    {
        std::vector<std::uint8_t> ext_buffer;
        std::uint16_t ext_type = 0;
        const extension_build_context ctx{
            .grease_ctx = grease_ctx,
            .grease_ext_count = grease_ext_count,
            .x25519_pubkey = x25519_pubkey,
            .hostname = hostname,
            .hello_size = hello.size(),
            .exts_size = exts.size(),
        };
        if (!build_extension(ext_ptr, ext_buffer, ext_type, ctx))
        {
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

std::vector<std::uint8_t> write_record_header(std::uint8_t record_type, std::uint16_t length)
{
    std::vector<std::uint8_t> header;
    header.reserve(5);
    header.push_back(record_type);
    header.push_back(static_cast<std::uint8_t>((tls_consts::kVer12 >> 8) & 0xFF));
    header.push_back(static_cast<std::uint8_t>(tls_consts::kVer12 & 0xFF));
    message_builder::push_u16(header, length);
    return header;
}

std::vector<std::uint8_t> construct_server_hello(const std::vector<std::uint8_t>& server_random,
                                                 const std::vector<std::uint8_t>& session_id,
                                                 std::uint16_t cipher_suite,
                                                 std::uint16_t key_share_group,
                                                 const std::vector<std::uint8_t>& key_share_data)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, tls_consts::kVer12);
    message_builder::push_bytes(hello, server_random);
    hello.push_back(static_cast<std::uint8_t>(session_id.size()));
    message_builder::push_bytes(hello, session_id);
    message_builder::push_u16(hello, cipher_suite);
    hello.push_back(0x00);

    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kSupportedVersions);
    message_builder::push_u16(extensions, 2);
    message_builder::push_u16(extensions, tls_consts::kVer13);

    message_builder::push_u16(extensions, tls_consts::ext::kKeyShare);
    const auto ext_len = static_cast<std::uint16_t>(2 + 2 + key_share_data.size());
    message_builder::push_u16(extensions, ext_len);
    message_builder::push_u16(extensions, key_share_group);
    message_builder::push_u16(extensions, static_cast<std::uint16_t>(key_share_data.size()));
    message_builder::push_bytes(extensions, key_share_data);

    message_builder::push_u16(hello, static_cast<std::uint16_t>(extensions.size()));
    message_builder::push_bytes(hello, extensions);

    const std::size_t total_len = hello.size() - 4;
    hello[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xFF);
    hello[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    hello[3] = static_cast<std::uint8_t>(total_len & 0xFF);
    return hello;
}

std::vector<std::uint8_t> construct_encrypted_extensions(const std::string& alpn)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x08);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x00);

    std::vector<std::uint8_t> extensions;
    if (!alpn.empty())
    {
        message_builder::push_u16(extensions, tls_consts::ext::kAlpn);
        std::vector<std::uint8_t> proto;
        message_builder::push_vector_u8(proto, std::vector<std::uint8_t>(alpn.begin(), alpn.end()));
        std::vector<std::uint8_t> ext;
        message_builder::push_vector_u16(ext, proto);
        message_builder::push_u16(extensions, static_cast<std::uint16_t>(ext.size()));
        message_builder::push_bytes(extensions, ext);
    }

    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<std::size_t> dist(10, 100);
    const std::size_t padding_len = dist(gen);
    message_builder::push_u16(extensions, tls_consts::ext::kPadding);
    message_builder::push_u16(extensions, static_cast<std::uint16_t>(padding_len));
    for (std::size_t i = 0; i < padding_len; ++i)
    {
        extensions.push_back(0x00);
    }

    message_builder::push_u16(msg, static_cast<std::uint16_t>(extensions.size()));
    message_builder::push_bytes(msg, extensions);

    const std::size_t total_len = msg.size() - 4;
    msg[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xFF);
    msg[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(total_len & 0xFF);

    return msg;
}

std::vector<std::uint8_t> construct_certificate(const std::vector<std::uint8_t>& cert_der)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x0b);
    std::vector<std::uint8_t> body;
    body.push_back(0x00);
    std::vector<std::uint8_t> list;
    message_builder::push_u24(list, static_cast<std::uint32_t>(cert_der.size()));
    message_builder::push_bytes(list, cert_der);
    message_builder::push_u16(list, 0x0000);
    message_builder::push_u24(body, static_cast<std::uint32_t>(list.size()));
    message_builder::push_bytes(body, list);
    message_builder::push_u24(msg, static_cast<std::uint32_t>(body.size()));
    message_builder::push_bytes(msg, body);
    return msg;
}

std::vector<std::uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<std::uint8_t>& handshake_hash)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x0f);
    std::vector<std::uint8_t> to_sign(64, 0x20);
    const std::string context_str = "TLS 1.3, server CertificateVerify";
    to_sign.insert(to_sign.end(), context_str.begin(), context_str.end());
    to_sign.push_back(0x00);
    to_sign.insert(to_sign.end(), handshake_hash.begin(), handshake_hash.end());

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    (void)EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, signing_key);
    std::size_t sig_len = 0;
    (void)EVP_DigestSign(mctx, nullptr, &sig_len, to_sign.data(), to_sign.size());
    std::vector<std::uint8_t> signature(sig_len);
    (void)EVP_DigestSign(mctx, signature.data(), &sig_len, to_sign.data(), to_sign.size());
    EVP_MD_CTX_free(mctx);

    std::vector<std::uint8_t> body;
    message_builder::push_u16(body, 0x0807);
    message_builder::push_u16(body, static_cast<std::uint16_t>(signature.size()));
    message_builder::push_bytes(body, signature);
    message_builder::push_u24(msg, static_cast<std::uint32_t>(body.size()));
    message_builder::push_bytes(msg, body);
    return msg;
}

std::vector<std::uint8_t> construct_finished(const std::vector<std::uint8_t>& verify_data)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x14);
    message_builder::push_u24(msg, static_cast<std::uint32_t>(verify_data.size()));
    message_builder::push_bytes(msg, verify_data);
    return msg;
}

std::optional<certificate_verify_info> parse_certificate_verify(const std::vector<std::uint8_t>& msg)
{
    if (msg.size() < 4 + 2 + 2)
    {
        return std::nullopt;
    }
    if (msg[0] != 0x0f)
    {
        return std::nullopt;
    }

    const std::uint32_t len =
        (static_cast<std::uint32_t>(msg[1]) << 16) | (static_cast<std::uint32_t>(msg[2]) << 8) | static_cast<std::uint32_t>(msg[3]);
    if (msg.size() < 4 + len)
    {
        return std::nullopt;
    }

    std::size_t pos = 4;
    if (pos + 2 > msg.size())
    {
        return std::nullopt;
    }

    const auto scheme = static_cast<std::uint16_t>((msg[pos] << 8) | msg[pos + 1]);
    pos += 2;

    if (pos + 2 > msg.size())
    {
        return std::nullopt;
    }

    const auto sig_len = static_cast<std::uint16_t>((msg[pos] << 8) | msg[pos + 1]);
    pos += 2;

    if (pos + sig_len > msg.size())
    {
        return std::nullopt;
    }

    certificate_verify_info info;
    info.scheme = scheme;
    const auto start = std::next(msg.begin(), static_cast<std::ptrdiff_t>(pos));
    const auto finish = std::next(start, static_cast<std::ptrdiff_t>(sig_len));
    info.signature.assign(start, finish);
    return info;
}

bool is_supported_certificate_verify_scheme(std::uint16_t scheme)
{
    using reality::tls_consts::sig_alg::kEcdsaSecp256r1Sha256;
    using reality::tls_consts::sig_alg::kEcdsaSecp384r1Sha384;
    using reality::tls_consts::sig_alg::kEcdsaSecp521r1Sha512;
    using reality::tls_consts::sig_alg::kEd25519;
    using reality::tls_consts::sig_alg::kRsaPkcs1Sha256;
    using reality::tls_consts::sig_alg::kRsaPkcs1Sha384;
    using reality::tls_consts::sig_alg::kRsaPkcs1Sha512;
    using reality::tls_consts::sig_alg::kRsaPssRsaeSha256;
    using reality::tls_consts::sig_alg::kRsaPssRsaeSha384;
    using reality::tls_consts::sig_alg::kRsaPssRsaeSha512;

    constexpr std::array<std::uint16_t, 10> supported_schemes = {kEd25519,
                                                                  kEcdsaSecp256r1Sha256,
                                                                  kEcdsaSecp384r1Sha384,
                                                                  kEcdsaSecp521r1Sha512,
                                                                  kRsaPkcs1Sha256,
                                                                  kRsaPkcs1Sha384,
                                                                  kRsaPkcs1Sha512,
                                                                  kRsaPssRsaeSha256,
                                                                  kRsaPssRsaeSha384,
                                                                  kRsaPssRsaeSha512};
    return std::ranges::find(supported_schemes, scheme) != supported_schemes.end();
}

std::optional<std::uint16_t> extract_cipher_suite_from_server_hello(const std::vector<std::uint8_t>& server_hello)
{
    if (server_hello.size() < 4 + 2 + 32 + 1)
    {
        return std::nullopt;
    }

    std::uint32_t pos = 4 + 2 + 32;
    const std::uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;

    if (pos + 2 > server_hello.size())
    {
        return std::nullopt;
    }

    return static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
}

bool locate_server_hello_extensions(const std::vector<std::uint8_t>& server_hello, std::size_t& pos, std::size_t& end)
{
    if (server_hello[pos] != 0x02)
    {
        return false;
    }

    pos += 4 + 2 + 32;
    if (pos >= server_hello.size())
    {
        return false;
    }

    const std::uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;
    pos += 3;

    if (pos + 2 > server_hello.size())
    {
        return false;
    }
    const auto ext_len = static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    pos += 2;

    end = pos + ext_len;
    if (end < pos || end > server_hello.size())
    {
        return false;
    }
    return true;
}

std::optional<server_key_share_info> parse_server_key_share_entry(const std::vector<std::uint8_t>& server_hello, const std::size_t pos, const std::size_t end)
{
    if (pos + 4 > end)
    {
        return std::nullopt;
    }
    const auto group = static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    const auto len = static_cast<std::uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
    const auto data_start = pos + 4;
    if (data_start + len > end)
    {
        return std::nullopt;
    }
    server_key_share_info info;
    info.group = group;
    info.data.assign(server_hello.begin() + static_cast<std::ptrdiff_t>(data_start),
                     server_hello.begin() + static_cast<std::ptrdiff_t>(data_start + len));
    return info;
}

bool skip_server_hello_prefix(const std::vector<std::uint8_t>& server_hello, std::size_t& pos)
{
    if (server_hello.size() < 4)
    {
        return false;
    }
    if (server_hello[0] == 0x16)
    {
        pos += 5;
    }
    return pos + 4 <= server_hello.size();
}

bool parse_extension_header(const std::vector<std::uint8_t>& server_hello,
                            const std::size_t end,
                            std::size_t& pos,
                            std::uint16_t& type,
                            std::uint16_t& ext_len)
{
    if (pos + 4 > end)
    {
        return false;
    }
    type = static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    ext_len = static_cast<std::uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
    pos += 4;
    return true;
}

bool advance_extension_payload(std::size_t& pos, const std::size_t end, const std::uint16_t ext_len)
{
    if (pos + ext_len > end)
    {
        return false;
    }
    pos += ext_len;
    return true;
}

std::optional<server_key_share_info> extract_server_key_share(const std::vector<std::uint8_t>& server_hello)
{
    std::size_t pos = 0;
    if (!skip_server_hello_prefix(server_hello, pos))
    {
        return std::nullopt;
    }

    std::size_t end = 0;
    if (!locate_server_hello_extensions(server_hello, pos, end))
    {
        return std::nullopt;
    }

    while (pos + 4 <= end)
    {
        std::uint16_t type = 0;
        std::uint16_t ext_len = 0;
        if (!parse_extension_header(server_hello, end, pos, type, ext_len))
        {
            break;
        }
        if (type == tls_consts::ext::kKeyShare && ext_len >= 4)
        {
            return parse_server_key_share_entry(server_hello, pos, end);
        }
        if (!advance_extension_payload(pos, end, ext_len))
        {
            break;
        }
    }
    return std::nullopt;
}

struct encrypted_extensions_range
{
    std::size_t pos = 0;
    std::size_t end = 0;
};

std::optional<encrypted_extensions_range> parse_encrypted_extensions_range(const std::vector<std::uint8_t>& ee_msg)
{
    if (ee_msg.size() < 6 || ee_msg[0] != 0x08)
    {
        return std::nullopt;
    }

    const std::size_t ext_len_pos = 4;
    const std::uint16_t total_ext_len = static_cast<std::uint16_t>((ee_msg[ext_len_pos] << 8) | ee_msg[ext_len_pos + 1]);
    const std::size_t ext_start = ext_len_pos + 2;
    const std::size_t ext_end = ext_start + total_ext_len;
    if (ext_end > ee_msg.size())
    {
        return std::nullopt;
    }

    return encrypted_extensions_range{.pos = ext_start, .end = ext_end};
}

bool read_extension_header(const std::vector<std::uint8_t>& msg, std::size_t& pos, const std::size_t end, std::uint16_t& type, std::uint16_t& len)
{
    if (pos + 4 > end)
    {
        return false;
    }
    type = static_cast<std::uint16_t>((msg[pos] << 8) | msg[pos + 1]);
    len = static_cast<std::uint16_t>((msg[pos + 2] << 8) | msg[pos + 3]);
    pos += 4;
    if (pos + len > end)
    {
        return false;
    }
    return true;
}

std::optional<std::string> parse_alpn_extension_body(const std::vector<std::uint8_t>& ee_msg, const std::size_t pos, const std::uint16_t len)
{
    if (len < 3)
    {
        return std::nullopt;
    }

    const std::size_t ext_end = pos + len;
    const std::uint16_t list_len = static_cast<std::uint16_t>((ee_msg[pos] << 8) | ee_msg[pos + 1]);
    if (list_len == 0 || pos + 3 > ext_end)
    {
        return std::nullopt;
    }

    const std::uint8_t proto_len = ee_msg[pos + 2];
    if (pos + 3 + proto_len > ext_end)
    {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(&ee_msg[pos + 3]), proto_len);
}

std::vector<std::uint8_t> extract_server_public_key(const std::vector<std::uint8_t>& server_hello)
{
    const auto info = extract_server_key_share(server_hello);
    if (!info.has_value())
    {
        return {};
    }
    if (info->group == tls_consts::group::kX25519)
    {
        if (info->data.size() == 32)
        {
            return info->data;
        }
        return {};
    }
    return {};
}

std::optional<std::string> extract_alpn_from_encrypted_extensions(const std::vector<std::uint8_t>& ee_msg)
{
    const auto range = parse_encrypted_extensions_range(ee_msg);
    if (!range.has_value())
    {
        return std::nullopt;
    }

    auto pos = range->pos;
    const auto end = range->end;

    while (pos + 4 <= end)
    {
        std::uint16_t type = 0;
        std::uint16_t len = 0;
        if (!read_extension_header(ee_msg, pos, end, type, len))
        {
            break;
        }
        if (type == tls_consts::ext::kAlpn)
        {
            const auto alpn = parse_alpn_extension_body(ee_msg, pos, len);
            if (alpn.has_value())
            {
                return alpn;
            }
        }
        pos += len;
    }
    return std::nullopt;
}

}    // namespace reality
