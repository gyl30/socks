#include <string>
#include <vector>
#include <memory>
#include <utility>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "reality_core.h"
#include "reality_messages.h"
#include "reality_fingerprint.h"

namespace reality
{

namespace
{

struct ExtensionBuildContext
{
    const GreaseContext& grease_ctx;
    int& grease_ext_count;
    const std::vector<std::uint8_t>& x25519_pubkey;
    const std::string& hostname;
    std::size_t hello_size;
    std::size_t exts_size;
};

bool build_grease_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const ExtensionBuildContext& ctx)
{
    ext_type = ctx.grease_ctx.get_extension_grease(ctx.grease_ext_count++);
    if (ctx.grease_ext_count == 2)
    {
        ext_buffer.push_back(0x00);
    }
    return true;
}

bool build_sni_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const ExtensionBuildContext& ctx)
{
    ext_type = tls_consts::ext::SNI;
    std::vector<std::uint8_t> server_name_list;
    message_builder::push_u8(server_name_list, 0x00);
    message_builder::push_u16(server_name_list, static_cast<std::uint16_t>(ctx.hostname.size()));
    message_builder::push_string(server_name_list, ctx.hostname);
    message_builder::push_vector_u16(ext_buffer, server_name_list);
    return true;
}

bool build_supported_groups_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                std::vector<std::uint8_t>& ext_buffer,
                                std::uint16_t& ext_type,
                                const ExtensionBuildContext& ctx)
{
    ext_type = tls_consts::ext::SUPPORTED_GROUPS;
    auto bp = std::static_pointer_cast<SupportedGroupsBlueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto g : bp->groups)
    {
        if (g == GREASE_PLACEHOLDER)
        {
            g = ctx.grease_ctx.get_grease(1);
        }
        message_builder::push_u16(list_data, g);
    }
    message_builder::push_vector_u16(ext_buffer, list_data);
    return true;
}

bool build_ec_point_formats_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::EC_POINT_FORMATS;
    auto bp = std::static_pointer_cast<ECPointFormatsBlueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->formats);
    return true;
}

bool build_alpn_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::ALPN;
    auto bp = std::static_pointer_cast<ALPNBlueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->protocols)
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_status_request_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::STATUS_REQUEST;
    message_builder::push_u8(ext_buffer, 0x01);
    message_builder::push_u16(ext_buffer, 0x0000);
    message_builder::push_u16(ext_buffer, 0x0000);
    return true;
}

bool build_signature_algorithms_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::SIGNATURE_ALG;
    auto bp = std::static_pointer_cast<SignatureAlgorithmsBlueprint>(ext_ptr);
    std::vector<std::uint8_t> list_data;
    for (auto a : bp->algorithms)
    {
        message_builder::push_u16(list_data, a);
    }
    message_builder::push_vector_u16(ext_buffer, list_data);
    return true;
}

bool build_key_share_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                         std::vector<std::uint8_t>& ext_buffer,
                         std::uint16_t& ext_type,
                         const ExtensionBuildContext& ctx)
{
    ext_type = tls_consts::ext::KEY_SHARE;
    auto bp = std::static_pointer_cast<KeyShareBlueprint>(ext_ptr);
    std::vector<std::uint8_t> share_list;
    for (const auto& ks : bp->key_shares)
    {
        std::uint16_t group = ks.group;
        if (group == GREASE_PLACEHOLDER)
        {
            group = ctx.grease_ctx.get_grease(1);
        }
        message_builder::push_u16(share_list, group);

        std::vector<std::uint8_t> key_data = ks.data;
        if (key_data.empty())
        {
            if (ks.group == tls_consts::group::X25519)
            {
                key_data = ctx.x25519_pubkey;
            }
            else if (ks.group == tls_consts::group::X25519_KYBER768_DRAFT00 || ks.group == tls_consts::group::X25519_MLKEM768)
            {
                key_data.resize(32 + 1184);
                (void)RAND_bytes(key_data.data(), static_cast<int>(key_data.size()));
                std::memcpy(key_data.data(), ctx.x25519_pubkey.data(), 32);
            }
            else if (ks.group == GREASE_PLACEHOLDER)
            {
                key_data.push_back(0x00);
            }
            else if (ks.group == tls_consts::group::SECP256R1)
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

bool build_psk_key_exchange_modes_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                      std::vector<std::uint8_t>& ext_buffer,
                                      std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::PSK_KEY_EXCHANGE_MODES;
    auto bp = std::static_pointer_cast<PSKKeyExchangeModesBlueprint>(ext_ptr);
    message_builder::push_vector_u8(ext_buffer, bp->modes);
    return true;
}

bool build_supported_versions_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                  std::vector<std::uint8_t>& ext_buffer,
                                  std::uint16_t& ext_type,
                                  const ExtensionBuildContext& ctx)
{
    ext_type = tls_consts::ext::SUPPORTED_VERSIONS;
    auto bp = std::static_pointer_cast<SupportedVersionsBlueprint>(ext_ptr);
    std::vector<std::uint8_t> ver_list;
    for (auto v : bp->versions)
    {
        if (v == GREASE_PLACEHOLDER)
        {
            v = ctx.grease_ctx.get_grease(4);
        }
        message_builder::push_u16(ver_list, v);
    }
    message_builder::push_vector_u8(ext_buffer, ver_list);
    return true;
}

bool build_compress_certificate_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::COMPRESS_CERT;
    auto bp = std::static_pointer_cast<CompressCertBlueprint>(ext_ptr);
    std::vector<std::uint8_t> alg_list;
    for (auto a : bp->algorithms)
    {
        message_builder::push_u16(alg_list, a);
    }
    message_builder::push_vector_u8(ext_buffer, alg_list);
    return true;
}

bool build_application_settings_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                    std::vector<std::uint8_t>& ext_buffer,
                                    std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::APPLICATION_SETTINGS;
    auto bp = std::static_pointer_cast<ApplicationSettingsBlueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->supported_protocols)
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_application_settings_new_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                        std::vector<std::uint8_t>& ext_buffer,
                                        std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::APPLICATION_SETTINGS_NEW;
    auto bp = std::static_pointer_cast<ApplicationSettingsNewBlueprint>(ext_ptr);
    std::vector<std::uint8_t> proto_list;
    for (const auto& p : bp->supported_protocols)
    {
        message_builder::push_vector_u8(proto_list, std::vector<std::uint8_t>(p.begin(), p.end()));
    }
    message_builder::push_vector_u16(ext_buffer, proto_list);
    return true;
}

bool build_grease_ech_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::GREASE_ECH;
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

bool build_channel_id_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr, std::uint16_t& ext_type)
{
    auto bp = std::static_pointer_cast<ChannelIDBlueprint>(ext_ptr);
    ext_type = bp->old_id ? tls_consts::ext::CHANNEL_ID_LEGACY : tls_consts::ext::CHANNEL_ID;
    return true;
}

bool build_delegated_credentials_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                                     std::vector<std::uint8_t>& ext_buffer,
                                     std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::DELEGATED_CREDENTIALS;
    auto bp = std::static_pointer_cast<DelegatedCredentialsBlueprint>(ext_ptr);
    std::vector<std::uint8_t> alg_list;
    for (auto a : bp->algorithms)
    {
        message_builder::push_u16(alg_list, a);
    }
    message_builder::push_vector_u16(ext_buffer, alg_list);
    return true;
}

bool build_record_size_limit_ext(const std::shared_ptr<ExtensionBlueprint>& ext_ptr, std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::RECORD_SIZE_LIMIT;
    auto bp = std::static_pointer_cast<RecordSizeLimitBlueprint>(ext_ptr);
    message_builder::push_u16(ext_buffer, bp->limit);
    return true;
}

bool build_pre_shared_key_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type)
{
    ext_type = tls_consts::ext::PRE_SHARED_KEY;
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

bool build_padding_ext(std::vector<std::uint8_t>& ext_buffer, std::uint16_t& ext_type, const ExtensionBuildContext& ctx)
{
    ext_type = tls_consts::ext::PADDING;
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

bool build_extension(const std::shared_ptr<ExtensionBlueprint>& ext_ptr,
                     std::vector<std::uint8_t>& ext_buffer,
                     std::uint16_t& ext_type,
                     const ExtensionBuildContext& ctx)
{
    switch (ext_ptr->type())
    {
        case ExtensionType::GREASE:
            return build_grease_ext(ext_buffer, ext_type, ctx);
        case ExtensionType::SNI:
            return build_sni_ext(ext_buffer, ext_type, ctx);
        case ExtensionType::ExtendedMasterSecret:
            ext_type = tls_consts::ext::EXT_MASTER_SECRET;
            return true;
        case ExtensionType::RenegotiationInfo:
            ext_type = tls_consts::ext::RENEGOTIATION_INFO;
            message_builder::push_u8(ext_buffer, 0x00);
            return true;
        case ExtensionType::SupportedGroups:
            return build_supported_groups_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case ExtensionType::ECPointFormats:
            return build_ec_point_formats_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::SessionTicket:
            ext_type = tls_consts::ext::SESSION_TICKET;
            return true;
        case ExtensionType::ALPN:
            return build_alpn_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::StatusRequest:
            return build_status_request_ext(ext_buffer, ext_type);
        case ExtensionType::SignatureAlgorithms:
            return build_signature_algorithms_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::SCT:
            ext_type = tls_consts::ext::SCT;
            return true;
        case ExtensionType::KeyShare:
            return build_key_share_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case ExtensionType::PSKKeyExchangeModes:
            return build_psk_key_exchange_modes_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::SupportedVersions:
            return build_supported_versions_ext(ext_ptr, ext_buffer, ext_type, ctx);
        case ExtensionType::CompressCertificate:
            return build_compress_certificate_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::ApplicationSettings:
            return build_application_settings_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::ApplicationSettingsNew:
            return build_application_settings_new_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::GreaseECH:
            return build_grease_ech_ext(ext_buffer, ext_type);
        case ExtensionType::NPN:
            ext_type = tls_consts::ext::NPN;
            return true;
        case ExtensionType::ChannelID:
            return build_channel_id_ext(ext_ptr, ext_type);
        case ExtensionType::DelegatedCredentials:
            return build_delegated_credentials_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::RecordSizeLimit:
            return build_record_size_limit_ext(ext_ptr, ext_buffer, ext_type);
        case ExtensionType::PreSharedKey:
            return build_pre_shared_key_ext(ext_buffer, ext_type);
        case ExtensionType::Padding:
            return build_padding_ext(ext_buffer, ext_type, ctx);
        default:
            return false;
    }
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

std::vector<std::uint8_t> ClientHelloBuilder::build(const FingerprintSpec& spec,
                                                    const std::vector<std::uint8_t>& session_id,
                                                    const std::vector<std::uint8_t>& random,
                                                    const std::vector<std::uint8_t>& x25519_pubkey,
                                                    const std::string& hostname)
{
    std::vector<std::uint8_t> hello;
    const GreaseContext grease_ctx;
    int grease_ext_count = 0;

    message_builder::push_u8(hello, 0x01);
    message_builder::push_u24(hello, 0);
    message_builder::push_u16(hello, spec.client_version);
    message_builder::push_bytes(hello, random);
    message_builder::push_vector_u8(hello, session_id);

    std::vector<std::uint8_t> ciphers_buf;
    for (auto cs : spec.cipher_suites)
    {
        if (cs == GREASE_PLACEHOLDER)
        {
            cs = grease_ctx.get_grease(0);
        }
        message_builder::push_u16(ciphers_buf, cs);
    }
    message_builder::push_vector_u16(hello, ciphers_buf);
    message_builder::push_vector_u8(hello, spec.compression_methods);

    FingerprintSpec spec_copy = spec;
    if (spec_copy.shuffle_extensions)
    {
        FingerprintFactory::shuffle_extensions(spec_copy.extensions);
    }

    std::vector<std::uint8_t> exts;

    for (const auto& ext_ptr : spec_copy.extensions)
    {
        std::vector<std::uint8_t> ext_buffer;
        std::uint16_t ext_type = 0;
        const ExtensionBuildContext ctx{
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
    header.push_back(static_cast<std::uint8_t>((tls_consts::VER_1_2 >> 8) & 0xFF));
    header.push_back(static_cast<std::uint8_t>(tls_consts::VER_1_2 & 0xFF));
    message_builder::push_u16(header, length);
    return header;
}

std::vector<std::uint8_t> construct_server_hello(const std::vector<std::uint8_t>& server_random,
                                                 const std::vector<std::uint8_t>& session_id,
                                                 std::uint16_t cipher_suite,
                                                 const std::vector<std::uint8_t>& server_public_key)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, tls_consts::VER_1_2);
    message_builder::push_bytes(hello, server_random);
    hello.push_back(static_cast<std::uint8_t>(session_id.size()));
    message_builder::push_bytes(hello, session_id);
    message_builder::push_u16(hello, cipher_suite);
    hello.push_back(0x00);

    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::SUPPORTED_VERSIONS);
    message_builder::push_u16(extensions, 2);
    message_builder::push_u16(extensions, tls_consts::VER_1_3);

    message_builder::push_u16(extensions, tls_consts::ext::KEY_SHARE);
    const auto ext_len = static_cast<std::uint16_t>(2 + 2 + server_public_key.size());
    message_builder::push_u16(extensions, ext_len);
    message_builder::push_u16(extensions, tls_consts::group::X25519);
    message_builder::push_u16(extensions, static_cast<std::uint16_t>(server_public_key.size()));
    message_builder::push_bytes(extensions, server_public_key);

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
        message_builder::push_u16(extensions, tls_consts::ext::ALPN);
        std::vector<std::uint8_t> proto;
        message_builder::push_vector_u8(proto, std::vector<std::uint8_t>(alpn.begin(), alpn.end()));
        std::vector<std::uint8_t> ext;
        message_builder::push_vector_u16(ext, proto);
        message_builder::push_u16(extensions, static_cast<std::uint16_t>(ext.size()));
        message_builder::push_bytes(extensions, ext);
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

bool is_supported_certificate_verify_scheme(std::uint16_t scheme) { return scheme == 0x0807; }

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

std::vector<std::uint8_t> extract_server_public_key(const std::vector<std::uint8_t>& server_hello)
{
    std::uint32_t pos = 0;
    if (server_hello.size() < 4)
    {
        return {};
    }

    if (server_hello[0] == 0x16)
    {
        pos += 5;
    }

    if (pos + 4 > server_hello.size())
    {
        return {};
    }

    if (server_hello[pos] != 0x02)
    {
        return {};
    }

    pos += 4 + 2 + 32;
    if (pos >= server_hello.size())
    {
        return {};
    }

    const std::uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;

    pos += 3;

    if (pos + 2 > server_hello.size())
    {
        return {};
    }
    const auto ext_len = static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    pos += 2;

    const std::size_t end = pos + ext_len;
    while (pos + 4 <= end)
    {
        const auto type = static_cast<std::uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
        const auto elen = static_cast<std::uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
        pos += 4;
        if (type == tls_consts::ext::KEY_SHARE && elen >= 4)
        {
            if (pos + 4 > end)
            {
                break;
            }
            const auto len = static_cast<std::uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
            if (len == 32)
            {
                return {server_hello.begin() + pos + 4, server_hello.begin() + pos + 4 + 32};
            }
        }
        pos += elen;
    }
    return {};
}

std::optional<std::string> extract_alpn_from_encrypted_extensions(const std::vector<std::uint8_t>& ee_msg)
{
    if (ee_msg.size() < 6 || ee_msg[0] != 0x08)
    {
        return std::nullopt;
    }

    std::uint32_t pos = 4;
    const std::uint16_t total_ext_len = (ee_msg[pos] << 8) | ee_msg[pos + 1];
    pos += 2;

    const std::size_t end = pos + total_ext_len;
    if (end > ee_msg.size())
    {
        return std::nullopt;
    }

    while (pos + 4 <= end)
    {
        const std::uint16_t type = (ee_msg[pos] << 8) | ee_msg[pos + 1];
        const std::uint16_t len = (ee_msg[pos + 2] << 8) | ee_msg[pos + 3];
        pos += 4;

        if (pos + len > end)
        {
            break;
        }

        if (type == tls_consts::ext::ALPN)
        {
            if (len < 3)
            {
                break;
            }

            const std::uint16_t list_len = (ee_msg[pos] << 8) | ee_msg[pos + 1];
            if (list_len > 0 && pos + 2 + 1 <= end)
            {
                const std::uint8_t proto_len = ee_msg[pos + 2];
                if (pos + 3 + proto_len <= end)
                {
                    return std::string(reinterpret_cast<const char*>(&ee_msg[pos + 3]), proto_len);
                }
            }
        }
        pos += len;
    }
    return std::nullopt;
}

}    // namespace reality