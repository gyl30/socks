#ifndef REALITY_MESSAGES_H
#define REALITY_MESSAGES_H

#include <algorithm>
#include <vector>
#include <string>
#include <cstdint>
#include <random>
#include <iterator>

#include "crypto_util.h"
#include "reality_core.h"
#include "reality_fingerprint.h"

namespace reality
{
class message_builder
{
   public:
    static void push_u8(std::vector<uint8_t> &buf, uint8_t val) { buf.push_back(val); }

    static void push_u16(std::vector<uint8_t> &buf, uint16_t val)
    {
        buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    static void push_u24(std::vector<uint8_t> &buf, uint32_t val)
    {
        buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    static void push_u32(std::vector<uint8_t> &buf, uint32_t val)
    {
        buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(val & 0xFF));
    }

    static void push_bytes(std::vector<uint8_t> &buf, const std::vector<uint8_t> &data) { buf.insert(buf.end(), data.begin(), data.end()); }

    static void push_bytes(std::vector<uint8_t> &buf, const uint8_t *data, size_t len) { buf.insert(buf.end(), data, data + len); }

    static void push_string(std::vector<uint8_t> &buf, const std::string &str) { buf.insert(buf.end(), str.begin(), str.end()); }

    static void push_vector_u8(std::vector<uint8_t> &buf, const std::vector<uint8_t> &data)
    {
        push_u8(buf, static_cast<uint8_t>(data.size()));
        push_bytes(buf, data);
    }

    static void push_vector_u16(std::vector<uint8_t> &buf, const std::vector<uint8_t> &data)
    {
        push_u16(buf, static_cast<uint16_t>(data.size()));
        push_bytes(buf, data);
    }
};

class ClientHelloBuilder
{
   public:
    static std::vector<uint8_t> build(FingerprintSpec spec,
                                      const std::vector<uint8_t> &session_id,
                                      const std::vector<uint8_t> &random,
                                      const std::vector<uint8_t> &x25519_pubkey,
                                      const std::string &hostname)
    {
        std::vector<uint8_t> hello;
        GreaseContext grease_ctx;
        int grease_ext_count = 0;

        message_builder::push_u8(hello, 0x01);
        message_builder::push_u24(hello, 0);
        message_builder::push_u16(hello, spec.client_version);
        message_builder::push_bytes(hello, random);
        message_builder::push_vector_u8(hello, session_id);

        std::vector<uint8_t> ciphers_buf;
        for (auto cs : spec.cipher_suites)
        {
            if (cs == GREASE_PLACEHOLDER)
                cs = grease_ctx.get_grease(0);
            message_builder::push_u16(ciphers_buf, cs);
        }
        message_builder::push_vector_u16(hello, ciphers_buf);
        message_builder::push_vector_u8(hello, spec.compression_methods);

        if (spec.shuffle_extensions)
        {
            FingerprintFactory::shuffle_extensions(spec.extensions);
        }

        std::vector<uint8_t> exts_buf;

        for (const auto &ext_ptr : spec.extensions)
        {
            std::vector<uint8_t> ext_data;
            uint16_t ext_type = 0;

            switch (ext_ptr->type())
            {
                case ExtensionType::GREASE:
                {
                    ext_type = grease_ctx.get_extension_grease(grease_ext_count++);
                    if (grease_ext_count == 2)
                        ext_data.push_back(0x00);
                    break;
                }
                case ExtensionType::SNI:
                {
                    ext_type = tls_consts::ext::SNI;
                    std::vector<uint8_t> server_name_list;
                    message_builder::push_u8(server_name_list, 0x00);
                    message_builder::push_u16(server_name_list, static_cast<uint16_t>(hostname.size()));
                    message_builder::push_string(server_name_list, hostname);
                    message_builder::push_vector_u16(ext_data, server_name_list);
                    break;
                }
                case ExtensionType::ExtendedMasterSecret:
                {
                    ext_type = tls_consts::ext::EXT_MASTER_SECRET;
                    break;
                }
                case ExtensionType::RenegotiationInfo:
                {
                    ext_type = tls_consts::ext::RENEGOTIATION_INFO;
                    message_builder::push_u8(ext_data, 0x00);
                    break;
                }
                case ExtensionType::SupportedGroups:
                {
                    ext_type = tls_consts::ext::SUPPORTED_GROUPS;
                    auto bp = std::static_pointer_cast<SupportedGroupsBlueprint>(ext_ptr);
                    std::vector<uint8_t> list_buf;
                    for (auto g : bp->groups)
                    {
                        if (g == GREASE_PLACEHOLDER)
                            g = grease_ctx.get_grease(1);
                        message_builder::push_u16(list_buf, g);
                    }
                    message_builder::push_vector_u16(ext_data, list_buf);
                    break;
                }
                case ExtensionType::ECPointFormats:
                {
                    ext_type = tls_consts::ext::EC_POINT_FORMATS;
                    auto bp = std::static_pointer_cast<ECPointFormatsBlueprint>(ext_ptr);
                    message_builder::push_vector_u8(ext_data, bp->formats);
                    break;
                }
                case ExtensionType::SessionTicket:
                {
                    ext_type = tls_consts::ext::SESSION_TICKET;
                    break;
                }
                case ExtensionType::ALPN:
                {
                    ext_type = tls_consts::ext::ALPN;
                    auto bp = std::static_pointer_cast<ALPNBlueprint>(ext_ptr);
                    std::vector<uint8_t> proto_list;
                    for (const auto &p : bp->protocols)
                    {
                        message_builder::push_vector_u8(proto_list, std::vector<uint8_t>(p.begin(), p.end()));
                    }
                    message_builder::push_vector_u16(ext_data, proto_list);
                    break;
                }
                case ExtensionType::StatusRequest:
                {
                    ext_type = tls_consts::ext::STATUS_REQUEST;
                    message_builder::push_u8(ext_data, 0x01);
                    message_builder::push_u16(ext_data, 0x0000);
                    message_builder::push_u16(ext_data, 0x0000);
                    break;
                }
                case ExtensionType::SignatureAlgorithms:
                {
                    ext_type = tls_consts::ext::SIGNATURE_ALG;
                    auto bp = std::static_pointer_cast<SignatureAlgorithmsBlueprint>(ext_ptr);
                    std::vector<uint8_t> list_buf;
                    for (auto a : bp->algorithms)
                    {
                        message_builder::push_u16(list_buf, a);
                    }
                    message_builder::push_vector_u16(ext_data, list_buf);
                    break;
                }
                case ExtensionType::SCT:
                {
                    ext_type = tls_consts::ext::SCT;
                    break;
                }
                case ExtensionType::KeyShare:
                {
                    ext_type = tls_consts::ext::KEY_SHARE;
                    auto bp = std::static_pointer_cast<KeyShareBlueprint>(ext_ptr);
                    std::vector<uint8_t> share_list;
                    for (const auto &ks : bp->key_shares)
                    {
                        uint16_t group = ks.group;
                        if (group == GREASE_PLACEHOLDER)
                            group = grease_ctx.get_grease(1);
                        message_builder::push_u16(share_list, group);

                        std::vector<uint8_t> key_data = ks.data;
                        if (key_data.empty())
                        {
                            if (ks.group == tls_consts::group::X25519)
                            {
                                key_data = x25519_pubkey;
                            }
                            else if (ks.group == tls_consts::group::X25519_KYBER768_DRAFT00 || ks.group == tls_consts::group::X25519_MLKEM768)
                            {
                                key_data.resize(32 + 1184);
                                RAND_bytes(key_data.data(), key_data.size());

                                std::memcpy(key_data.data(), x25519_pubkey.data(), 32);
                            }
                            else if (ks.group == GREASE_PLACEHOLDER)
                            {
                                key_data.push_back(0x00);
                            }
                            else if (ks.group == tls_consts::group::SECP256R1)
                            {
                                key_data.resize(65);
                                RAND_bytes(key_data.data(), 65);
                            }
                        }
                        message_builder::push_vector_u16(share_list, key_data);
                    }
                    message_builder::push_vector_u16(ext_data, share_list);
                    break;
                }
                case ExtensionType::PSKKeyExchangeModes:
                {
                    ext_type = tls_consts::ext::PSK_KEY_EXCHANGE_MODES;
                    auto bp = std::static_pointer_cast<PSKKeyExchangeModesBlueprint>(ext_ptr);
                    message_builder::push_vector_u8(ext_data, bp->modes);
                    break;
                }
                case ExtensionType::SupportedVersions:
                {
                    ext_type = tls_consts::ext::SUPPORTED_VERSIONS;
                    auto bp = std::static_pointer_cast<SupportedVersionsBlueprint>(ext_ptr);
                    std::vector<uint8_t> ver_list;
                    for (auto v : bp->versions)
                    {
                        if (v == GREASE_PLACEHOLDER)
                            v = grease_ctx.get_grease(4);
                        message_builder::push_u16(ver_list, v);
                    }
                    message_builder::push_vector_u8(ext_data, ver_list);
                    break;
                }
                case ExtensionType::CompressCertificate:
                {
                    ext_type = tls_consts::ext::COMPRESS_CERT;
                    auto bp = std::static_pointer_cast<CompressCertBlueprint>(ext_ptr);
                    std::vector<uint8_t> alg_list;
                    for (auto a : bp->algorithms)
                    {
                        message_builder::push_u16(alg_list, a);
                    }
                    message_builder::push_vector_u8(ext_data, alg_list);
                    break;
                }
                case ExtensionType::ApplicationSettings:
                {
                    ext_type = tls_consts::ext::APPLICATION_SETTINGS;
                    auto bp = std::static_pointer_cast<ApplicationSettingsBlueprint>(ext_ptr);
                    std::vector<uint8_t> proto_list;
                    for (const auto &p : bp->supported_protocols)
                    {
                        message_builder::push_vector_u8(proto_list, std::vector<uint8_t>(p.begin(), p.end()));
                    }
                    message_builder::push_vector_u16(ext_data, proto_list);
                    break;
                }
                case ExtensionType::GreaseECH:
                {
                    ext_type = tls_consts::ext::GREASE_ECH;
                    uint8_t rnd_byte;
                    RAND_bytes(&rnd_byte, 1);
                    ext_data.resize(rnd_byte % 16);
                    RAND_bytes(ext_data.data(), ext_data.size());
                    break;
                }
                case ExtensionType::NPN:
                {
                    ext_type = tls_consts::ext::NPN;
                    break;
                }
                case ExtensionType::ChannelID:
                {
                    auto bp = std::static_pointer_cast<ChannelIDBlueprint>(ext_ptr);
                    ext_type = bp->old_id ? 0x3003 : 0x3003;

                    break;
                }
                case ExtensionType::DelegatedCredentials:
                {
                    ext_type = tls_consts::ext::DELEGATED_CREDENTIALS;
                    auto bp = std::static_pointer_cast<DelegatedCredentialsBlueprint>(ext_ptr);
                    std::vector<uint8_t> alg_list;
                    for (auto a : bp->algorithms)
                    {
                        message_builder::push_u16(alg_list, a);
                    }
                    message_builder::push_vector_u16(ext_data, alg_list);
                    break;
                }
                case ExtensionType::RecordSizeLimit:
                {
                    ext_type = tls_consts::ext::RECORD_SIZE_LIMIT;
                    auto bp = std::static_pointer_cast<RecordSizeLimitBlueprint>(ext_ptr);
                    message_builder::push_u16(ext_data, bp->limit);
                    break;
                }
                case ExtensionType::PreSharedKey:
                {
                    ext_type = tls_consts::ext::PRE_SHARED_KEY;

                    std::vector<uint8_t> identity(32);
                    RAND_bytes(identity.data(), 32);
                    message_builder::push_u16(ext_data, 32 + 2 + 4);
                    message_builder::push_vector_u16(ext_data, identity);
                    message_builder::push_u32(ext_data, 0);

                    std::vector<uint8_t> binder(32);
                    RAND_bytes(binder.data(), 32);
                    message_builder::push_u16(ext_data, 33);
                    message_builder::push_vector_u8(ext_data, binder);
                    break;
                }
                case ExtensionType::Padding:
                {
                    ext_type = tls_consts::ext::PADDING;
                    size_t current_len = hello.size() + 2 + exts_buf.size() + 4;
                    size_t padding_len = 0;
                    if (current_len <= 512)
                    {
                        padding_len = 512 - current_len;
                    }
                    else
                    {
                        padding_len = (128 - (current_len % 128)) % 128;
                        if (padding_len == 0)
                            padding_len = 128;
                    }
                    if (padding_len > 0)
                        ext_data.resize(padding_len, 0x00);
                    break;
                }
                default:
                    continue;
            }

            message_builder::push_u16(exts_buf, ext_type);
            message_builder::push_vector_u16(exts_buf, ext_data);
        }

        message_builder::push_vector_u16(hello, exts_buf);

        size_t total_len = hello.size() - 4;
        hello[1] = (total_len >> 16) & 0xFF;
        hello[2] = (total_len >> 8) & 0xFF;
        hello[3] = total_len & 0xFF;

        return hello;
    }
};

inline std::vector<uint8_t> write_record_header(uint8_t record_type, uint16_t length)
{
    std::vector<uint8_t> header;
    header.reserve(5);
    header.push_back(record_type);
    header.push_back(static_cast<uint8_t>((tls_consts::VER_1_2 >> 8) & 0xFF));
    header.push_back(static_cast<uint8_t>(tls_consts::VER_1_2 & 0xFF));
    message_builder::push_u16(header, length);
    return header;
}

inline std::vector<uint8_t> construct_server_hello(const std::vector<uint8_t> &server_random,
                                                   const std::vector<uint8_t> &session_id,
                                                   uint16_t cipher_suite,
                                                   const std::vector<uint8_t> &server_public_key)
{
    std::vector<uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, tls_consts::VER_1_2);
    message_builder::push_bytes(hello, server_random);
    hello.push_back(static_cast<uint8_t>(session_id.size()));
    message_builder::push_bytes(hello, session_id);
    message_builder::push_u16(hello, cipher_suite);
    hello.push_back(0x00);

    std::vector<uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::SUPPORTED_VERSIONS);
    message_builder::push_u16(extensions, 2);
    message_builder::push_u16(extensions, tls_consts::VER_1_3);

    message_builder::push_u16(extensions, tls_consts::ext::KEY_SHARE);
    const auto ext_len = static_cast<uint16_t>(2 + 2 + server_public_key.size());
    message_builder::push_u16(extensions, ext_len);
    message_builder::push_u16(extensions, tls_consts::group::X25519);
    message_builder::push_u16(extensions, static_cast<uint16_t>(server_public_key.size()));
    message_builder::push_bytes(extensions, server_public_key);

    message_builder::push_u16(hello, static_cast<uint16_t>(extensions.size()));
    message_builder::push_bytes(hello, extensions);

    const size_t total_len = hello.size() - 4;
    hello[1] = static_cast<uint8_t>((total_len >> 16) & 0xFF);
    hello[2] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    hello[3] = static_cast<uint8_t>(total_len & 0xFF);
    return hello;
}

inline std::vector<uint8_t> construct_encrypted_extensions() { return {0x08, 0x00, 0x00, 0x02, 0x00, 0x00}; }

inline std::vector<uint8_t> construct_certificate(const std::vector<uint8_t> &cert_der)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x0b);
    std::vector<uint8_t> body;
    body.push_back(0x00);
    std::vector<uint8_t> list;
    message_builder::push_u24(list, static_cast<uint32_t>(cert_der.size()));
    message_builder::push_bytes(list, cert_der);
    message_builder::push_u16(list, 0x0000);
    message_builder::push_u24(body, static_cast<uint32_t>(list.size()));
    message_builder::push_bytes(body, list);
    message_builder::push_u24(msg, static_cast<uint32_t>(body.size()));
    message_builder::push_bytes(msg, body);
    return msg;
}

inline std::vector<uint8_t> construct_certificate_verify(EVP_PKEY *signing_key, const std::vector<uint8_t> &handshake_hash)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x0f);
    std::vector<uint8_t> to_sign(64, 0x20);
    std::string context_str = "TLS 1.3, server CertificateVerify";
    to_sign.insert(to_sign.end(), context_str.begin(), context_str.end());
    to_sign.push_back(0x00);
    to_sign.insert(to_sign.end(), handshake_hash.begin(), handshake_hash.end());

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, signing_key);
    size_t sig_len = 0;
    EVP_DigestSign(mctx, nullptr, &sig_len, to_sign.data(), to_sign.size());
    std::vector<uint8_t> signature(sig_len);
    EVP_DigestSign(mctx, signature.data(), &sig_len, to_sign.data(), to_sign.size());
    EVP_MD_CTX_free(mctx);

    std::vector<uint8_t> body;
    message_builder::push_u16(body, 0x0807);
    message_builder::push_u16(body, static_cast<uint16_t>(signature.size()));
    message_builder::push_bytes(body, signature);
    message_builder::push_u24(msg, static_cast<uint32_t>(body.size()));
    message_builder::push_bytes(msg, body);
    return msg;
}

inline std::vector<uint8_t> construct_finished(const std::vector<uint8_t> &verify_data)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x14);
    message_builder::push_u24(msg, static_cast<uint32_t>(verify_data.size()));
    message_builder::push_bytes(msg, verify_data);
    return msg;
}

inline std::vector<uint8_t> extract_server_public_key(const std::vector<uint8_t> &server_hello)
{
    uint32_t pos = 0;
    if (server_hello.size() < 4)
    {
        return {};
    }
    if (server_hello[0] == 0x16)
    {
        pos += 5;
    }
    if (pos + 38 > server_hello.size() || server_hello[pos] != 0x02)
    {
        return {};
    }

    pos += 38;
    const uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;
    pos += 3;

    if (pos + 2 > server_hello.size())
    {
        return {};
    }
    const auto ext_len = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    pos += 2;

    const size_t end = pos + ext_len;
    while (pos + 4 <= end)
    {
        const auto type = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
        const auto elen = static_cast<uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
        pos += 4;
        if (type == tls_consts::ext::KEY_SHARE && elen >= 4)
        {
            const auto len = static_cast<uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
            if (len == 32)
            {
                return {server_hello.begin() + pos + 4, server_hello.begin() + pos + 4 + 32};
            }
        }
        pos += elen;
    }
    return {};
}
}    // namespace reality

#endif
