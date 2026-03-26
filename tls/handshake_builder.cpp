#include <span>
#include <limits>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <optional>
#include <algorithm>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/types.h>
}

#include "tls/core.h"
#include "tls/handshake_builder.h"

namespace tls
{

namespace
{

void push_u16(std::vector<std::uint8_t>& buf, const std::uint16_t val)
{
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xff));
    buf.push_back(static_cast<std::uint8_t>(val & 0xff));
}

void push_u24(std::vector<std::uint8_t>& buf, const std::uint32_t val)
{
    buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xff));
    buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xff));
    buf.push_back(static_cast<std::uint8_t>(val & 0xff));
}

void push_bytes(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data) { buf.insert(buf.end(), data.begin(), data.end()); }

void push_vector_u8(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    buf.push_back(static_cast<std::uint8_t>(data.size()));
    push_bytes(buf, data);
}

void push_vector_u16(std::vector<std::uint8_t>& buf, const std::vector<std::uint8_t>& data)
{
    push_u16(buf, static_cast<std::uint16_t>(data.size()));
    push_bytes(buf, data);
}

}    // namespace

std::vector<std::uint8_t> write_record_header(const std::uint8_t record_type, const std::uint16_t length)
{
    std::vector<std::uint8_t> header;
    header.reserve(5);
    header.push_back(record_type);
    header.push_back(static_cast<std::uint8_t>((::tls::consts::kVer12 >> 8) & 0xff));
    header.push_back(static_cast<std::uint8_t>(::tls::consts::kVer12 & 0xff));
    push_u16(header, length);
    return header;
}

std::vector<std::uint8_t> construct_server_hello(const std::vector<std::uint8_t>& server_random,
                                                 const std::vector<std::uint8_t>& session_id,
                                                 const std::uint16_t cipher_suite,
                                                 const std::uint16_t key_share_group,
                                                 const std::vector<std::uint8_t>& key_share_data,
                                                 const std::span<const std::uint16_t> extension_order)
{
    constexpr std::size_t kMaxSessionIdLen = 255;
    constexpr std::size_t kMaxExtensionsLen = 65535;
    constexpr std::size_t kSupportedVersionsExtLen = 6;
    constexpr std::size_t kKeyShareOverheadLen = 8;
    constexpr std::size_t kMaxKeyShareLen = kMaxExtensionsLen - kSupportedVersionsExtLen - kKeyShareOverheadLen;

    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0x00);
    hello.push_back(0x00);
    hello.push_back(0x00);
    push_u16(hello, ::tls::consts::kVer12);
    push_bytes(hello, server_random);
    const auto sid_len = std::min(session_id.size(), kMaxSessionIdLen);
    hello.push_back(static_cast<std::uint8_t>(sid_len));
    hello.insert(hello.end(), session_id.begin(), session_id.begin() + static_cast<std::ptrdiff_t>(sid_len));
    push_u16(hello, cipher_suite);
    hello.push_back(0x00);

    std::vector<std::uint8_t> supported_versions_ext;
    push_u16(supported_versions_ext, ::tls::consts::ext::kSupportedVersions);
    push_u16(supported_versions_ext, 2);
    push_u16(supported_versions_ext, ::tls::consts::kVer13);

    std::vector<std::uint8_t> key_share_ext;
    push_u16(key_share_ext, ::tls::consts::ext::kKeyShare);
    const auto key_share_len = std::min(key_share_data.size(), kMaxKeyShareLen);
    const auto ext_len = static_cast<std::uint16_t>(2 + 2 + key_share_len);
    push_u16(key_share_ext, ext_len);
    push_u16(key_share_ext, key_share_group);
    push_u16(key_share_ext, static_cast<std::uint16_t>(key_share_len));
    key_share_ext.insert(key_share_ext.end(), key_share_data.begin(), key_share_data.begin() + static_cast<std::ptrdiff_t>(key_share_len));

    std::vector<std::uint8_t> extensions;
    bool emitted_supported_versions = false;
    bool emitted_key_share = false;
    const auto append_extension = [&](const std::uint16_t ext_type)
    {
        if (ext_type == ::tls::consts::ext::kSupportedVersions && !emitted_supported_versions)
        {
            push_bytes(extensions, supported_versions_ext);
            emitted_supported_versions = true;
        }
        else if (ext_type == ::tls::consts::ext::kKeyShare && !emitted_key_share)
        {
            push_bytes(extensions, key_share_ext);
            emitted_key_share = true;
        }
    };

    for (const auto ext_type : extension_order)
    {
        append_extension(ext_type);
    }
    append_extension(::tls::consts::ext::kSupportedVersions);
    append_extension(::tls::consts::ext::kKeyShare);

    push_u16(hello, static_cast<std::uint16_t>(extensions.size()));
    push_bytes(hello, extensions);

    const std::size_t total_len = hello.size() - 4;
    hello[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xff);
    hello[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xff);
    hello[3] = static_cast<std::uint8_t>(total_len & 0xff);
    return hello;
}

std::vector<std::uint8_t> construct_encrypted_extensions(const std::string& alpn,
                                                         const std::span<const std::uint16_t> extension_order,
                                                         const bool include_padding,
                                                         const std::optional<std::uint16_t> padding_len)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x08);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x00);

    std::vector<std::uint8_t> extensions;
    std::vector<std::uint8_t> alpn_ext;
    if (!alpn.empty())
    {
        push_u16(alpn_ext, ::tls::consts::ext::kAlpn);
        std::vector<std::uint8_t> proto;
        push_vector_u8(proto, std::vector<std::uint8_t>(alpn.begin(), alpn.end()));
        std::vector<std::uint8_t> ext;
        push_vector_u16(ext, proto);
        push_u16(alpn_ext, static_cast<std::uint16_t>(ext.size()));
        push_bytes(alpn_ext, ext);
    }

    std::vector<std::uint8_t> padding_ext;
    if (include_padding)
    {
        constexpr std::size_t kMaxExtensionsLen = 65535;
        std::size_t padding_budget = 0;
        if (alpn_ext.size() + 4 <= kMaxExtensionsLen)
        {
            padding_budget = kMaxExtensionsLen - alpn_ext.size() - 4;
        }

        std::uint16_t resolved_padding_len = 0;
        if (padding_len.has_value())
        {
            resolved_padding_len = static_cast<std::uint16_t>(std::min<std::size_t>(static_cast<std::size_t>(*padding_len), padding_budget));
        }
        else
        {
            static thread_local std::mt19937 gen(std::random_device{}());
            std::uniform_int_distribution<std::uint16_t> dist(10, 100);
            resolved_padding_len = static_cast<std::uint16_t>(std::min<std::size_t>(static_cast<std::size_t>(dist(gen)), padding_budget));
        }

        if (padding_budget > 0)
        {
            push_u16(padding_ext, ::tls::consts::ext::kPadding);
            push_u16(padding_ext, resolved_padding_len);
            for (std::uint16_t i = 0; i < resolved_padding_len; ++i)
            {
                padding_ext.push_back(0x00);
            }
        }
    }

    bool emitted_alpn = false;
    bool emitted_padding = false;
    const auto append_extension = [&](const std::uint16_t ext_type)
    {
        if (ext_type == ::tls::consts::ext::kAlpn && !emitted_alpn && !alpn_ext.empty())
        {
            push_bytes(extensions, alpn_ext);
            emitted_alpn = true;
        }
        else if (ext_type == ::tls::consts::ext::kPadding && !emitted_padding && !padding_ext.empty())
        {
            push_bytes(extensions, padding_ext);
            emitted_padding = true;
        }
    };

    for (const auto ext_type : extension_order)
    {
        append_extension(ext_type);
    }
    append_extension(::tls::consts::ext::kAlpn);
    append_extension(::tls::consts::ext::kPadding);

    push_u16(msg, static_cast<std::uint16_t>(extensions.size()));
    push_bytes(msg, extensions);

    const std::size_t total_len = msg.size() - 4;
    msg[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xff);
    msg[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xff);
    msg[3] = static_cast<std::uint8_t>(total_len & 0xff);
    return msg;
}

std::vector<std::uint8_t> construct_certificate(const std::span<const std::vector<std::uint8_t>> cert_chain)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x0b);
    std::vector<std::uint8_t> body;
    body.push_back(0x00);
    std::vector<std::uint8_t> list;
    for (const auto& cert_der : cert_chain)
    {
        push_u24(list, static_cast<std::uint32_t>(cert_der.size()));
        push_bytes(list, cert_der);
        push_u16(list, 0x0000);
    }
    push_u24(body, static_cast<std::uint32_t>(list.size()));
    push_bytes(body, list);
    push_u24(msg, static_cast<std::uint32_t>(body.size()));
    push_bytes(msg, body);
    return msg;
}

std::vector<std::uint8_t> construct_certificate(const std::vector<std::uint8_t>& cert_der)
{
    return construct_certificate(std::span<const std::vector<std::uint8_t>>(&cert_der, 1));
}

std::vector<std::uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<std::uint8_t>& handshake_hash)
{
    if (signing_key == nullptr)
    {
        return {};
    }

    std::vector<std::uint8_t> msg;
    msg.push_back(0x0f);
    std::vector<std::uint8_t> to_sign(64, 0x20);
    const std::string context_str = "TLS 1.3, server CertificateVerify";
    to_sign.insert(to_sign.end(), context_str.begin(), context_str.end());
    to_sign.push_back(0x00);
    to_sign.insert(to_sign.end(), handshake_hash.begin(), handshake_hash.end());

    const ::tls::openssl_ptrs::evp_md_ctx_ptr mctx(EVP_MD_CTX_new());
    if (mctx == nullptr)
    {
        return {};
    }
    if (EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, signing_key) != 1)
    {
        return {};
    }
    std::size_t sig_len = 0;
    if (EVP_DigestSign(mctx.get(), nullptr, &sig_len, to_sign.data(), to_sign.size()) != 1 || sig_len == 0)
    {
        return {};
    }
    if (sig_len > std::numeric_limits<std::uint16_t>::max())
    {
        return {};
    }
    std::vector<std::uint8_t> signature(sig_len);
    if (EVP_DigestSign(mctx.get(), signature.data(), &sig_len, to_sign.data(), to_sign.size()) != 1)
    {
        return {};
    }
    signature.resize(sig_len);

    std::vector<std::uint8_t> body;
    push_u16(body, 0x0807);
    push_u16(body, static_cast<std::uint16_t>(sig_len));
    push_bytes(body, signature);
    push_u24(msg, static_cast<std::uint32_t>(body.size()));
    push_bytes(msg, body);
    return msg;
}

std::vector<std::uint8_t> construct_finished(const std::vector<std::uint8_t>& verify_data)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x14);
    push_u24(msg, static_cast<std::uint32_t>(verify_data.size()));
    push_bytes(msg, verify_data);
    return msg;
}

}    // namespace tls
