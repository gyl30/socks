#include <span>
#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <optional>
#include <algorithm>

extern "C"
{
#include <openssl/x509.h>
}

#include "tls/core.h"
#include "tls/handshake_message.h"

namespace tls
{

namespace
{

bool read_u16_at(const std::span<const uint8_t> data, std::size_t& pos, uint16_t& value)
{
    if (pos + 2 > data.size())
    {
        return false;
    }
    value = static_cast<uint16_t>((static_cast<uint16_t>(data[pos]) << 8) | static_cast<uint16_t>(data[pos + 1]));
    pos += 2;
    return true;
}

bool read_u24_at(const std::span<const uint8_t> data, std::size_t& pos, uint32_t& value)
{
    if (pos + 3 > data.size())
    {
        return false;
    }
    value = (static_cast<uint32_t>(data[pos]) << 16) | (static_cast<uint32_t>(data[pos + 1]) << 8) | static_cast<uint32_t>(data[pos + 2]);
    pos += 3;
    return true;
}

bool read_handshake_message_len(const std::span<const uint8_t> data, std::size_t& full_len)
{
    if (data.size() < 4)
    {
        return false;
    }

    const auto payload_len = (static_cast<uint32_t>(data[1]) << 16) | (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
    full_len = static_cast<std::size_t>(payload_len) + 4U;
    return full_len <= data.size();
}

bool parse_extension_types(const std::span<const uint8_t> ext_block, handshake_extension_layout& layout, const bool capture_padding_len)
{
    layout.types.clear();
    layout.padding_len.reset();

    std::size_t pos = 0;
    while (pos < ext_block.size())
    {
        if (pos + 4 > ext_block.size())
        {
            return false;
        }
        const auto ext_type = static_cast<uint16_t>((static_cast<uint16_t>(ext_block[pos]) << 8) | static_cast<uint16_t>(ext_block[pos + 1]));
        const auto ext_len = static_cast<uint16_t>((static_cast<uint16_t>(ext_block[pos + 2]) << 8) | static_cast<uint16_t>(ext_block[pos + 3]));
        pos += 4;
        if (pos + ext_len > ext_block.size())
        {
            return false;
        }
        layout.types.push_back(ext_type);
        if (capture_padding_len && ext_type == tls::consts::ext::kPadding)
        {
            layout.padding_len = ext_len;
        }
        pos += ext_len;
    }
    return true;
}

bool is_exact_handshake_message(const std::span<const uint8_t> message, const uint8_t expected_type)
{
    std::size_t full_len = 0;
    if (!read_handshake_message_len(message, full_len))
    {
        return false;
    }
    return message[0] == expected_type && full_len == message.size();
}

bool validate_certificate_der(const std::span<const uint8_t> certificate_der)
{
    const auto* der_begin = certificate_der.data();
    const auto* parse_cursor = der_begin;
    const auto der_len = static_cast<int64_t>(certificate_der.size());
    const tls::openssl_ptrs::x509_ptr certificate(d2i_X509(nullptr, &parse_cursor, der_len));
    if (certificate == nullptr)
    {
        return false;
    }
    return parse_cursor == der_begin + static_cast<std::ptrdiff_t>(certificate_der.size());
}

constexpr std::array<uint8_t, 32> kHelloRetryRequestRandom = {
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

bool is_hello_retry_request_random(const std::span<const uint8_t> server_hello, const std::size_t random_pos)
{
    if (random_pos + kHelloRetryRequestRandom.size() > server_hello.size())
    {
        return false;
    }

    return std::equal(
        kHelloRetryRequestRandom.begin(), kHelloRetryRequestRandom.end(), server_hello.begin() + static_cast<std::ptrdiff_t>(random_pos));
}

bool skip_server_hello_prefix(const std::span<const uint8_t> server_hello, std::size_t& pos)
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

bool locate_server_hello_body(const std::span<const uint8_t> server_hello, std::size_t& pos, std::size_t& end)
{
    if (!skip_server_hello_prefix(server_hello, pos))
    {
        return false;
    }
    if (server_hello[pos] != 0x02)
    {
        return false;
    }
    const auto payload_len = (static_cast<uint32_t>(server_hello[pos + 1]) << 16) | (static_cast<uint32_t>(server_hello[pos + 2]) << 8) |
                             static_cast<uint32_t>(server_hello[pos + 3]);
    pos += 4;
    end = pos + payload_len;
    return end >= pos && end == server_hello.size();
}

bool parse_extension_header(const std::span<const uint8_t> server_hello, const std::size_t end, std::size_t& pos, uint16_t& type, uint16_t& ext_len)
{
    if (pos + 4 > end)
    {
        return false;
    }
    type = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    ext_len = static_cast<uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
    pos += 4;
    return true;
}

bool advance_extension_payload(std::size_t& pos, const std::size_t end, const uint16_t ext_len)
{
    if (pos + ext_len > end)
    {
        return false;
    }
    pos += ext_len;
    return true;
}

bool is_forbidden_tls13_server_hello_extension(const uint16_t ext_type)
{
    switch (ext_type)
    {
        case tls::consts::ext::kStatusRequest:
        case tls::consts::ext::kSessionTicket:
        case tls::consts::ext::kExtMasterSecret:
        case tls::consts::ext::kRenegotiationInfo:
        case tls::consts::ext::kAlpn:
        case tls::consts::ext::kSct:
            return true;
        default:
            return false;
    }
}

bool parse_supported_version_extension(const std::span<const uint8_t> server_hello,
                                       const std::size_t pos,
                                       const std::size_t ext_end,
                                       server_hello_info& info)
{
    if (pos + 2 != ext_end)
    {
        return false;
    }
    info.supported_version = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    info.has_supported_version = true;
    return true;
}

bool parse_hrr_key_share_extension(const std::span<const uint8_t> server_hello,
                                   const std::size_t pos,
                                   const std::size_t ext_end,
                                   server_hello_info& info)
{
    if (pos + 2 != ext_end)
    {
        return false;
    }

    info.key_share.group = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    info.key_share.data.clear();
    info.has_key_share = true;
    return true;
}

std::optional<server_key_share_info> parse_server_key_share_entry(const std::span<const uint8_t> server_hello,
                                                                  const std::size_t pos,
                                                                  const std::size_t ext_end)
{
    if (pos + 4 > ext_end)
    {
        return std::nullopt;
    }
    const auto group = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    const auto len = static_cast<uint16_t>((server_hello[pos + 2] << 8) | server_hello[pos + 3]);
    const auto data_start = pos + 4;
    if (data_start + len != ext_end)
    {
        return std::nullopt;
    }
    server_key_share_info info;
    info.group = group;
    info.data.assign(server_hello.begin() + static_cast<std::ptrdiff_t>(data_start),
                     server_hello.begin() + static_cast<std::ptrdiff_t>(data_start + len));
    return info;
}

bool parse_server_hello_key_share_extension(const std::span<const uint8_t> server_hello,
                                            const std::size_t pos,
                                            const std::size_t ext_end,
                                            server_hello_info& info,
                                            const bool is_hello_retry_request)
{
    if (info.has_key_share)
    {
        return false;
    }
    if (is_hello_retry_request)
    {
        return parse_hrr_key_share_extension(server_hello, pos, ext_end, info);
    }

    const auto key_share = parse_server_key_share_entry(server_hello, pos, ext_end);
    if (!key_share.has_value())
    {
        return false;
    }
    info.key_share = *key_share;
    info.has_key_share = true;
    return true;
}

bool parse_server_hello_extension_by_type(const std::span<const uint8_t> server_hello,
                                          const uint16_t type,
                                          const std::size_t pos,
                                          const std::size_t ext_end,
                                          server_hello_info& info,
                                          const bool is_hello_retry_request)
{
    if (type == tls::consts::ext::kSupportedVersions)
    {
        return !info.has_supported_version && parse_supported_version_extension(server_hello, pos, ext_end, info);
    }
    if (type == tls::consts::ext::kKeyShare)
    {
        return parse_server_hello_key_share_extension(server_hello, pos, ext_end, info, is_hello_retry_request);
    }
    if (is_forbidden_tls13_server_hello_extension(type))
    {
        info.has_forbidden_tls13_extension = true;
    }

    return true;
}

bool parse_server_hello_extensions(
    const std::span<const uint8_t> server_hello, std::size_t pos, const std::size_t end, server_hello_info& info, const bool is_hello_retry_request)
{
    while (pos + 4 <= end)
    {
        uint16_t type = 0;
        uint16_t ext_len = 0;
        if (!parse_extension_header(server_hello, end, pos, type, ext_len))
        {
            return false;
        }
        if (pos + ext_len > end)
        {
            return false;
        }

        const auto ext_end = pos + ext_len;
        if (!parse_server_hello_extension_by_type(server_hello, type, pos, ext_end, info, is_hello_retry_request))
        {
            return false;
        }

        if (!advance_extension_payload(pos, end, ext_len))
        {
            return false;
        }
    }
    return pos == end;
}

struct encrypted_extensions_range
{
    std::size_t pos = 0;
    std::size_t end = 0;
};

std::optional<encrypted_extensions_range> parse_encrypted_extensions_range(const std::span<const uint8_t> encrypted_extensions)
{
    if (!is_exact_handshake_message(encrypted_extensions, 0x08))
    {
        return std::nullopt;
    }
    if (encrypted_extensions.size() < 6)
    {
        return std::nullopt;
    }

    const auto total_ext_len = static_cast<uint16_t>((encrypted_extensions[4] << 8) | encrypted_extensions[5]);
    constexpr std::size_t ext_start = 6;
    const std::size_t ext_end = ext_start + total_ext_len;
    if (ext_end != encrypted_extensions.size())
    {
        return std::nullopt;
    }

    return encrypted_extensions_range{.pos = ext_start, .end = ext_end};
}

bool read_extension_header(const std::span<const uint8_t> msg, std::size_t& pos, const std::size_t end, uint16_t& type, uint16_t& len)
{
    if (pos + 4 > end)
    {
        return false;
    }
    type = static_cast<uint16_t>((msg[pos] << 8) | msg[pos + 1]);
    len = static_cast<uint16_t>((msg[pos + 2] << 8) | msg[pos + 3]);
    pos += 4;
    return pos + len <= end;
}

std::optional<std::string> parse_alpn_extension_body(const std::span<const uint8_t> encrypted_extensions, const std::size_t pos, const uint16_t len)
{
    if (len < 3)
    {
        return std::nullopt;
    }

    const std::size_t ext_end = pos + len;
    const auto list_len = static_cast<uint16_t>((encrypted_extensions[pos] << 8) | encrypted_extensions[pos + 1]);
    if (list_len < 2 || pos + 3 > ext_end)
    {
        return std::nullopt;
    }
    if (pos + 2 + list_len != ext_end)
    {
        return std::nullopt;
    }

    const uint8_t proto_len = encrypted_extensions[pos + 2];
    if (proto_len == 0 || static_cast<std::size_t>(proto_len) + 1 > list_len)
    {
        return std::nullopt;
    }
    if (pos + 3 + proto_len != ext_end)
    {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(&encrypted_extensions[pos + 3]), proto_len);
}

}    // namespace

bool extract_handshake_message(const std::span<const uint8_t> data, std::vector<uint8_t>& message)
{
    message.clear();

    std::size_t full_len = 0;
    if (!read_handshake_message_len(data, full_len))
    {
        return false;
    }

    message.assign(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(full_len));
    return true;
}

bool parse_server_hello_extension_layout(const std::span<const uint8_t> server_hello, handshake_extension_layout& layout)
{
    layout.types.clear();
    layout.padding_len.reset();

    if (!is_exact_handshake_message(server_hello, 0x02))
    {
        return false;
    }
    if (server_hello.size() < 4 + 2 + 32 + 1 + 2 + 1 + 2)
    {
        return false;
    }

    std::size_t pos = 4 + 2 + 32;
    const auto session_id_len = static_cast<std::size_t>(server_hello[pos]);
    ++pos;
    if (pos + session_id_len + 2 + 1 + 2 > server_hello.size())
    {
        return false;
    }

    pos += session_id_len;
    pos += 2;
    pos += 1;

    uint16_t ext_len = 0;
    if (!read_u16_at(server_hello, pos, ext_len))
    {
        return false;
    }
    if (pos + ext_len != server_hello.size())
    {
        return false;
    }

    return parse_extension_types(server_hello.subspan(pos, ext_len), layout, false);
}

bool parse_encrypted_extensions_layout(const std::span<const uint8_t> encrypted_extensions, handshake_extension_layout& layout)
{
    layout.types.clear();
    layout.padding_len.reset();

    if (!is_exact_handshake_message(encrypted_extensions, 0x08))
    {
        return false;
    }

    std::size_t pos = 4;
    uint16_t ext_len = 0;
    if (!read_u16_at(encrypted_extensions, pos, ext_len))
    {
        return false;
    }
    if (pos + ext_len != encrypted_extensions.size())
    {
        return false;
    }

    return parse_extension_types(encrypted_extensions.subspan(pos, ext_len), layout, true);
}

bool parse_certificate_chain(const std::span<const uint8_t> certificate_message, std::vector<std::vector<uint8_t>>& certificate_chain)
{
    certificate_chain.clear();

    if (!is_exact_handshake_message(certificate_message, 0x0b))
    {
        return false;
    }
    if (certificate_message.size() < 8)
    {
        return false;
    }

    std::size_t pos = 4;
    const auto context_len = static_cast<std::size_t>(certificate_message[pos]);
    ++pos;
    if (pos + context_len + 3 > certificate_message.size())
    {
        return false;
    }
    pos += context_len;

    uint32_t certificate_list_len = 0;
    if (!read_u24_at(certificate_message, pos, certificate_list_len))
    {
        return false;
    }
    if (pos + certificate_list_len != certificate_message.size())
    {
        return false;
    }

    const auto certificate_list_end = pos + certificate_list_len;
    while (pos < certificate_list_end)
    {
        uint32_t certificate_len = 0;
        if (!read_u24_at(certificate_message, pos, certificate_len))
        {
            return false;
        }
        if (certificate_len == 0)
        {
            return false;
        }
        if (pos + certificate_len + 2 > certificate_list_end)
        {
            return false;
        }

        const auto certificate_der = certificate_message.subspan(pos, static_cast<std::size_t>(certificate_len));
        if (!validate_certificate_der(certificate_der))
        {
            return false;
        }

        certificate_chain.emplace_back(certificate_message.begin() + static_cast<std::ptrdiff_t>(pos),
                                       certificate_message.begin() + static_cast<std::ptrdiff_t>(pos + certificate_len));
        pos += certificate_len;

        uint16_t ext_len = 0;
        if (!read_u16_at(certificate_message, pos, ext_len))
        {
            return false;
        }
        if (pos + ext_len > certificate_list_end)
        {
            return false;
        }
        pos += ext_len;
    }

    return !certificate_chain.empty();
}

bool extract_first_certificate(const std::span<const uint8_t> certificate_message, std::vector<uint8_t>& certificate)
{
    certificate.clear();

    std::vector<std::vector<uint8_t>> certificate_chain;
    if (!parse_certificate_chain(certificate_message, certificate_chain))
    {
        return false;
    }

    certificate = std::move(certificate_chain.front());
    return true;
}

std::optional<certificate_verify_info> parse_certificate_verify(const std::span<const uint8_t> message)
{
    if (!is_exact_handshake_message(message, 0x0f) || message.size() < 8)
    {
        return std::nullopt;
    }

    std::size_t pos = 4;
    uint16_t scheme = 0;
    if (!read_u16_at(message, pos, scheme))
    {
        return std::nullopt;
    }
    uint16_t signature_len = 0;
    if (!read_u16_at(message, pos, signature_len))
    {
        return std::nullopt;
    }
    if (pos + signature_len != message.size())
    {
        return std::nullopt;
    }

    certificate_verify_info info;
    info.scheme = scheme;
    info.signature.assign(message.begin() + static_cast<std::ptrdiff_t>(pos), message.end());
    return info;
}

bool is_supported_certificate_verify_scheme(const uint16_t scheme)
{
    using tls::consts::sig_alg::kEcdsaSecp256r1Sha256;
    using tls::consts::sig_alg::kEcdsaSecp384r1Sha384;
    using tls::consts::sig_alg::kEcdsaSecp521r1Sha512;
    using tls::consts::sig_alg::kEd25519;
    using tls::consts::sig_alg::kRsaPkcs1Sha256;
    using tls::consts::sig_alg::kRsaPkcs1Sha384;
    using tls::consts::sig_alg::kRsaPkcs1Sha512;
    using tls::consts::sig_alg::kRsaPssRsaeSha256;
    using tls::consts::sig_alg::kRsaPssRsaeSha384;
    using tls::consts::sig_alg::kRsaPssRsaeSha512;

    constexpr std::array<uint16_t, 10> kSupportedSchemes = {
        kEd25519,
        kEcdsaSecp256r1Sha256,
        kEcdsaSecp384r1Sha384,
        kEcdsaSecp521r1Sha512,
        kRsaPkcs1Sha256,
        kRsaPkcs1Sha384,
        kRsaPkcs1Sha512,
        kRsaPssRsaeSha256,
        kRsaPssRsaeSha384,
        kRsaPssRsaeSha512,
    };
    return std::find(kSupportedSchemes.begin(), kSupportedSchemes.end(), scheme) != kSupportedSchemes.end();
}

const char* named_group_name(const uint16_t group)
{
    switch (group)
    {
        case tls::consts::group::kSecp256r1:
            return "secp256r1";
        case tls::consts::group::kSecp384r1:
            return "secp384r1";
        case tls::consts::group::kSecp521r1:
            return "secp521r1";
        case tls::consts::group::kX25519:
            return "x25519";
        case tls::consts::group::kX25519MLKEM768:
            return "x25519_mlkem768";
        case tls::consts::group::kFfdhe2048:
            return "ffdhe2048";
        case tls::consts::group::kFfdhe3072:
            return "ffdhe3072";
        default:
            return "unknown";
    }
}

std::optional<server_hello_info> parse_server_hello(const std::span<const uint8_t> server_hello)
{
    std::size_t pos = 0;
    std::size_t end = 0;
    if (!locate_server_hello_body(server_hello, pos, end))
    {
        return std::nullopt;
    }
    if (pos + 2 + 32 + 1 > end)
    {
        return std::nullopt;
    }

    server_hello_info info;
    info.legacy_version = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    info.is_hello_retry_request = is_hello_retry_request_random(server_hello, pos + 2);
    pos += 2 + 32;

    const auto session_id_len = static_cast<std::size_t>(server_hello[pos]);
    ++pos;
    if (pos + session_id_len + 2 + 1 + 2 > end)
    {
        return std::nullopt;
    }
    info.session_id.assign(server_hello.begin() + static_cast<std::ptrdiff_t>(pos),
                           server_hello.begin() + static_cast<std::ptrdiff_t>(pos + session_id_len));
    pos += session_id_len;

    info.cipher_suite = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    pos += 2;
    info.compression_method = server_hello[pos];
    ++pos;

    const auto ext_len = static_cast<uint16_t>((server_hello[pos] << 8) | server_hello[pos + 1]);
    pos += 2;
    if (pos + ext_len != end)
    {
        return std::nullopt;
    }
    if (!parse_server_hello_extensions(server_hello, pos, end, info, info.is_hello_retry_request))
    {
        return std::nullopt;
    }
    return info;
}

std::optional<uint16_t> extract_cipher_suite_from_server_hello(const std::span<const uint8_t> server_hello)
{
    const auto info = parse_server_hello(server_hello);
    if (!info.has_value())
    {
        return std::nullopt;
    }
    return info->cipher_suite;
}

std::optional<server_key_share_info> extract_server_key_share(const std::span<const uint8_t> server_hello)
{
    const auto info = parse_server_hello(server_hello);
    if (!info.has_value() || !info->has_key_share)
    {
        return std::nullopt;
    }
    return info->key_share;
}

std::vector<uint8_t> extract_server_public_key(const std::span<const uint8_t> server_hello)
{
    const auto info = extract_server_key_share(server_hello);
    if (!info.has_value())
    {
        return {};
    }
    if (info->group == tls::consts::group::kX25519 && info->data.size() == 32)
    {
        return info->data;
    }
    return {};
}

std::optional<encrypted_extensions_info> parse_encrypted_extensions(const std::span<const uint8_t> encrypted_extensions)
{
    const auto range = parse_encrypted_extensions_range(encrypted_extensions);
    if (!range.has_value())
    {
        return std::nullopt;
    }

    encrypted_extensions_info info;
    auto pos = range->pos;
    const auto end = range->end;

    while (pos + 4 <= end)
    {
        uint16_t type = 0;
        uint16_t len = 0;
        if (!read_extension_header(encrypted_extensions, pos, end, type, len))
        {
            return std::nullopt;
        }
        if (type == tls::consts::ext::kAlpn)
        {
            if (info.has_alpn)
            {
                return std::nullopt;
            }
            const auto alpn = parse_alpn_extension_body(encrypted_extensions, pos, len);
            if (!alpn.has_value())
            {
                return std::nullopt;
            }
            info.has_alpn = true;
            info.alpn = *alpn;
        }
        pos += len;
    }
    if (pos != end)
    {
        return std::nullopt;
    }
    return info;
}

std::optional<std::string> extract_alpn_from_encrypted_extensions(const std::span<const uint8_t> encrypted_extensions)
{
    const auto info = parse_encrypted_extensions(encrypted_extensions);
    if (!info.has_value() || !info->has_alpn)
    {
        return std::nullopt;
    }
    return info->alpn;
}

}    // namespace tls
