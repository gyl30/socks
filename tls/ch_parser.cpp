#include <vector>
#include <cstdint>
#include <algorithm>

#include "tls/ch_parser.h"
#include "tls/core.h"

namespace tls
{

namespace
{
constexpr std::uint16_t kMaxSniLen = 255;
}

bool client_hello_parser::read_client_hello_prefix(reader& r, client_hello_info& info)
{
    std::uint8_t handshake_type = 0;
    if (!r.read_u8(handshake_type) || handshake_type != 0x01)
    {
        return false;
    }

    if (!r.skip(3))
    {
        return false;
    }

    if (!r.skip(2))
    {
        return false;
    }

    return r.read_vector(info.random, 32);
}

bool client_hello_parser::read_session_id(reader& r, client_hello_info& info)
{
    std::uint8_t sid_len = 0;
    if (!r.read_u8(sid_len))
    {
        return false;
    }

    info.sid_offset = static_cast<std::uint32_t>(r.offset());
    if (sid_len == 0)
    {
        return true;
    }

    return r.read_vector(info.session_id, sid_len);
}

bool client_hello_parser::parse_cipher_suites_and_compression(reader& r, client_hello_info& info)
{
    std::uint16_t cs_len = 0;
    if (!r.read_u16(cs_len))
    {
        return false;
    }
    if ((cs_len % 2) != 0)
    {
        return false;
    }
    reader suites_r = r.slice(cs_len);
    if (!suites_r.valid())
    {
        return false;
    }
    while (suites_r.remaining() >= 2)
    {
        std::uint16_t suite = 0;
        if (!suites_r.read_u16(suite))
        {
            return false;
        }
        info.cipher_suites.push_back(suite);
    }
    if (suites_r.remaining() != 0)
    {
        return false;
    }

    std::uint8_t comp_len = 0;
    if (!r.read_u8(comp_len))
    {
        return false;
    }
    return r.read_vector(info.compression_methods, comp_len);
}

bool client_hello_parser::read_extension_header(reader& r, std::uint16_t& type, std::uint16_t& len) { return r.read_u16(type) && r.read_u16(len); }

bool client_hello_parser::read_sni_item_header(reader& r, std::uint8_t& type, std::uint16_t& len) { return r.read_u8(type) && r.read_u16(len); }

bool client_hello_parser::handle_sni_item(reader& r, const std::uint8_t type, const std::uint16_t len, client_hello_info& info)
{
    if (type == 0x00)
    {
        if (len == 0 || len > kMaxSniLen || !r.has(len))
        {
            info.malformed_sni = true;
            return true;
        }
        info.sni.assign(reinterpret_cast<const char*>(r.data()), len);
        return true;
    }

    if (!r.skip(len))
    {
        info.malformed_sni = true;
        return true;
    }
    return false;
}

bool client_hello_parser::read_key_share_item_header(reader& r, std::uint16_t& group, std::uint16_t& len) { return r.read_u16(group) && r.read_u16(len); }

void client_hello_parser::handle_key_share_item(reader& r, const std::uint16_t group, const std::uint16_t len, client_hello_info& info)
{
    if (group == consts::group::kX25519)
    {
        if (len != 32 || !r.has(32))
        {
            return;
        }
        info.x25519_pub.assign(r.data(), r.data() + 32);
        info.has_x25519_share = true;
        return;
    }
    if (group != consts::group::kX25519MLKEM768)
    {
        return;
    }
    if (len != kMlkem768PublicKeySize + 32 || !r.has(len))
    {
        return;
    }
    info.x25519_mlkem768_share.assign(r.data(), r.data() + static_cast<std::ptrdiff_t>(len));
    info.has_x25519_mlkem768_share = true;
}

void client_hello_parser::finalize_key_share_info(client_hello_info& info)
{
    info.key_share_group = 0;
    if (info.has_x25519_mlkem768_share)
    {
        info.key_share_group = consts::group::kX25519MLKEM768;
        return;
    }
    if (info.has_x25519_share)
    {
        info.key_share_group = consts::group::kX25519;
    }
}

void client_hello_parser::finalize_tls13_info(client_hello_info& info)
{
    info.is_tls13 = false;
    if (info.malformed_key_share || info.malformed_supported_groups || info.malformed_supported_versions)
    {
        info.key_share_group = 0;
        return;
    }
    if (std::find(info.supported_versions.begin(), info.supported_versions.end(), consts::kVer13) == info.supported_versions.end())
    {
        info.key_share_group = 0;
        return;
    }
    if (info.has_x25519_mlkem768_share)
    {
        const auto hybrid_it = std::find(info.supported_groups.begin(), info.supported_groups.end(), consts::group::kX25519MLKEM768);
        if (hybrid_it != info.supported_groups.end())
        {
            info.is_tls13 = true;
            info.key_share_group = consts::group::kX25519MLKEM768;
            return;
        }
    }
    if (info.has_x25519_share)
    {
        const auto x25519_it = std::find(info.supported_groups.begin(), info.supported_groups.end(), consts::group::kX25519);
        if (x25519_it != info.supported_groups.end())
        {
            info.is_tls13 = true;
            info.key_share_group = consts::group::kX25519;
            return;
        }
    }
    info.key_share_group = 0;
}

bool client_hello_parser::parse_before_extensions(reader& r, client_hello_info& info)
{
    if (!read_client_hello_prefix(r, info))
    {
        return false;
    }
    if (!read_session_id(r, info))
    {
        return false;
    }
    return parse_cipher_suites_and_compression(r, info);
}

void client_hello_parser::parse_extension_block(reader& r, client_hello_info& info)
{
    std::uint16_t ext_len = 0;
    if (!r.read_u16(ext_len))
    {
        if (r.remaining() != 0)
        {
            info.malformed_extensions = true;
        }
        return;
    }

    reader ext_r = r.slice(ext_len);
    if (!ext_r.valid())
    {
        info.malformed_extensions = true;
        return;
    }
    parse_extensions(ext_r, info);
    if (ext_r.remaining() != 0 || r.remaining() != 0)
    {
        info.malformed_extensions = true;
    }
}

client_hello_info client_hello_parser::parse(const std::vector<std::uint8_t>& buf)
{
    client_hello_info info;
    reader r(buf);
    if (!parse_before_extensions(r, info))
    {
        return info;
    }
    parse_extension_block(r, info);
    finalize_tls13_info(info);
    return info;
}

void client_hello_parser::parse_extensions(reader& r, client_hello_info& info)
{
    while (r.remaining() != 0)
    {
        if (r.remaining() < 4)
        {
            info.malformed_extensions = true;
            return;
        }

        std::uint16_t type = 0;
        std::uint16_t ext_len = 0;
        if (!read_extension_header(r, type, ext_len))
        {
            info.malformed_extensions = true;
            return;
        }

        reader val = r.slice(ext_len);
        if (!val.valid())
        {
            info.malformed_extensions = true;
            return;
        }

        if (type == consts::ext::kSni)
        {
            parse_sni(val, info);
        }
        else if (type == consts::ext::kAlpn)
        {
            parse_alpn(val, info);
        }
        else if (type == consts::ext::kSupportedGroups)
        {
            parse_supported_groups(val, info);
        }
        else if (type == consts::ext::kSupportedVersions)
        {
            parse_supported_versions(val, info);
        }
        else if (type == consts::ext::kSignatureAlg)
        {
            parse_signature_algorithms(val, info);
        }
        else if (type == consts::ext::kKeyShare)
        {
            parse_key_share(val, info);
        }
        else if (type == consts::ext::kRenegotiationInfo)
        {
            parse_renegotiation_info(val, info);
        }
    }
}

void client_hello_parser::parse_sni(reader& r, client_hello_info& info)
{
    std::uint16_t list_len = 0;
    if (!r.read_u16(list_len))
    {
        info.malformed_sni = true;
        return;
    }

    reader list_r = r.slice(list_len);
    if (!list_r.valid())
    {
        info.malformed_sni = true;
        return;
    }
    if (r.remaining() != 0)
    {
        info.malformed_sni = true;
        return;
    }

    bool host_name_seen = false;
    while (list_r.remaining() >= 3)
    {
        std::uint8_t type = 0;
        std::uint16_t len = 0;
        if (!read_sni_item_header(list_r, type, len))
        {
            info.malformed_sni = true;
            return;
        }
        if (type == 0x00)
        {
            if (host_name_seen || len == 0 || len > kMaxSniLen || !list_r.has(len))
            {
                info.malformed_sni = true;
                return;
            }
            info.sni.assign(reinterpret_cast<const char*>(list_r.data()), len);
            host_name_seen = true;
            if (!list_r.skip(len))
            {
                info.malformed_sni = true;
                return;
            }
            continue;
        }
        if (!list_r.skip(len))
        {
            info.malformed_sni = true;
            return;
        }
    }
    if (list_r.remaining() != 0)
    {
        info.malformed_sni = true;
    }
}

void client_hello_parser::parse_alpn(reader& r, client_hello_info& info)
{
    std::uint16_t list_len = 0;
    if (!r.read_u16(list_len))
    {
        return;
    }

    reader list_r = r.slice(list_len);
    if (!list_r.valid() || r.remaining() != 0)
    {
        return;
    }

    while (list_r.remaining() >= 1)
    {
        std::uint8_t proto_len = 0;
        if (!list_r.read_u8(proto_len) || proto_len == 0 || !list_r.has(proto_len))
        {
            info.alpn_protocols.clear();
            return;
        }
        info.alpn_protocols.emplace_back(reinterpret_cast<const char*>(list_r.data()), proto_len);
        if (!list_r.skip(proto_len))
        {
            info.alpn_protocols.clear();
            return;
        }
    }
    if (list_r.remaining() != 0)
    {
        info.alpn_protocols.clear();
    }
}

void client_hello_parser::parse_key_share(reader& r, client_hello_info& info)
{
    std::uint16_t share_len = 0;
    if (!r.read_u16(share_len))
    {
        info.malformed_key_share = true;
        return;
    }
    reader shares_r = r.slice(share_len);
    if (!shares_r.valid())
    {
        info.malformed_key_share = true;
        return;
    }
    if (r.remaining() != 0)
    {
        info.malformed_key_share = true;
        return;
    }

    while (shares_r.remaining() >= 4)
    {
        std::uint16_t group = 0;
        std::uint16_t len = 0;
        if (!read_key_share_item_header(shares_r, group, len))
        {
            info.malformed_key_share = true;
            break;
        }
        if (group == consts::group::kX25519 && len != 32)
        {
            info.malformed_key_share = true;
            break;
        }
        if (group == consts::group::kX25519MLKEM768 && len != kMlkem768PublicKeySize + 32)
        {
            info.malformed_key_share = true;
            break;
        }
        handle_key_share_item(shares_r, group, len, info);
        if (!shares_r.skip(len))
        {
            info.malformed_key_share = true;
            break;
        }
    }
    if (shares_r.remaining() != 0)
    {
        info.malformed_key_share = true;
    }
    if (info.malformed_key_share)
    {
        info.has_x25519_share = false;
        info.has_x25519_mlkem768_share = false;
        info.x25519_pub.clear();
        info.x25519_mlkem768_share.clear();
        info.is_tls13 = false;
        info.key_share_group = 0;
        return;
    }
    finalize_key_share_info(info);
}

void client_hello_parser::parse_supported_groups(reader& r, client_hello_info& info)
{
    std::uint16_t groups_len = 0;
    if (!r.read_u16(groups_len) || groups_len == 0 || (groups_len % 2) != 0)
    {
        info.malformed_supported_groups = true;
        return;
    }

    reader groups_r = r.slice(groups_len);
    if (!groups_r.valid() || r.remaining() != 0)
    {
        info.malformed_supported_groups = true;
        return;
    }

    while (groups_r.remaining() >= 2)
    {
        std::uint16_t group = 0;
        if (!groups_r.read_u16(group))
        {
            info.malformed_supported_groups = true;
            return;
        }
        info.supported_groups.push_back(group);
    }
    if (groups_r.remaining() != 0)
    {
        info.malformed_supported_groups = true;
    }
}

void client_hello_parser::parse_supported_versions(reader& r, client_hello_info& info)
{
    std::uint8_t versions_len = 0;
    if (!r.read_u8(versions_len) || versions_len == 0 || (versions_len % 2) != 0)
    {
        info.malformed_supported_versions = true;
        return;
    }

    reader versions_r = r.slice(versions_len);
    if (!versions_r.valid() || r.remaining() != 0)
    {
        info.malformed_supported_versions = true;
        return;
    }

    while (versions_r.remaining() >= 2)
    {
        std::uint16_t version = 0;
        if (!versions_r.read_u16(version))
        {
            info.malformed_supported_versions = true;
            return;
        }
        info.supported_versions.push_back(version);
    }
    if (versions_r.remaining() != 0)
    {
        info.malformed_supported_versions = true;
    }
}

void client_hello_parser::parse_signature_algorithms(reader& r, client_hello_info& info)
{
    std::uint16_t algorithms_len = 0;
    if (!r.read_u16(algorithms_len) || algorithms_len == 0 || (algorithms_len % 2) != 0)
    {
        info.malformed_signature_algorithms = true;
        info.signature_algorithms.clear();
        return;
    }

    reader algorithms_r = r.slice(algorithms_len);
    if (!algorithms_r.valid() || r.remaining() != 0)
    {
        info.malformed_signature_algorithms = true;
        info.signature_algorithms.clear();
        return;
    }

    while (algorithms_r.remaining() >= 2)
    {
        std::uint16_t sig_alg = 0;
        if (!algorithms_r.read_u16(sig_alg))
        {
            info.malformed_signature_algorithms = true;
            info.signature_algorithms.clear();
            return;
        }
        info.signature_algorithms.push_back(sig_alg);
    }

    if (algorithms_r.remaining() != 0)
    {
        info.malformed_signature_algorithms = true;
        info.signature_algorithms.clear();
    }
}

void client_hello_parser::parse_renegotiation_info(reader& r, client_hello_info& info)
{
    info.has_renegotiation_info = true;
    info.secure_renegotiation.clear();

    std::uint8_t renegotiation_len = 0;
    if (!r.read_u8(renegotiation_len))
    {
        info.malformed_renegotiation_info = true;
        return;
    }

    if (!r.read_vector(info.secure_renegotiation, renegotiation_len) || r.remaining() != 0)
    {
        info.malformed_renegotiation_info = true;
        info.secure_renegotiation.clear();
    }
}

}    // namespace tls
