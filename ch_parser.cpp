#include <vector>
#include <cstdint>

#include "ch_parser.h"
#include "reality_core.h"

namespace mux
{

bool ch_parser::read_tls_record_header(reader& r)
{
    if (r.remaining() < 5)
    {
        return false;
    }

    std::uint8_t record_type = 0;
    if (!r.read_u8(record_type) || record_type != 0x16)
    {
        return false;
    }

    return r.skip(2 + 2);
}

bool ch_parser::read_client_hello_prefix(reader& r, client_hello_info& info)
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

bool ch_parser::read_session_id(reader& r, client_hello_info& info)
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

bool ch_parser::skip_cipher_suites_and_compression(reader& r)
{
    std::uint16_t cs_len = 0;
    if (!r.read_u16(cs_len))
    {
        return false;
    }
    if (!r.skip(cs_len))
    {
        return false;
    }

    std::uint8_t comp_len = 0;
    if (!r.read_u8(comp_len))
    {
        return false;
    }
    return r.skip(comp_len);
}

bool ch_parser::read_extension_header(reader& r, std::uint16_t& type, std::uint16_t& len)
{
    if (!r.read_u16(type) || !r.read_u16(len))
    {
        return false;
    }
    return true;
}

bool ch_parser::read_sni_item_header(reader& r, std::uint8_t& type, std::uint16_t& len)
{
    if (!r.read_u8(type) || !r.read_u16(len))
    {
        return false;
    }
    return true;
}

bool ch_parser::handle_sni_item(reader& r, const std::uint8_t type, const std::uint16_t len, client_hello_info& info)
{
    if (type == 0x00)
    {
        if (r.has(len))
        {
            info.sni.assign(reinterpret_cast<const char*>(r.data()), len);
        }
        return true;
    }

    if (!r.skip(len))
    {
        return true;
    }
    return false;
}

bool ch_parser::read_key_share_item_header(reader& r, std::uint16_t& group, std::uint16_t& len)
{
    if (!r.read_u16(group) || !r.read_u16(len))
    {
        return false;
    }
    return true;
}

void ch_parser::handle_key_share_item(reader& r, const std::uint16_t group, const std::uint16_t len, client_hello_info& info)
{
    if (group != reality::tls_consts::group::kX25519)
    {
        return;
    }
    if (len != 32 || !r.has(32))
    {
        return;
    }
    info.x25519_pub.assign(r.data(), r.data() + 32);
    info.has_x25519_share = true;
}

void ch_parser::finalize_key_share_info(client_hello_info& info)
{
    if (!info.has_x25519_share)
    {
        return;
    }
    info.is_tls13 = true;
    info.key_share_group = reality::tls_consts::group::kX25519;
}

client_hello_info ch_parser::parse(const std::vector<std::uint8_t>& buf)
{
    client_hello_info info;
    reader r(buf);

    if (!read_tls_record_header(r))
    {
        return info;
    }

    if (!read_client_hello_prefix(r, info))
    {
        return info;
    }

    if (!read_session_id(r, info))
    {
        return info;
    }

    if (!skip_cipher_suites_and_compression(r))
    {
        return info;
    }

    std::uint16_t ext_len = 0;
    if (!r.read_u16(ext_len))
    {
        return info;
    }

    reader ext_r = r.slice(ext_len);
    if (ext_r.valid())
    {
        parse_extensions(ext_r, info);
    }

    return info;
}

void ch_parser::parse_extensions(reader& r, client_hello_info& info)
{
    while (r.remaining() >= 4)
    {
        std::uint16_t type = 0;
        std::uint16_t ext_len = 0;
        if (!read_extension_header(r, type, ext_len))
        {
            break;
        }

        reader val = r.slice(ext_len);
        if (!val.valid())
        {
            break;
        }

        if (type == reality::tls_consts::ext::kSni)
        {
            parse_sni(val, info);
        }
        else if (type == reality::tls_consts::ext::kKeyShare)
        {
            parse_key_share(val, info);
        }
    }
}

void ch_parser::parse_sni(reader& r, client_hello_info& info)
{
    std::uint16_t list_len = 0;
    if (!r.read_u16(list_len))
    {
        return;
    }

    reader list_r = r.slice(list_len);
    if (!list_r.valid())
    {
        return;
    }

    while (list_r.remaining() >= 3)
    {
        std::uint8_t type = 0;
        std::uint16_t len = 0;
        if (!read_sni_item_header(list_r, type, len))
        {
            break;
        }
        if (handle_sni_item(list_r, type, len, info))
        {
            return;
        }
    }
}

void ch_parser::parse_key_share(reader& r, client_hello_info& info)
{
    std::uint16_t share_len = 0;
    if (!r.read_u16(share_len))
    {
        return;
    }
    reader shares_r = r.slice(share_len);
    if (!shares_r.valid())
    {
        return;
    }

    while (shares_r.remaining() >= 4)
    {
        std::uint16_t group = 0;
        std::uint16_t len = 0;
        if (!read_key_share_item_header(shares_r, group, len))
        {
            break;
        }
        handle_key_share_item(shares_r, group, len, info);
        if (!shares_r.skip(len))
        {
            break;
        }
    }
    finalize_key_share_info(info);
}

}    // namespace mux
