#include "ch_parser.h"

namespace mux
{

client_hello_info_t ch_parser::parse(const std::vector<uint8_t>& buf)
{
    client_hello_info_t info;
    reader r(buf);

    if (r.remaining() >= 5 && r.peek(0) == 0x16 && r.peek(1) == static_cast<uint8_t>(reality::tls_consts::VER_1_2 >> 8))
    {
        r.skip(5);
    }

    uint8_t type;
    if (!r.read_u8(type) || type != 0x01)
    {
        return info;
    }
    if (!r.skip(3 + 2))
    {
        return info;
    }

    if (!r.read_vector(info.random, 32))
    {
        return info;
    }

    uint8_t sid_len;

    const size_t sid_start_offset = r.offset() + 1;

    if (!r.read_u8(sid_len))
    {
        return info;
    }

    info.sid_offset = static_cast<uint32_t>(sid_start_offset);

    if (sid_len > 0)
    {
        if (!r.read_vector(info.session_id, sid_len))
        {
            return info;
        }
    }

    uint16_t cs_len;
    if (!r.read_u16(cs_len))
    {
        return info;
    }
    if (!r.skip(cs_len))
    {
        return info;
    }

    uint8_t comp_len;
    if (!r.read_u8(comp_len))
    {
        return info;
    }
    if (!r.skip(comp_len))
    {
        return info;
    }

    uint16_t ext_len;
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

void ch_parser::parse_extensions(reader& r, client_hello_info_t& info)
{
    while (r.remaining() >= 4)
    {
        uint16_t type;
        uint16_t len;
        if (!r.read_u16(type) || !r.read_u16(len))
        {
            break;
        }

        reader val = r.slice(len);
        if (!val.valid())
        {
            break;
        }

        if (type == reality::tls_consts::ext::SNI)
        {
            parse_sni(val, info);
        }
        else if (type == reality::tls_consts::ext::KEY_SHARE)
        {
            parse_key_share(val, info);
        }
    }
}

void ch_parser::parse_sni(reader& r, client_hello_info_t& info)
{
    uint16_t list_len;
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
        uint8_t type = 0;
        uint16_t len = 0;

        if (!list_r.read_u8(type) || !list_r.read_u16(len))
        {
            break;
        }

        if (type == 0x00)
        {
            if (list_r.has(len))
            {
                info.sni.assign(reinterpret_cast<const char*>(list_r.ptr), len);
            }
            return;
        }

        if (!list_r.skip(len))
        {
            break;
        }
    }
}

void ch_parser::parse_key_share(reader& r, client_hello_info_t& info)
{
    uint16_t share_len;
    if (!r.read_u16(share_len))
    {
        return;
    }

    while (r.remaining() >= 4)
    {
        uint16_t group = 0;
        uint16_t key_len = 0;
        r.read_u16(group);
        r.read_u16(key_len);

        if (group == reality::tls_consts::group::X25519 && key_len == 32)
        {
            if (r.has(32))
            {
                info.x25519_pub.assign(r.ptr, r.ptr + 32);
                info.is_tls13 = true;
            }
            return;
        }
        r.skip(key_len);
    }
}

}    // namespace mux
