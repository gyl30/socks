#include <cstdint>
#include <vector>

#include "ch_parser.h"
#include "reality_core.h"

namespace mux
{

client_hello_info ch_parser::parse(const std::vector<std::uint8_t>& buf)
{
    client_hello_info info;
    reader r(buf);

    if (r.remaining() < 5)
    {
        return info;
    }

    std::uint8_t record_type = 0;
    if (!r.read_u8(record_type) || record_type != 0x16)
    {
        return info;
    }

    if (!r.skip(2 + 2))    // Skip version and length
    {
        return info;
    }

    std::uint8_t handshake_type = 0;
    if (!r.read_u8(handshake_type) || handshake_type != 0x01)
    {
        return info;
    }

    if (!r.skip(3))    // Skip handshake length
    {
        return info;
    }

    if (!r.skip(2))    // Skip version (0x0303)
    {
        return info;
    }

    if (!r.read_vector(info.random, 32))
    {
        return info;
    }

    std::uint8_t sid_len = 0;
    if (!r.read_u8(sid_len))
    {
        return info;
    }

    info.sid_offset = static_cast<std::uint32_t>(r.offset());
    if (sid_len > 0)
    {
        if (!r.read_vector(info.session_id, sid_len))
        {
            return info;
        }
    }

    std::uint16_t cs_len = 0;
    if (!r.read_u16(cs_len))
    {
        return info;
    }
    if (!r.skip(cs_len))
    {
        return info;
    }

    std::uint8_t comp_len = 0;
    if (!r.read_u8(comp_len))
    {
        return info;
    }
    if (!r.skip(comp_len))
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
        std::uint16_t len = 0;
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

        if (!list_r.read_u8(type) || !list_r.read_u16(len))
        {
            break;
        }

        if (type == 0x00)    // host_name
        {
            if (list_r.has(len))
            {
                info.sni.assign(reinterpret_cast<const char*>(list_r.data()), len);
            }
            return;
        }

        if (!list_r.skip(len))
        {
            break;
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

    while (r.remaining() >= 4)
    {
        std::uint16_t group = 0;
        std::uint16_t len = 0;
        if (!r.read_u16(group) || !r.read_u16(len))
        {
            break;
        }

        if (group == 0x001d)    // X25519
        {
            if (len == 32)
            {
                if (r.has(32))
                {
                    info.x25519_pub.assign(r.data(), r.data() + 32);
                    info.is_tls13 = true;
                }
            }
            return;
        }

        if (!r.skip(len))
        {
            break;
        }
    }
}

}    // namespace mux