#include <array>
#include <cstdint>

#include "tls_record_validation.h"

namespace reality
{

bool is_valid_tls13_compat_ccs(const std::array<std::uint8_t, 5>& header, const std::uint8_t body_byte)
{
    if (header[0] != 0x14)
    {
        return false;
    }
    if (header[1] != 0x03 || header[2] != 0x03)
    {
        return false;
    }
    const std::uint16_t body_len = static_cast<std::uint16_t>((header[3] << 8) | header[4]);
    if (body_len != 1)
    {
        return false;
    }
    return body_byte == 0x01;
}

}    // namespace reality
