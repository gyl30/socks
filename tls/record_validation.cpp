#include <array>
#include <cstdint>

#include "tls/core.h"
#include "tls/record_validation.h"

namespace tls
{

bool is_valid_tls13_compat_ccs(const std::array<uint8_t, 5>& header, uint8_t body_byte)
{
    if (header[0] != 0x14)
    {
        return false;
    }
    if (header[1] != 0x03 || header[2] != 0x03)
    {
        return false;
    }
    const auto body_len = tls::get_record_payload_len(header.data());
    if (body_len != 1)
    {
        return false;
    }
    return body_byte == 0x01;
}

}    // namespace tls
