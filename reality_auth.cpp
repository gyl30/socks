#include "reality_auth.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace reality
{

bool build_auth_payload(const std::vector<uint8_t>& short_id,
                        uint32_t timestamp,
                        const std::array<uint8_t, 2>& nonce,
                        std::array<uint8_t, AUTH_PAYLOAD_LEN>& out)
{
    if (short_id.size() > SHORT_ID_MAX_LEN)
    {
        return false;
    }

    out.fill(0);
    out[0] = 1;
    out[1] = static_cast<uint8_t>(short_id.size());

    for (size_t i = 0; i < short_id.size(); ++i)
    {
        out[2 + i] = short_id[i];
    }

    out[10] = static_cast<uint8_t>((timestamp >> 24) & 0xFF);
    out[11] = static_cast<uint8_t>((timestamp >> 16) & 0xFF);
    out[12] = static_cast<uint8_t>((timestamp >> 8) & 0xFF);
    out[13] = static_cast<uint8_t>(timestamp & 0xFF);

    out[14] = nonce[0];
    out[15] = nonce[1];

    return true;
}

std::optional<auth_payload> parse_auth_payload(std::span<const uint8_t> payload)
{
    if (payload.size() != AUTH_PAYLOAD_LEN)
    {
        return std::nullopt;
    }

    auth_payload out;
    out.version = payload[0];
    if (out.version != 1)
    {
        return std::nullopt;
    }

    const uint8_t short_len = payload[1];
    if (short_len > SHORT_ID_MAX_LEN)
    {
        return std::nullopt;
    }

    out.short_id.assign(payload.begin() + 2, payload.begin() + 2 + short_len);

    out.timestamp = (static_cast<uint32_t>(payload[10]) << 24) | (static_cast<uint32_t>(payload[11]) << 16) |
                    (static_cast<uint32_t>(payload[12]) << 8) | static_cast<uint32_t>(payload[13]);

    out.nonce = {payload[14], payload[15]};
    return out;
}

}    // namespace reality
