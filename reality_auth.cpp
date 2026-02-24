#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <algorithm>

#include "reality_auth.h"

namespace reality
{

bool build_auth_payload(const std::vector<std::uint8_t>& short_id,
                        const std::array<std::uint8_t, 3>& version,
                        std::uint32_t timestamp,
                        std::array<std::uint8_t, kAuthPayloadLen>& out)
{
    if (short_id.size() > kShortIdMaxLen)
    {
        return false;
    }

    out.fill(0);

    out[0] = version[0];
    out[1] = version[1];
    out[2] = version[2];
    out[3] = 0;

    out[4] = static_cast<std::uint8_t>((timestamp >> 24) & 0xFF);
    out[5] = static_cast<std::uint8_t>((timestamp >> 16) & 0xFF);
    out[6] = static_cast<std::uint8_t>((timestamp >> 8) & 0xFF);
    out[7] = static_cast<std::uint8_t>(timestamp & 0xFF);

    for (std::size_t i = 0; i < short_id.size(); ++i)
    {
        out[8 + i] = short_id[i];
    }

    return true;
}

std::optional<auth_payload> parse_auth_payload(std::span<const std::uint8_t> payload)
{
    if (payload.size() != kAuthPayloadLen)
    {
        return std::nullopt;
    }
    if (payload[3] != 0x00)
    {
        return std::nullopt;
    }

    auth_payload out;

    out.version_x = payload[0];
    out.version_y = payload[1];
    out.version_z = payload[2];

    out.timestamp = (static_cast<std::uint32_t>(payload[4]) << 24) | (static_cast<std::uint32_t>(payload[5]) << 16) |
                    (static_cast<std::uint32_t>(payload[6]) << 8) | static_cast<std::uint32_t>(payload[7]);

    std::copy(payload.begin() + 8, payload.begin() + 16, out.short_id.begin());

    return out;
}

}    // namespace reality
