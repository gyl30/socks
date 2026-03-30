#ifndef REALITY_AUTH_H
#define REALITY_AUTH_H

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace reality
{

constexpr std::size_t kAuthPayloadLen = 16;
constexpr std::size_t kShortIdMaxLen = 8;

struct auth_payload
{
    uint8_t version_x = 1;
    uint8_t version_y = 0;
    uint8_t version_z = 0;
    uint32_t timestamp = 0;
    std::array<uint8_t, kShortIdMaxLen> short_id = {};
};

[[nodiscard]] bool build_auth_payload(const std::vector<uint8_t>& short_id,
                                      const std::array<uint8_t, 3>& version,
                                      uint32_t timestamp,
                                      std::array<uint8_t, kAuthPayloadLen>& out);

[[nodiscard]] std::optional<auth_payload> parse_auth_payload(std::span<const uint8_t> payload);

}    // namespace reality

#endif
