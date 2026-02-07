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
    std::uint8_t version_x = 1;
    std::uint8_t version_y = 0;
    std::uint8_t version_z = 0;
    std::uint32_t timestamp = 0;
    std::array<std::uint8_t, kShortIdMaxLen> short_id = {};
};

[[nodiscard]] bool build_auth_payload(const std::vector<std::uint8_t>& short_id,
                                      std::uint32_t timestamp,
                                      std::array<std::uint8_t, kAuthPayloadLen>& out);

[[nodiscard]] std::optional<auth_payload> parse_auth_payload(std::span<const std::uint8_t> payload);

}    // namespace reality

#endif
