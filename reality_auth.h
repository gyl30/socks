#ifndef REALITY_AUTH_H
#define REALITY_AUTH_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace reality
{
constexpr size_t AUTH_PAYLOAD_LEN = 16;
constexpr size_t SHORT_ID_MAX_LEN = 8;

struct auth_payload
{
    uint8_t version = 1;
    std::vector<uint8_t> short_id;
    uint32_t timestamp = 0;
    std::array<uint8_t, 2> nonce = {0, 0};
};

[[nodiscard]] bool build_auth_payload(const std::vector<uint8_t>& short_id,
                                      uint32_t timestamp,
                                      const std::array<uint8_t, 2>& nonce,
                                      std::array<uint8_t, AUTH_PAYLOAD_LEN>& out);

[[nodiscard]] std::optional<auth_payload> parse_auth_payload(std::span<const uint8_t> payload);

}    // namespace reality

#endif
