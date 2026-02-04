#ifndef REALITY_AUTH_H
#define REALITY_AUTH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace reality
{

constexpr std::size_t AUTH_PAYLOAD_LEN = 16;
constexpr std::size_t SHORT_ID_MAX_LEN = 8;

struct auth_payload
{
    std::uint8_t version = 1;
    std::vector<std::uint8_t> short_id;
    std::uint32_t timestamp = 0;
    std::array<std::uint8_t, 2> nonce = {0, 0};
};

[[nodiscard]] bool build_auth_payload(const std::vector<std::uint8_t>& short_id,
                                      std::uint32_t timestamp,
                                      const std::array<std::uint8_t, 2>& nonce,
                                      std::array<std::uint8_t, AUTH_PAYLOAD_LEN>& out);

[[nodiscard]] std::optional<auth_payload> parse_auth_payload(std::span<const std::uint8_t> payload);

}    // namespace reality

#endif