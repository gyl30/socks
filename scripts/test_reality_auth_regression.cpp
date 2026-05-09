#include <array>
#include <cstdint>
#include <iostream>
#include <string>

#include "reality/handshake/auth.h"

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

}    // namespace

int main()
{
    constexpr std::array<uint8_t, 3> version{1, 0, 0};
    constexpr uint32_t timestamp = 0x01020304U;

    std::array<uint8_t, reality::kAuthPayloadLen> payload{};
    const bool build_ok = require(reality::build_auth_payload(version, timestamp, payload), "build_auth_payload failed");
    const bool version_ok = require(payload[0] == 1 && payload[1] == 0 && payload[2] == 0 && payload[3] == 0, "payload version layout invalid");
    const bool timestamp_ok = require(
        payload[4] == 0x01 && payload[5] == 0x02 && payload[6] == 0x03 && payload[7] == 0x04, "payload timestamp layout invalid");

    bool reserved_zero_ok = true;
    for (std::size_t i = 8; i < payload.size(); ++i)
    {
        reserved_zero_ok = reserved_zero_ok && (payload[i] == 0);
    }
    reserved_zero_ok = require(reserved_zero_ok, "payload reserved bytes should default to zero");

    const auto parsed = reality::parse_auth_payload(payload);
    const bool parse_ok = require(parsed.has_value(), "parse_auth_payload should accept zero reserved bytes");
    const bool parsed_reserved_ok = require(parsed.has_value() && reality::has_zero_reserved_bytes(*parsed), "parsed payload reserved bytes should be zero");

    payload[8] = 0x7F;
    const auto parsed_non_zero = reality::parse_auth_payload(payload);
    const bool parse_non_zero_ok = require(parsed_non_zero.has_value(), "parse_auth_payload should preserve non-zero reserved bytes");
    const bool reserved_validation_ok = require(
        parsed_non_zero.has_value() && !reality::has_zero_reserved_bytes(*parsed_non_zero), "non-zero reserved bytes should fail validation");

    payload[3] = 0x01;
    const auto invalid_reserved_marker = reality::parse_auth_payload(payload);
    const bool invalid_marker_ok = require(!invalid_reserved_marker.has_value(), "payload[3] must stay zero");

    return build_ok && version_ok && timestamp_ok && reserved_zero_ok && parse_ok && parsed_reserved_ok && parse_non_zero_ok &&
                   reserved_validation_ok && invalid_marker_ok
               ? 0
               : 1;
}
