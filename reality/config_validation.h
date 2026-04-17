#ifndef REALITY_CONFIG_VALIDATION_H
#define REALITY_CONFIG_VALIDATION_H

#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "reality/handshake/fingerprint.h"

namespace reality
{

enum class hex_field_status
{
    kOk,
    kEmpty,
    kOddLength,
    kInvalidChar,
    kLengthInvalid,
};

[[nodiscard]] std::string normalize_fingerprint_name(std::string_view name);

[[nodiscard]] bool try_parse_fingerprint_type(std::string_view name, std::optional<fingerprint_type>& fingerprint_type);

[[nodiscard]] hex_field_status validate_hex_field(std::string_view value, std::size_t min_bytes, std::size_t max_bytes);

[[nodiscard]] hex_field_status decode_hex_field(std::string_view value,
                                                std::size_t min_bytes,
                                                std::size_t max_bytes,
                                                std::vector<uint8_t>& output);

}    // namespace reality

#endif
