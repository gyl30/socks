#ifndef REALITY_CONFIG_VALIDATION_H
#define REALITY_CONFIG_VALIDATION_H

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

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

[[nodiscard]] bool is_supported_fingerprint_name(std::string_view name);

[[nodiscard]] hex_field_status validate_hex_field(std::string_view value, std::size_t min_bytes, std::size_t max_bytes);

[[nodiscard]] hex_field_status decode_hex_field(std::string_view value,
                                                std::size_t min_bytes,
                                                std::size_t max_bytes,
                                                std::vector<uint8_t>& output);

}    // namespace reality

#endif
