#include <cctype>
#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "tls/crypto_util.h"
#include "reality/config_validation.h"

namespace reality
{

namespace
{

[[nodiscard]] bool is_hex_char(const char ch)
{
    return std::isxdigit(static_cast<unsigned char>(ch)) != 0;
}

}    // namespace

std::string normalize_fingerprint_name(const std::string_view name)
{
    std::string normalized_name;
    normalized_name.reserve(name.size());
    for (const char ch : name)
    {
        if (ch == '-' || ch == ' ')
        {
            normalized_name.push_back('_');
            continue;
        }
        normalized_name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized_name;
}

bool try_parse_fingerprint_type(const std::string_view name, std::optional<fingerprint_type>& out_fingerprint_type)
{
    const auto normalized_name = normalize_fingerprint_name(name);
    if (normalized_name.empty() || normalized_name == "random")
    {
        out_fingerprint_type.reset();
        return true;
    }

    struct entry
    {
        const char* name;
        reality::fingerprint_type type;
    };

    static const entry kEntries[] = {
        {.name = "chrome", .type = fingerprint_type::kChrome120},
        {.name = "chrome_120", .type = fingerprint_type::kChrome120},
        {.name = "chrome_mlkem", .type = fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_mlkem768", .type = fingerprint_type::kChrome120Mlkem768},
        {.name = "chrome_hybrid", .type = fingerprint_type::kChrome120Mlkem768},
        {.name = "firefox", .type = fingerprint_type::kFirefox120},
        {.name = "firefox_120", .type = fingerprint_type::kFirefox120},
        {.name = "ios", .type = fingerprint_type::kIOS14},
        {.name = "ios_14", .type = fingerprint_type::kIOS14},
        {.name = "android", .type = fingerprint_type::kAndroid11OkHttp},
        {.name = "android_11_okhttp", .type = fingerprint_type::kAndroid11OkHttp},
    };

    for (const auto& entry : kEntries)
    {
        if (normalized_name == entry.name)
        {
            out_fingerprint_type = entry.type;
            return true;
        }
    }

    return false;
}

hex_field_status validate_hex_field(const std::string_view value, const std::size_t min_bytes, const std::size_t max_bytes)
{
    if (value.empty())
    {
        return min_bytes == 0 ? hex_field_status::kOk : hex_field_status::kEmpty;
    }

    if ((value.size() % 2) != 0)
    {
        return hex_field_status::kOddLength;
    }

    for (const char ch : value)
    {
        if (!is_hex_char(ch))
        {
            return hex_field_status::kInvalidChar;
        }
    }

    const auto byte_count = value.size() / 2;
    if (byte_count < min_bytes || byte_count > max_bytes)
    {
        return hex_field_status::kLengthInvalid;
    }

    return hex_field_status::kOk;
}

hex_field_status decode_hex_field(const std::string_view value,
                                  const std::size_t min_bytes,
                                  const std::size_t max_bytes,
                                  std::vector<uint8_t>& output)
{
    output.clear();

    const auto validation_status = validate_hex_field(value, min_bytes, max_bytes);
    if (validation_status != hex_field_status::kOk)
    {
        return validation_status;
    }

    output = tls::crypto_util::hex_to_bytes(std::string(value));
    if (output.empty() || (output.size() * 2) != value.size())
    {
        output.clear();
        return hex_field_status::kInvalidChar;
    }

    return hex_field_status::kOk;
}

}    // namespace reality
