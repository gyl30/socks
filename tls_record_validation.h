#ifndef TLS_RECORD_VALIDATION_H
#define TLS_RECORD_VALIDATION_H

#include <array>
#include <cstdint>

namespace reality
{

[[nodiscard]] bool is_valid_tls13_compat_ccs(const std::array<std::uint8_t, 5>& header, std::uint8_t body_byte);

}    // namespace reality

#endif
