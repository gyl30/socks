#ifndef TLS_RECORD_VALIDATION_H
#define TLS_RECORD_VALIDATION_H

#include <array>
#include <cstdint>

namespace tls
{

[[nodiscard]] bool is_valid_tls13_compat_ccs(const std::array<uint8_t, 5>& header, uint8_t body_byte);

}    // namespace tls

#endif
