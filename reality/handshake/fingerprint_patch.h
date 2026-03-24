#ifndef REALITY_FINGERPRINT_PATCH_H
#define REALITY_FINGERPRINT_PATCH_H

#include <cstdint>

#include "reality/handshake/fingerprint.h"

namespace reality
{

void fingerprint_append_key_share_group(fingerprint_template& spec, std::uint16_t group);

void fingerprint_append_cipher_suite(fingerprint_template& spec, std::uint16_t cipher_suite);

}    // namespace reality

#endif
