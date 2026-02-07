#include <span>
#include <vector>
#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#include "reality_auth.h"

    if (size == 0)
        return 0;

    std::span<const uint8_t> input(data, size);
    reality::parse_auth_payload(input);

    return 0;
}
