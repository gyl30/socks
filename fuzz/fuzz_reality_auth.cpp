#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

#include "reality_auth.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::span<const uint8_t> input(data, size);
    auto payload = reality::parse_auth_payload(input);
    if (payload)
    {
    }

    return 0;
}
