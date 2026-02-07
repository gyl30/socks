#include <span>
#include <vector>
#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#include "ch_parser.h"

    if (size == 0)
        return 0;

    std::vector<uint8_t> input(data, data + size);
    mux::ch_parser::parse(input);

    return 0;
}
