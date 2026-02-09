#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

#include "ch_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
    {
        return 0;
    }

    std::vector<uint8_t> input(data, data + size);
    auto hello = mux::ch_parser::parse(input);
    (void)hello;

    return 0;
}
