#include <cstddef>
#include <cstdint>

#include "protocol.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    socks_udp_header header;
    if (socks_codec::decode_udp_header(data, size, header))
    {
        auto bytes = socks_codec::encode_udp_header(header);
        (void)bytes;
    }
    return 0;
}
