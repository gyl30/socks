#include <vector>
#include <cstdint>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#include "protocol.h"

    socks_udp_header header;
    if (socks_codec::decode_udp_header(data, size, header))
    {
        socks_codec::encode_udp_header(header);
    }
    return 0;
}
