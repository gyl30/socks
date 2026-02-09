#include <vector>
#include <cstdint>
#include <stddef.h>

#include "protocol.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    socks5_request req;
    if (socks_codec::decode_socks5_request(data, size, req))
    {
    }

    socks5_auth_request auth;
    if (socks_codec::decode_socks5_auth_request(data, size, auth))
    {
    }

    return 0;
}
