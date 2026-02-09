#include <vector>
#include <cstddef>
#include <cstdint>

#include "mux_codec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 7)
    {
        return 0;
    }

    mux::frame_header header;
    if (mux::mux_codec::decode_header(data, size, header))
    {
        std::vector<uint8_t> buffer;
        mux::mux_codec::encode_header(header, buffer);
    }

    mux::syn_payload syn;
    if (mux::mux_codec::decode_syn(data, size, syn))
    {
    }

    mux::ack_payload ack;
    if (mux::mux_codec::decode_ack(data, size, ack))
    {
    }

    return 0;
}
