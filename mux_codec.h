#ifndef MUX_CODEC_H
#define MUX_CODEC_H

#include <vector>
#include <cstddef>
#include <cstdint>

#include "mux_protocol.h"

namespace mux
{

class mux_codec
{
   public:
    static void encode_header(const frame_header& h, std::vector<std::uint8_t>& buf);
    static bool decode_header(const std::uint8_t* buf, std::size_t len, frame_header& out);

    static void encode_syn(const syn_payload& p, std::vector<std::uint8_t>& buf);

    [[nodiscard]] static bool decode_syn(const std::uint8_t* data, std::size_t len, syn_payload& out);

    static void encode_ack(const ack_payload& p, std::vector<std::uint8_t>& buf);

    [[nodiscard]] static bool decode_ack(const std::uint8_t* data, std::size_t len, ack_payload& out);
};

}    // namespace mux

#endif
