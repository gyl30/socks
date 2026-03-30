#ifndef MUX_CODEC_H
#define MUX_CODEC_H

#include <span>
#include <vector>

#include "mux_protocol.h"

namespace mux
{

class mux_codec
{
   public:
    static void encode_header(const frame_header& h, std::vector<uint8_t>& buf);
    static void decode_header(const uint8_t* buf, frame_header& out);
    [[nodiscard]] static std::vector<uint8_t> encode_frame(const frame_header& h, std::span<const uint8_t> payload);
    static void decode_frames(std::vector<uint8_t>& pending,
                              std::span<const uint8_t> data,
                              std::size_t max_buffer,
                              std::vector<mux_frame>& frames,
                              boost::system::error_code& ec);

    [[nodiscard]] static bool encode_syn(const syn_payload& p, std::vector<uint8_t>& buf);

    [[nodiscard]] static bool decode_syn(const uint8_t* data, std::size_t len, syn_payload& out);

    [[nodiscard]] static bool encode_ack(const ack_payload& p, std::vector<uint8_t>& buf);

    [[nodiscard]] static bool decode_ack(const uint8_t* data, std::size_t len, ack_payload& out);
};

}    // namespace mux

#endif
