#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

#include "mux_codec.h"
#include "mux_protocol.h"
namespace
{

constexpr std::array<uint8_t, 5> kCommands = {mux::kCmdSyn, mux::kCmdAck, mux::kCmdDat, mux::kCmdFin, mux::kCmdRst};

std::vector<uint8_t> make_buffer(const uint8_t* data, std::size_t size)
{
    std::vector<uint8_t> out;
    if (data != nullptr && size != 0)
    {
        out.assign(data, data + size);
    }
    return out;
}

uint16_t read_u16(const uint8_t* data, std::size_t size, std::size_t offset)
{
    if (data == nullptr || size == 0)
    {
        return 0;
    }
    const auto hi = static_cast<uint16_t>(data[offset % size]);
    const auto lo = static_cast<uint16_t>(data[(offset + 1) % size]);
    return static_cast<uint16_t>((hi << 8) | lo);
}

uint32_t read_u32(const uint8_t* data, std::size_t size, std::size_t offset)
{
    if (data == nullptr || size == 0)
    {
        return 0;
    }
    const auto b0 = static_cast<uint32_t>(data[offset % size]);
    const auto b1 = static_cast<uint32_t>(data[(offset + 1) % size]);
    const auto b2 = static_cast<uint32_t>(data[(offset + 2) % size]);
    const auto b3 = static_cast<uint32_t>(data[(offset + 3) % size]);
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
}

std::string make_printable_text(const uint8_t* data, std::size_t size, std::size_t offset, std::size_t max_len, const char* fallback)
{
    static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/";
    if (data == nullptr || size == 0)
    {
        return fallback;
    }

    const std::size_t len = std::min<std::size_t>(1 + static_cast<std::size_t>(data[offset % size] % max_len), max_len);
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        out.push_back(kAlphabet[data[(offset + i) % size] % (sizeof(kAlphabet) - 1)]);
    }
    return out;
}

}    // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size)
{
    const auto raw = make_buffer(data, size);
    const auto* raw_ptr = raw.empty() ? nullptr : raw.data();
    if (size < mux::kHeaderSize)
    {
        return 0;
    }
    mux::frame_header header{};
    (void)mux::mux_codec::decode_header(raw_ptr, header);

    if (!raw.empty())
    {
        header.stream_id = read_u32(data, size, 0);
        header.length = static_cast<uint16_t>(raw.size());
        header.command = kCommands[static_cast<std::size_t>(data[0]) % kCommands.size()];

        std::vector<uint8_t> encoded_header;
        mux::mux_codec::encode_header(header, encoded_header);

        mux::frame_header decoded_header{};
        (void)mux::mux_codec::decode_header(encoded_header.data(), decoded_header);
    }

    if (raw.size() >= mux::kHeaderSize)
    {
        const auto* body = raw_ptr + mux::kHeaderSize;
        const auto body_len = raw.size() - mux::kHeaderSize;

        mux::syn_payload syn_from_raw{};
        (void)mux::mux_codec::decode_syn(body, body_len, syn_from_raw);

        mux::ack_payload ack_from_raw{};
        (void)mux::mux_codec::decode_ack(body, body_len, ack_from_raw);
    }

    mux::syn_payload synthetic_syn{};
    synthetic_syn.socks_cmd = raw.empty() ? mux::kCmdSyn : kCommands[static_cast<std::size_t>(data[0]) % kCommands.size()];
    synthetic_syn.addr = make_printable_text(data, size, 1, 64, "example.com");
    synthetic_syn.port = read_u16(data, size, 2);

    std::vector<uint8_t> syn_buf;
    if (mux::mux_codec::encode_syn(synthetic_syn, syn_buf))
    {
        mux::syn_payload decoded_syn{};
        (void)mux::mux_codec::decode_syn(syn_buf.data(), syn_buf.size(), decoded_syn);
    }

    mux::ack_payload synthetic_ack{};
    synthetic_ack.socks_rep = raw.empty() ? 0x00 : data[0];
    synthetic_ack.bnd_addr = make_printable_text(data, size, 6, 64, "127.0.0.1");
    synthetic_ack.bnd_port = read_u16(data, size, 8);

    std::vector<uint8_t> ack_buf;
    if (mux::mux_codec::encode_ack(synthetic_ack, ack_buf))
    {
        mux::ack_payload decoded_ack{};
        (void)mux::mux_codec::decode_ack(ack_buf.data(), ack_buf.size(), decoded_ack);
    }

    return 0;
}
