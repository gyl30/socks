#include <vector>
#include <cstdint>

#include <gtest/gtest.h>

#include "mux_codec.h"
#include "mux_protocol.h"

namespace
{

TEST(ProtocolEdgeTest, HugePayloadEncoding)
{
    mux::frame_header header;
    header.stream_id = 1;
    header.command = mux::kCmdDat;
    header.length = 0xFFFF;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(header, buffer);
    ASSERT_EQ(buffer.size(), 7);
    EXPECT_EQ(buffer[4], 0xFF);
    EXPECT_EQ(buffer[5], 0xFF);
}

TEST(ProtocolEdgeTest, StreamIdBoundary)
{
    mux::frame_header header;
    header.stream_id = 0xFFFFFFFF;
    header.command = mux::kCmdSyn;
    header.length = 10;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(header, buffer);

    mux::frame_header decoded;
    ASSERT_TRUE(mux::mux_codec::decode_header(buffer.data(), buffer.size(), decoded));
    EXPECT_EQ(decoded.stream_id, 0xFFFFFFFF);
}

TEST(ProtocolEdgeTest, InvalidCommandDecoding)
{
    std::vector<std::uint8_t> buffer = {0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x99};
    mux::frame_header decoded;
    ASSERT_TRUE(mux::mux_codec::decode_header(buffer.data(), buffer.size(), decoded));
    EXPECT_EQ(decoded.command, 0x99);
}

}    // namespace
