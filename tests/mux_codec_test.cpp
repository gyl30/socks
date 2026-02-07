#include <vector>
#include <string>
#include <cstdint>

#include <gtest/gtest.h>

#include "mux_codec.h"

TEST(MuxCodecTest, FrameHeader_RoundTrip)
{
    mux::frame_header input;
    input.stream_id = 0x12345678;
    input.length = 0xAABB;
    input.command = 0xCC;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(input, buffer);

    ASSERT_EQ(buffer.size(), 7);

    EXPECT_EQ(buffer[0], 0x12);
    EXPECT_EQ(buffer[1], 0x34);
    EXPECT_EQ(buffer[2], 0x56);
    EXPECT_EQ(buffer[3], 0x78);

    EXPECT_EQ(buffer[4], 0xAA);
    EXPECT_EQ(buffer[5], 0xBB);

    EXPECT_EQ(buffer[6], 0xCC);

    mux::frame_header output;
    bool success = mux::mux_codec::decode_header(buffer.data(), buffer.size(), output);
    ASSERT_TRUE(success);

    EXPECT_EQ(output.stream_id, input.stream_id);
    EXPECT_EQ(output.length, input.length);
    EXPECT_EQ(output.command, input.command);
}

TEST(MuxCodecTest, SynPayload_RoundTrip)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "www.google.com";
    input.port = 443;
    input.trace_id = "trace-12345";

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    ASSERT_EQ(buffer.size(), 30);

    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.socks_cmd, input.socks_cmd);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
    EXPECT_EQ(output.trace_id, input.trace_id);
}

TEST(MuxCodecTest, SynPayload_NoTraceId)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1";
    input.port = 8080;
    input.trace_id = "";

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_TRUE(output.trace_id.empty());
}

TEST(MuxCodecTest, SynPayload_Decode_TooShort)
{
    std::vector<std::uint8_t> buffer = {0x01};
    mux::syn_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, SynPayload_Decode_InvalidAddrLen)
{
    std::vector<std::uint8_t> buffer;
    buffer.push_back(0x01);
    buffer.push_back(100);

    buffer.push_back(0x00);
    buffer.push_back(0x00);

    mux::syn_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, SynPayload_Decode_InvalidTraceIdLen)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1";
    input.port = 80;
    input.trace_id = "";

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    buffer.back() = 10;

    mux::syn_payload output;

    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, AckPayload_RoundTrip)
{
    mux::ack_payload input;
    input.socks_rep = 0x00;
    input.bnd_addr = "10.0.0.1";
    input.bnd_port = 12345;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_ack(input, buffer);

    mux::ack_payload output;
    bool success = mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.socks_rep, input.socks_rep);
    EXPECT_EQ(output.bnd_addr, input.bnd_addr);
    EXPECT_EQ(output.bnd_port, input.bnd_port);
}

TEST(MuxCodecTest, AckPayload_Decode_TooShort)
{
    std::vector<std::uint8_t> buffer = {0x00};
    mux::ack_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, SynPayload_TruncateLongAddress)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;

    input.addr = std::string(300, 'A');
    input.port = 80;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);

    EXPECT_EQ(output.addr.size(), 255);
}

TEST(MuxCodecTest, FrameHeader_Limits)
{
    mux::frame_header input;
    input.stream_id = 0xFFFFFFFF;
    input.length = 0xFFFF;
    input.command = 0xFF;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(input, buffer);

    mux::frame_header output;
    bool success = mux::mux_codec::decode_header(buffer.data(), buffer.size(), output);
    ASSERT_TRUE(success);
    EXPECT_EQ(output.stream_id, 0xFFFFFFFF);
    EXPECT_EQ(output.length, 0xFFFF);
    EXPECT_EQ(output.command, 0xFF);
}

TEST(MuxCodecTest, SynPayload_EmptyAddr)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "";
    input.port = 80;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    ASSERT_EQ(buffer.size(), 5);

    mux::syn_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.addr, "");
}

TEST(MuxCodecTest, SynPayload_NullBytesInAddr)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = std::string("a\0b", 3);
    input.port = 80;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.addr.size(), 3);
    EXPECT_EQ(output.addr[1], '\0');
}

TEST(MuxCodecTest, SynPayload_MaxFieldLengths)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = std::string(255, 'A');
    input.port = 65535;
    input.trace_id = std::string(255, 'T');

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.addr.size(), 255);
    EXPECT_EQ(output.trace_id.size(), 255);
    EXPECT_EQ(output.port, 65535);
}

TEST(MuxCodecTest, SynPayload_Fuzz_Truncation)
{
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1";
    input.port = 443;
    input.trace_id = "trace";

    std::vector<std::uint8_t> valid_buffer;
    mux::mux_codec::encode_syn(input, valid_buffer);

    for (std::size_t len = 0; len < valid_buffer.size(); ++len)
    {
        mux::syn_payload output;

        bool result = mux::mux_codec::decode_syn(valid_buffer.data(), len, output);

        std::size_t pos_after_port = 1 + 1 + 9 + 2;

        if (len == pos_after_port)
        {
            EXPECT_TRUE(result) << "Length " << len << " should be valid (no trace info)";
        }
        else if (len > pos_after_port)
        {
            EXPECT_FALSE(result) << "Length " << len << " should fail (incomplete trace)";
        }
        else
        {
            EXPECT_FALSE(result) << "Length " << len << " should fail (incomplete header/addr/port)";
        }
    }
}

TEST(MuxCodecTest, AckPayload_EmptyAddr_MaxPort)
{
    mux::ack_payload input;
    input.socks_rep = 0xFF;
    input.bnd_addr = "";
    input.bnd_port = 65535;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_ack(input, buffer);

    mux::ack_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.bnd_addr, "");
    EXPECT_EQ(output.bnd_port, 65535);
}

TEST(MuxCodecTest, FrameHeader_ZeroLength)
{
    mux::frame_header input;
    input.stream_id = 1;
    input.length = 0;
    input.command = mux::kCmdDat;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(input, buffer);
    ASSERT_EQ(buffer.size(), 7);

    mux::frame_header output;
    ASSERT_TRUE(mux::mux_codec::decode_header(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.length, 0);
}

TEST(MuxCodecTest, FrameHeader_DecodeShortBuffer)
{
    std::vector<std::uint8_t> buffer = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
    mux::frame_header output;
    EXPECT_FALSE(mux::mux_codec::decode_header(buffer.data(), buffer.size(), output));
}
