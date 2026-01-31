#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "mux_codec.h"

// 使用中文注释，方便阅读

// 1. Frame Header 测试
TEST(MuxCodecTest, FrameHeader_RoundTrip) {
    // 构造一个典型的 Header
    // Stream ID: 0x12345678, Length: 0xAABB, Command: 0xCC
    mux::frame_header input;
    input.stream_id = 0x12345678;
    input.length = 0xAABB;
    input.command = 0xCC;

    // 编码
    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(input, buffer);

    // 验证编码后的字节大小 (4 + 2 + 1 = 7 bytes)
    ASSERT_EQ(buffer.size(), 7);

    // 验证大端序编码细节
    // StreamID
    EXPECT_EQ(buffer[0], 0x12);
    EXPECT_EQ(buffer[1], 0x34);
    EXPECT_EQ(buffer[2], 0x56);
    EXPECT_EQ(buffer[3], 0x78);
    // Length
    EXPECT_EQ(buffer[4], 0xAA);
    EXPECT_EQ(buffer[5], 0xBB);
    // Command
    EXPECT_EQ(buffer[6], 0xCC);

    // 解码
    mux::frame_header output = mux::mux_codec::decode_header(buffer.data());

    // 验证解码一致性
    EXPECT_EQ(output.stream_id, input.stream_id);
    EXPECT_EQ(output.length, input.length);
    EXPECT_EQ(output.command, input.command);
}

// 2. SYN Payload 测试
TEST(MuxCodecTest, SynPayload_RoundTrip) {
    mux::syn_payload input;
    input.socks_cmd = 0x01; // Connect
    input.addr = "www.google.com";
    input.port = 443;
    input.trace_id = "trace-12345";

    // 编码
    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    // 预期大小: 
    // cmd(1) + addr_len(1) + addr(14) + port(2) + trace_len(1) + trace(11) = 30
    ASSERT_EQ(buffer.size(), 30);

    // 解码
    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.socks_cmd, input.socks_cmd);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_EQ(output.port, input.port);
    EXPECT_EQ(output.trace_id, input.trace_id);
}

TEST(MuxCodecTest, SynPayload_NoTraceId) {
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1";
    input.port = 8080;
    input.trace_id = ""; // 空 trace_id

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.addr, input.addr);
    EXPECT_TRUE(output.trace_id.empty());
}

TEST(MuxCodecTest, SynPayload_Decode_TooShort) {
    // 只有 cmd (1 byte)
    std::vector<std::uint8_t> buffer = {0x01};
    mux::syn_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, SynPayload_Decode_InvalidAddrLen) {
    std::vector<std::uint8_t> buffer;
    buffer.push_back(0x01); // cmd
    buffer.push_back(100);  // addr len = 100
    // 填充一些数据，使总长度达到 4 (超过最小检查)，但不足 104
    buffer.push_back(0x00);
    buffer.push_back(0x00);
    // current len = 4. expected min = 2 + 100 + 2 = 104.
    
    mux::syn_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

TEST(MuxCodecTest, SynPayload_Decode_InvalidTraceIdLen) {
    // 构造一个合法的 addr 部分
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1"; // len 9
    input.port = 80;
    input.trace_id = ""; // 编码时不带 trace
    
    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);
    // encoded size = 1(cmd) + 1(len) + 9(addr) + 2(port) + 1(tracelen=0) = 14 bytes
    
    // 手动修改最后一位 trace_len 为 10，但后面没数据
    buffer.back() = 10; 
    
    mux::syn_payload output;
    // decode logic:
    // current_pos read trace_len. 
    // if len >= current_pos + trace_id_len
    // code checks: if (len > current_pos) -> read len. then check overflow.
    // implementation:
    // if (len > current_pos) {
    //    byte trace_len = data[current_pos];
    //    if (len >= current_pos + 1 + trace_len) ... wait code says:
    //    current_pos++;
    //    if (len >= current_pos + trace_id_len) -> OK
    // }
    // If len is NOT enough, it just skips reading trace_id? 
    // Let's check implementation behavior. Code:
    /*
        if (len > current_pos)
        {
            const std::uint8_t trace_id_len = data[current_pos];
            current_pos++;
            if (len >= current_pos + trace_id_len)
            {
                out.trace_id = ...
            }
        }
    */
    // If buffer ends exactly at trace_id_len byte (e.g. we modified last byte to 10),
    // len > current_pos (yes, at index 13).
    // trace_id_len = 10.
    // current_pos becomes 14.
    // len (14) >= 14 + 10 (24) -> False.
    // So distinct trace_id is NOT populated. But function returns true?
    // The function returns true because it successfully decoded mandatory parts.
    // Trace ID is optional? Protocol design question. 
    // If trace_id_len is present but body missing, is it failure or ignore?
    // Current code ignores it.
    
    // Let's assert that it returns FALSE now because we enforce strict length check
    
    EXPECT_FALSE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
}

// 3. ACK Payload 测试
TEST(MuxCodecTest, AckPayload_RoundTrip) {
    mux::ack_payload input;
    input.socks_rep = 0x00; // Success
    input.bnd_addr = "10.0.0.1";
    input.bnd_port = 12345;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_ack(input, buffer);

    // 解码
    mux::ack_payload output;
    bool success = mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    EXPECT_EQ(output.socks_rep, input.socks_rep);
    EXPECT_EQ(output.bnd_addr, input.bnd_addr);
    EXPECT_EQ(output.bnd_port, input.bnd_port);
}

TEST(MuxCodecTest, AckPayload_Decode_TooShort) {
    std::vector<std::uint8_t> buffer = {0x00};
    mux::ack_payload output;
    EXPECT_FALSE(mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output));
}

// 4. 边界测试：超长地址截断
// mux_codec.cpp 中使用了 std::min(len, 255) 来截断编码
TEST(MuxCodecTest, SynPayload_TruncateLongAddress) {
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    // 构造 300 字节的地址
    input.addr = std::string(300, 'A'); 
    input.port = 80;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    // 解码
    mux::syn_payload output;
    bool success = mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output);

    ASSERT_TRUE(success);
    // 应该被截断为 255
    EXPECT_EQ(output.addr.size(), 255);
}

// 5. 高级边界测试 (Advanced Boundaries)

// 5.1 Frame Header 极限值
TEST(MuxCodecTest, FrameHeader_Limits) {
    mux::frame_header input;
    input.stream_id = 0xFFFFFFFF; // Max uint32
    input.length = 0xFFFF;        // Max uint16
    input.command = 0xFF;         // Max uint8

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_header(input, buffer);

    mux::frame_header output = mux::mux_codec::decode_header(buffer.data());
    EXPECT_EQ(output.stream_id, 0xFFFFFFFF);
    EXPECT_EQ(output.length, 0xFFFF);
    EXPECT_EQ(output.command, 0xFF);
}

// 5.2 SYN Payload 空字段与特殊字符
TEST(MuxCodecTest, SynPayload_EmptyAddr) {
    // 允许空地址吗？根据协议是可以的 length=0
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = ""; 
    input.port = 80;
    
    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);
    // cmd(1) + len(1=0) + port(2) + tracelen(1=0) = 5 bytes
    ASSERT_EQ(buffer.size(), 5);
    
    mux::syn_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.addr, "");
}

TEST(MuxCodecTest, SynPayload_NullBytesInAddr) {
    // 验证 std::string 处理 \0 的能力 (非 C-string)
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

// 5.3 SYN Payload 字段长度极限 (255)
TEST(MuxCodecTest, SynPayload_MaxFieldLengths) {
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = std::string(255, 'A');
    input.port = 65535; // Max port
    input.trace_id = std::string(255, 'T');

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_syn(input, buffer);

    mux::syn_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_syn(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.addr.size(), 255);
    EXPECT_EQ(output.trace_id.size(), 255);
    EXPECT_EQ(output.port, 65535);
}

// 5.4 ACK Payload 恶意截断测试 (逐步减少字节)
TEST(MuxCodecTest, SynPayload_Fuzz_Truncation) {
    mux::syn_payload input;
    input.socks_cmd = 0x01;
    input.addr = "127.0.0.1";
    input.port = 443;
    input.trace_id = "trace";

    std::vector<std::uint8_t> valid_buffer;
    mux::mux_codec::encode_syn(input, valid_buffer);
    // Expected size: 1+1+9+2+1+5 = 19 bytes

    // 尝试解码每一个非法长度 (0 到 18)
    for (size_t len = 0; len < valid_buffer.size(); ++len) {
        mux::syn_payload output;
        // 应该失败，除了特定的可选字段逻辑
        // 我们来看逻辑：
        // decode_syn 严格检查 cmd+len -> addr -> port 
        // 只有 trace_id 是可选的。
        // 如果数据刚好切在 port 之后，trace_len 之前？
        // 逻辑：if (len > current_pos) { read trace_len ... }
        // 意味着如果 port 读完正好没数据了，它认为是没有 trace info，返回成功。
        
        bool result = mux::mux_codec::decode_syn(valid_buffer.data(), len, output);
        
        // 计算关键边界
        size_t pos_after_port = 1 + 1 + 9 + 2; // = 13
        
        if (len == pos_after_port) {
            // 刚好读完 port，没有 trace_len 字节
            // 代码逻辑允许这种情况 (trace optional)
            EXPECT_TRUE(result) << "Length " << len << " should be valid (no trace info)";
        } else if (len > pos_after_port) {
            // 有 trace_len 字节，但 body 不够？
            // 比如 14 字节 (有了 trace_len=5)，但总长不够 14+5=19
            // 代码逻辑：if (len > current_pos) read len; check body size.
            // 所以 14..18 应该都失败
            EXPECT_FALSE(result) << "Length " << len << " should fail (incomplete trace)";
        } else {
            // 不足 13 字节，肯定失败
            EXPECT_FALSE(result) << "Length " << len << " should fail (incomplete header/addr/port)";
        }
    }
}

// 5.5 ACK Payload 边界
TEST(MuxCodecTest, AckPayload_EmptyAddr_MaxPort) {
    mux::ack_payload input;
    input.socks_rep = 0xFF; // Fail code
    input.bnd_addr = "";
    input.bnd_port = 65535;

    std::vector<std::uint8_t> buffer;
    mux::mux_codec::encode_ack(input, buffer);

    mux::ack_payload output;
    ASSERT_TRUE(mux::mux_codec::decode_ack(buffer.data(), buffer.size(), output));
    EXPECT_EQ(output.bnd_addr, "");
    EXPECT_EQ(output.bnd_port, 65535);
}
