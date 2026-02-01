#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "ch_parser.h"

using namespace mux;

// 构造 Client Hello 的辅助类
class ClientHelloBuilder
{
   public:
    std::vector<uint8_t> buffer;

    ClientHelloBuilder()
    {
        // 记录头 (内容类型 0x16, 版本 0x0301)
        add_u8(0x16);
        add_u16(0x0301);
        // 长度占位符
        add_u16(0);
    }

    void start_handshake()
    {
        // 握手头 (类型 0x01 Client Hello)
        add_u8(0x01);
        // 握手长度占位符 (3 字节)
        add_u8(0);
        add_u8(0);
        add_u8(0);

        // 版本 (CH 中为 0x0303 即 TLS 1.2)
        add_u16(0x0303);

        // 随机数 (32 字节)
        for (int i = 0; i < 32; ++i) add_u8(0xAA);

        // Session ID 长度 (0)
        add_u8(0);

        // 加密套件长度 (2 字节) + 1 个套件 (0x1302 TLS_AES_256_GCM_SHA384)
        add_u16(2);
        add_u16(0x1302);

        // 压缩方法长度 (1) + null (0)
        add_u8(1);
        add_u8(0);

        // 扩展长度占位符
        ext_len_pos = buffer.size();
        add_u16(0);
    }

    void add_sni(const std::string& hostname)
    {
        add_u16(0x0000);    // SNI 类型
        size_t len_pos = buffer.size();
        add_u16(0);    // 长度占位符

        size_t list_len_pos = buffer.size();
        add_u16(0);    // 列表长度占位符

        add_u8(0);    // 主机名类型
        add_u16(hostname.size());
        for (char c : hostname) add_u8(c);

        uint16_t total_len = buffer.size() - list_len_pos - 2;
        poke_u16(list_len_pos, total_len);

        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void add_key_share()
    {
        add_u16(0x0033);    // Key Share 类型
        size_t len_pos = buffer.size();
        add_u16(0);    // 长度占位符

        size_t share_len_pos = buffer.size();
        add_u16(0);    // Share 列表长度占位符

        add_u16(0x001d);                              // Group X25519
        add_u16(32);                                  // Key 长度
        for (int i = 0; i < 32; ++i) add_u8(0xBB);    // 伪造 Key

        uint16_t list_len = buffer.size() - share_len_pos - 2;
        poke_u16(share_len_pos, list_len);

        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void finish()
    {
        // 修正扩展长度
        if (ext_len_pos > 0)
        {
            uint16_t ext_len = buffer.size() - ext_len_pos - 2;
            poke_u16(ext_len_pos, ext_len);
        }

        // 修正握手长度 (偏移量 6, 7, 8 处的 3 字节)
        // Record(5) + Type(1) + Len(3) ...
        size_t handshake_len = buffer.size() - 5 - 4;
        buffer[6] = (handshake_len >> 16) & 0xFF;
        buffer[7] = (handshake_len >> 8) & 0xFF;
        buffer[8] = handshake_len & 0xFF;

        // 修正记录长度 (偏移量 3, 4)
        size_t record_len = buffer.size() - 5;
        poke_u16(3, record_len);
    }

   private:
    size_t ext_len_pos = 0;

    void add_u8(uint8_t v) { buffer.push_back(v); }
    void add_u16(uint16_t v)
    {
        buffer.push_back((v >> 8) & 0xFF);
        buffer.push_back(v & 0xFF);
    }
    void poke_u16(size_t pos, uint16_t v)
    {
        buffer[pos] = (v >> 8) & 0xFF;
        buffer[pos + 1] = v & 0xFF;
    }
};

TEST(CHParserTest, ValidTLS13)
{
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_sni("example.com");
    builder.add_key_share();
    builder.finish();

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_EQ(info.sni, "example.com");
    EXPECT_TRUE(info.is_tls13);
    EXPECT_EQ(info.random.size(), 32);
    // 0xAA was used for random
    EXPECT_EQ(info.random[0], 0xAA);

    EXPECT_EQ(info.x25519_pub.size(), 32);
    EXPECT_EQ(info.x25519_pub[0], 0xBB);
}

TEST(CHParserTest, ValidTLS12)
{
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_sni("legacy.com");
    // No Key Share
    builder.finish();

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_EQ(info.sni, "legacy.com");
    EXPECT_FALSE(info.is_tls13);    // 无 Key Share -> 不被视为完整的 TLS 1.3 Reality 候选
}

TEST(CHParserTest, NoSNI)
{
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_key_share();
    builder.finish();

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_TRUE(info.sni.empty());
    EXPECT_TRUE(info.is_tls13);    // 存在 Key Share
}

TEST(CHParserTest, Malformed_TooShort)
{
    std::vector<uint8_t> buf = {0x16, 0x03, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, Malformed_NotClientHello)
{
    std::vector<uint8_t> buf = {0x16,
                                0x03,
                                0x01,
                                0x00,
                                0x05,
                                0x02,    // Server Hello
                                0x00,
                                0x00,
                                0x01,
                                0x03};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}
