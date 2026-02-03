#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "ch_parser.h"

using namespace mux;

class ClientHelloBuilder
{
   public:
    std::vector<uint8_t> buffer;

    ClientHelloBuilder()
    {
        add_u8(0x16);
        add_u16(0x0301);

        add_u16(0);
    }

    void start_handshake()
    {
        add_u8(0x01);

        add_u8(0);
        add_u8(0);
        add_u8(0);

        add_u16(0x0303);

        for (int i = 0; i < 32; ++i) add_u8(0xAA);

        add_u8(0);

        add_u16(2);
        add_u16(0x1302);

        add_u8(1);
        add_u8(0);

        ext_len_pos = buffer.size();
        add_u16(0);
    }

    void add_sni(const std::string& hostname)
    {
        add_u16(0x0000);
        size_t len_pos = buffer.size();
        add_u16(0);

        size_t list_len_pos = buffer.size();
        add_u16(0);

        add_u8(0);
        add_u16(hostname.size());
        for (char c : hostname) add_u8(c);

        uint16_t total_len = buffer.size() - list_len_pos - 2;
        poke_u16(list_len_pos, total_len);

        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void add_key_share()
    {
        add_u16(0x0033);
        size_t len_pos = buffer.size();
        add_u16(0);

        size_t share_len_pos = buffer.size();
        add_u16(0);

        add_u16(0x001d);
        add_u16(32);
        for (int i = 0; i < 32; ++i) add_u8(0xBB);

        uint16_t list_len = buffer.size() - share_len_pos - 2;
        poke_u16(share_len_pos, list_len);

        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void finish()
    {
        if (ext_len_pos > 0)
        {
            uint16_t ext_len = buffer.size() - ext_len_pos - 2;
            poke_u16(ext_len_pos, ext_len);
        }

        size_t handshake_len = buffer.size() - 5 - 4;
        buffer[6] = (handshake_len >> 16) & 0xFF;
        buffer[7] = (handshake_len >> 8) & 0xFF;
        buffer[8] = handshake_len & 0xFF;

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

    EXPECT_EQ(info.random[0], 0xAA);

    EXPECT_EQ(info.x25519_pub.size(), 32);
    EXPECT_EQ(info.x25519_pub[0], 0xBB);
}

TEST(CHParserTest, ValidTLS12)
{
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_sni("legacy.com");

    builder.finish();

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_EQ(info.sni, "legacy.com");
    EXPECT_FALSE(info.is_tls13);
}

TEST(CHParserTest, NoSNI)
{
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_key_share();
    builder.finish();

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_TRUE(info.sni.empty());
    EXPECT_TRUE(info.is_tls13);
}

TEST(CHParserTest, Malformed_TooShort)
{
    std::vector<uint8_t> buf = {0x16, 0x03, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, Malformed_NotClientHello)
{
    std::vector<uint8_t> buf = {0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x03};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, Malformed_TruncatedSessionID)
{
    ClientHelloBuilder builder;
    builder.start_handshake();

    std::vector<uint8_t> buf;
    buf.push_back(0x01);
    buf.push_back(0);
    buf.push_back(0);
    buf.push_back(100);
    buf.push_back(0x03);
    buf.push_back(0x03);
    for (int i = 0; i < 32; ++i) buf.push_back(0);
    buf.push_back(32);
    buf.push_back(0xAA);

    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.session_id.empty());
}

TEST(CHParserTest, Malformed_ExtensionsLen)
{
    ClientHelloBuilder builder;
    builder.start_handshake();

    builder.buffer.pop_back();
    builder.buffer.pop_back();

    auto info = ch_parser::parse(builder.buffer);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, Malformed_ExtensionTruncated)
{
    ClientHelloBuilder builder;
    builder.start_handshake();

    size_t pos = builder.buffer.size();
    builder.buffer.push_back(0);
    builder.buffer.push_back(0);

    builder.buffer.push_back(0);
    builder.buffer.push_back(0);

    builder.buffer.push_back(0);
    builder.buffer.push_back(10);

    uint16_t total = builder.buffer.size() - pos - 2;
    builder.buffer[pos] = (total >> 8);
    builder.buffer[pos + 1] = total & 0xFF;

    auto info = ch_parser::parse(builder.buffer);

    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, SNI_MalformedList)
{
    ClientHelloBuilder builder;
    builder.start_handshake();

    size_t pos = builder.buffer.size();
    builder.buffer.push_back(0);
    builder.buffer.push_back(0);

    builder.buffer.push_back(0);
    builder.buffer.push_back(0);
    builder.buffer.push_back(0);
    builder.buffer.push_back(5);

    builder.buffer.push_back(0);
    builder.buffer.push_back(10);
    builder.buffer.push_back(0);

    uint16_t total = builder.buffer.size() - pos - 2;
    builder.buffer[pos] = (total >> 8);
    builder.buffer[pos + 1] = total & 0xFF;

    auto info = ch_parser::parse(builder.buffer);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, KeyShare_WrongGroup)
{
    ClientHelloBuilder builder;
    builder.start_handshake();

    size_t pos = builder.buffer.size();
    builder.buffer.push_back(0);
    builder.buffer.push_back(0);

    builder.buffer.push_back(0x00);
    builder.buffer.push_back(0x33);
    builder.buffer.push_back(0);
    builder.buffer.push_back(6);

    builder.buffer.push_back(0);
    builder.buffer.push_back(4);

    builder.buffer.push_back(0x00);
    builder.buffer.push_back(0x11);
    builder.buffer.push_back(0);
    builder.buffer.push_back(0);

    uint16_t total = builder.buffer.size() - pos - 2;
    builder.buffer[pos] = (total >> 8);
    builder.buffer[pos + 1] = total & 0xFF;

    auto info = ch_parser::parse(builder.buffer);
    EXPECT_FALSE(info.is_tls13);
}
