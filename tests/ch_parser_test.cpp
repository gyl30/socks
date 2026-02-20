#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <gtest/gtest.h>

#define private public
#include "ch_parser.h"
#undef private
#include "reality_core.h"

using mux::ch_parser;

class client_hello_builder
{
   public:
    [[nodiscard]] const std::vector<uint8_t>& get_buffer() const { return buffer_; }
    [[nodiscard]] std::vector<uint8_t>& get_mutable_buffer() { return buffer_; }

    client_hello_builder()
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

        for (int i = 0; i < 32; ++i)
        {
            add_u8(0xAA);
        }

        add_u8(0);

        add_u16(2);
        add_u16(0x1302);

        add_u8(1);
        add_u8(0);

        ext_len_pos_ = buffer_.size();
        add_u16(0);
    }

    void add_sni(const std::string& hostname)
    {
        add_u16(0x0000);
        const size_t len_pos = buffer_.size();
        add_u16(0);

        const size_t list_len_pos = buffer_.size();
        add_u16(0);

        add_u8(0);
        add_u16(to_u16(hostname.size()));
        for (const char c : hostname)
        {
            add_u8(static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
        }

        const uint16_t total_len = to_u16(buffer_.size() - list_len_pos - 2);
        poke_u16(list_len_pos, total_len);

        const uint16_t ext_len = to_u16(buffer_.size() - len_pos - 2);
        poke_u16(len_pos, ext_len);
    }

    void add_key_share()
    {
        add_u16(0x0033);
        const size_t len_pos = buffer_.size();
        add_u16(0);

        const size_t share_len_pos = buffer_.size();
        add_u16(0);

        add_u16(0x001d);
        add_u16(32);
        for (int i = 0; i < 32; ++i)
        {
            add_u8(0xBB);
        }

        const uint16_t list_len = to_u16(buffer_.size() - share_len_pos - 2);
        poke_u16(share_len_pos, list_len);

        const uint16_t ext_len = to_u16(buffer_.size() - len_pos - 2);
        poke_u16(len_pos, ext_len);
    }

    void finish()
    {
        if (ext_len_pos_ > 0)
        {
            const uint16_t ext_len = to_u16(buffer_.size() - ext_len_pos_ - 2);
            poke_u16(ext_len_pos_, ext_len);
        }

        const size_t handshake_len = buffer_.size() - 5 - 4;
        buffer_[6] = static_cast<std::uint8_t>((handshake_len >> 16) & 0xFFU);
        buffer_[7] = static_cast<std::uint8_t>((handshake_len >> 8) & 0xFFU);
        buffer_[8] = static_cast<std::uint8_t>(handshake_len & 0xFFU);

        const size_t record_len = buffer_.size() - 5;
        poke_u16(3, to_u16(record_len));
    }

   private:
    std::vector<uint8_t> buffer_;
    size_t ext_len_pos_ = 0;

    void add_u8(uint8_t v) { buffer_.push_back(v); }
    void add_u16(uint16_t v)
    {
        buffer_.push_back((v >> 8) & 0xFF);
        buffer_.push_back(v & 0xFF);
    }
    void poke_u16(size_t pos, uint16_t v)
    {
        buffer_[pos] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
        buffer_[pos + 1] = static_cast<std::uint8_t>(v & 0xFFU);
    }

    [[nodiscard]] static std::uint16_t to_u16(const std::size_t value)
    {
        return static_cast<std::uint16_t>(value);
    }
};

TEST(CHParserTest, ValidTLS13)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.add_sni("example.com");
    builder.add_key_share();
    builder.finish();

    auto info = ch_parser::parse(builder.get_buffer());

    EXPECT_EQ(info.sni, "example.com");
    EXPECT_TRUE(info.is_tls13);
    EXPECT_EQ(info.random.size(), 32);

    EXPECT_EQ(info.random[0], 0xAA);

    EXPECT_EQ(info.x25519_pub.size(), 32);
    EXPECT_EQ(info.x25519_pub[0], 0xBB);
}

TEST(CHParserTest, ValidTLS12)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.add_sni("legacy.com");

    builder.finish();

    auto info = ch_parser::parse(builder.get_buffer());

    EXPECT_EQ(info.sni, "legacy.com");
    EXPECT_FALSE(info.is_tls13);
}

TEST(CHParserTest, NoSNI)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.add_key_share();
    builder.finish();

    auto info = ch_parser::parse(builder.get_buffer());

    EXPECT_TRUE(info.sni.empty());
    EXPECT_TRUE(info.is_tls13);
}

TEST(CHParserTest, MalformedTooShort)
{
    const std::vector<uint8_t> buf = {0x16, 0x03, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, MalformedNotClientHello)
{
    const std::vector<uint8_t> buf = {0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x03};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, MalformedTruncatedSessionID)
{
    client_hello_builder builder;
    builder.start_handshake();

    std::vector<uint8_t> buf;
    buf.push_back(0x01);
    buf.push_back(0);
    buf.push_back(0);
    buf.push_back(100);
    buf.push_back(0x03);
    buf.push_back(0x03);
    for (int i = 0; i < 32; ++i)
    {
        buf.push_back(0);
    }
    buf.push_back(32);
    buf.push_back(0xAA);

    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.session_id.empty());
}

TEST(CHParserTest, MalformedExtensionsLen)
{
    client_hello_builder builder;
    builder.start_handshake();

    builder.get_mutable_buffer().pop_back();
    builder.get_mutable_buffer().pop_back();

    auto info = ch_parser::parse(builder.get_buffer());
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, MalformedExtensionTruncated)
{
    client_hello_builder builder;
    builder.start_handshake();

    const size_t pos = builder.get_buffer().size();
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(10);

    const std::size_t total = builder.get_buffer().size() - pos - 2;
    builder.get_mutable_buffer()[pos] = static_cast<std::uint8_t>((total >> 8) & 0xFFU);
    builder.get_mutable_buffer()[pos + 1] = static_cast<std::uint8_t>(total & 0xFFU);

    auto info = ch_parser::parse(builder.get_buffer());

    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, SNIMalformedList)
{
    client_hello_builder builder;
    builder.start_handshake();

    const size_t pos = builder.get_buffer().size();
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(5);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(10);
    builder.get_mutable_buffer().push_back(0);

    const std::size_t total = builder.get_buffer().size() - pos - 2;
    builder.get_mutable_buffer()[pos] = static_cast<std::uint8_t>((total >> 8) & 0xFFU);
    builder.get_mutable_buffer()[pos + 1] = static_cast<std::uint8_t>(total & 0xFFU);

    auto info = ch_parser::parse(builder.get_buffer());
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, KeyShareWrongGroup)
{
    client_hello_builder builder;
    builder.start_handshake();

    const size_t pos = builder.get_buffer().size();
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x33);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(6);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(4);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x11);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    const std::size_t total = builder.get_buffer().size() - pos - 2;
    builder.get_mutable_buffer()[pos] = static_cast<std::uint8_t>((total >> 8) & 0xFFU);
    builder.get_mutable_buffer()[pos + 1] = static_cast<std::uint8_t>(total & 0xFFU);

    auto info = ch_parser::parse(builder.get_buffer());
    EXPECT_FALSE(info.is_tls13);
}

TEST(CHParserTest, WrongRecordType)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.finish();
    auto buf = builder.get_buffer();
    buf[0] = 0x17;
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, InternalReadAndSkipFailures)
{
    {
        std::vector<std::uint8_t> const buf;
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        EXPECT_FALSE(ch_parser::read_session_id(r, info));
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x00};
        ch_parser::reader r(buf);
        EXPECT_FALSE(ch_parser::skip_cipher_suites_and_compression(r));
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x01, 0x02};
        ch_parser::reader r(buf);
        std::uint16_t type = 0;
        std::uint16_t len = 0;
        EXPECT_FALSE(ch_parser::read_extension_header(r, type, len));
    }

    {
        std::vector<std::uint8_t> const buf = {0x01};
        ch_parser::reader r(buf);
        std::uint8_t type = 0;
        std::uint16_t len = 0;
        EXPECT_FALSE(ch_parser::read_sni_item_header(r, type, len));
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x1D, 0x00};
        ch_parser::reader r(buf);
        std::uint16_t group = 0;
        std::uint16_t len = 0;
        EXPECT_FALSE(ch_parser::read_key_share_item_header(r, group, len));
    }
}

TEST(CHParserTest, ReaderInvalidSliceKeepsSafeAccessors)
{
    std::vector<std::uint8_t> const buf = {0x01};
    ch_parser::reader r(buf);
    auto invalid = r.slice(2);

    EXPECT_FALSE(invalid.valid());
    EXPECT_EQ(invalid.remaining(), 0U);
    EXPECT_EQ(invalid.offset(), 0U);
}

TEST(CHParserTest, InternalSNIAndExtensionBranches)
{
    {
        std::vector<std::uint8_t> const buf = {0xAB};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        EXPECT_TRUE(ch_parser::handle_sni_item(r, 0x00, 2, info));
        EXPECT_TRUE(info.sni.empty());
    }

    {
        std::vector<std::uint8_t> const buf = {0xAB};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        EXPECT_TRUE(ch_parser::handle_sni_item(r, 0x01, 2, info));
    }

    {
        std::vector<std::uint8_t> const buf = {0xAB, 0xCD};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        EXPECT_FALSE(ch_parser::handle_sni_item(r, 0x01, 2, info));
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x05, 0x01};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_extension_block(r, info);
        EXPECT_TRUE(info.sni.empty());
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x00, 0x00, 0x05, 0xFF};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_extensions(r, info);
        EXPECT_TRUE(info.sni.empty());
    }

    {
        std::vector<std::uint8_t> const buf;
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_sni(r, info);
        EXPECT_TRUE(info.sni.empty());
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x05, 0x41};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_sni(r, info);
        EXPECT_TRUE(info.sni.empty());
    }
}

TEST(CHParserTest, InternalKeyShareBranches)
{
    {
        std::vector<std::uint8_t> const buf(31, 0x11);
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::handle_key_share_item(r, reality::tls_consts::group::kX25519, 31, info);
        EXPECT_FALSE(info.has_x25519_share);
    }

    {
        mux::client_hello_info info;
        ch_parser::finalize_key_share_info(info);
        EXPECT_FALSE(info.is_tls13);
    }

    {
        std::vector<std::uint8_t> const buf;
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_key_share(r, info);
        EXPECT_FALSE(info.is_tls13);
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x05, 0x01};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_key_share(r, info);
        EXPECT_FALSE(info.is_tls13);
    }

    {
        std::vector<std::uint8_t> const buf = {0x00, 0x04, 0x00, 0x17, 0x00, 0x01};
        ch_parser::reader r(buf);
        mux::client_hello_info info;
        ch_parser::parse_key_share(r, info);
        EXPECT_FALSE(info.is_tls13);
    }
}

TEST(CHParserTest, WrongHandshakeType)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.finish();
    auto buf = builder.get_buffer();
    buf[5] = 0x02;
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, TruncatedRandom)
{
    client_hello_builder builder;
    builder.start_handshake();
    auto buf = builder.get_buffer();
    buf.resize(10);
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, SNINonHostName)
{
    client_hello_builder builder;
    builder.start_handshake();
    const size_t pos = builder.get_buffer().size();
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(8);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(6);

    builder.get_mutable_buffer().push_back(0x01);
    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(3);
    builder.get_mutable_buffer().push_back('a');
    builder.get_mutable_buffer().push_back('b');
    builder.get_mutable_buffer().push_back('c');

    const std::size_t total = builder.get_buffer().size() - pos - 2;
    builder.get_mutable_buffer()[pos] = static_cast<std::uint8_t>((total >> 8) & 0xFFU);
    builder.get_mutable_buffer()[pos + 1] = static_cast<std::uint8_t>(total & 0xFFU);

    auto info = ch_parser::parse(builder.get_buffer());
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, TruncatedHandshakeType)
{
    std::vector<uint8_t> const buf = {0x16, 0x03, 0x03, 0x00, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, TruncatedVersion)
{
    std::vector<uint8_t> const buf = {0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, TruncatedCipherSuitesLen)
{
    client_hello_builder builder;
    builder.start_handshake();
    auto buf = builder.get_buffer();

    buf.resize(44 + 1);
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.size() == 32);
}

TEST(CHParserTest, TruncatedCompressionLen)
{
    client_hello_builder builder;
    builder.start_handshake();
    auto buf = builder.get_buffer();
    buf.resize(buf.size() - 5);
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, TruncatedExtensionsLen)
{
    client_hello_builder builder;
    builder.start_handshake();
    auto buf = builder.get_buffer();

    buf.resize(50);
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, TruncatedHandshakeHeader)
{
    std::vector<uint8_t> const buf = {0x16, 0x03, 0x03, 0x00, 0x01, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, ReaderInvalidStateCoversGuardBranches)
{
    ch_parser::reader reader(nullptr, 0, nullptr);
    EXPECT_FALSE(reader.valid());
    EXPECT_FALSE(reader.has(1));
    EXPECT_EQ(reader.remaining(), 0U);
    EXPECT_EQ(reader.offset(), 0U);
    EXPECT_EQ(reader.peek(0), 0U);

    std::uint8_t value_u8 = 0;
    std::uint16_t value_u16 = 0;
    std::vector<std::uint8_t> value_vec;
    EXPECT_FALSE(reader.skip(1));
    EXPECT_FALSE(reader.read_u8(value_u8));
    EXPECT_FALSE(reader.read_u16(value_u16));
    EXPECT_FALSE(reader.read_vector(value_vec, 1));

    auto sliced = reader.slice(1);
    EXPECT_FALSE(sliced.valid());
    EXPECT_EQ(sliced.remaining(), 0U);
}

TEST(CHParserTest, TruncatedRandomField)
{
    std::vector<uint8_t> buf = {0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c};
    buf.insert(buf.end(), 10, 0xAA);
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.random.empty());
}

TEST(CHParserTest, KeyShareWrongLength)
{
    client_hello_builder builder;
    builder.start_handshake();
    const size_t pos = builder.get_buffer().size();
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(0);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x33);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(10);

    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(8);

    builder.get_mutable_buffer().push_back(0x00);
    builder.get_mutable_buffer().push_back(0x1d);
    builder.get_mutable_buffer().push_back(0);
    builder.get_mutable_buffer().push_back(31);
    for (int i = 0; i < 4; ++i)
    {
        builder.get_mutable_buffer().push_back(0xEE);
    }

    const std::size_t total = builder.get_buffer().size() - pos - 2;
    builder.get_mutable_buffer()[pos] = static_cast<std::uint8_t>((total >> 8) & 0xFFU);
    builder.get_mutable_buffer()[pos + 1] = static_cast<std::uint8_t>(total & 0xFFU);

    auto info = ch_parser::parse(builder.get_buffer());
    EXPECT_TRUE(info.x25519_pub.empty());
}

TEST(CHParserTest, ParseBeforeExtensionsFailsOnTruncatedSessionId)
{
    client_hello_builder builder;
    builder.start_handshake();
    builder.finish();

    auto buf = builder.get_buffer();
    constexpr std::size_t sid_len_pos = 5 + 1 + 3 + 2 + 32;
    buf[sid_len_pos] = 4;
    buf.resize(sid_len_pos + 1);

    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.session_id.empty());
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, ParseSniHandlesShortListWithoutItems)
{
    std::vector<std::uint8_t> const buf = {0x00, 0x01, 0xAB};
    ch_parser::reader r(buf);
    mux::client_hello_info info;

    ch_parser::parse_sni(r, info);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, ParseSniContinuesAfterSkippingNonHostNameItem)
{
    std::vector<std::uint8_t> const buf = {
        0x00,
        0x0A,
        0x01,
        0x00,
        0x01,
        0x78,
        0x00,
        0x00,
        0x03,
        0x61,
        0x62,
        0x63,
    };
    ch_parser::reader r(buf);
    mux::client_hello_info info;

    ch_parser::parse_sni(r, info);
    EXPECT_EQ(info.sni, "abc");
}

TEST(CHParserTest, ParseKeyShareX25519Len32ButInsufficientData)
{
    std::vector<std::uint8_t> const buf = {
        0x00,
        0x08,
        0x00,
        0x1d,
        0x00,
        0x20,
        0x11,
        0x22,
        0x33,
        0x44,
    };
    ch_parser::reader r(buf);
    mux::client_hello_info info;

    ch_parser::parse_key_share(r, info);
    EXPECT_FALSE(info.has_x25519_share);
    EXPECT_TRUE(info.x25519_pub.empty());
    EXPECT_FALSE(info.is_tls13);
}
