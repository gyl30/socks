#include <gtest/gtest.h>
#include <vector>
#include <cstdint>
#include "ch_parser.h"

using namespace mux;

// Helper to construct Client Hello
class ClientHelloBuilder {
public:
    std::vector<uint8_t> buffer;

    ClientHelloBuilder() {
        // Record Header (content type 0x16, version 0x0301)
        add_u8(0x16);
        add_u16(0x0301);
        // Placeholder for length
        add_u16(0); 
    }

    void start_handshake() {
        // Handshake Header (type 0x01 Client Hello)
        add_u8(0x01);
        // Placeholder for handshake length (3 bytes)
        add_u8(0);
        add_u8(0);
        add_u8(0);
        
        // Version (0x0303 for TLS 1.2 in CH)
        add_u16(0x0303);
        
        // Random (32 bytes)
        for(int i=0; i<32; ++i) add_u8(0xAA);
        
        // Session ID length (0)
        add_u8(0);
        
        // Cipher Suites length (2 bytes) + 1 suite (0x1302 TLS_AES_256_GCM_SHA384)
        add_u16(2);
        add_u16(0x1302);
        
        // Compression methods length (1) + null (0)
        add_u8(1);
        add_u8(0);
        
        // Extensions length placeholder
        ext_len_pos = buffer.size();
        add_u16(0);
    }
    
    void add_sni(const std::string& hostname) {
        add_u16(0x0000); // SNI Type
        size_t len_pos = buffer.size();
        add_u16(0); // Len placeholder
        
        size_t list_len_pos = buffer.size();
        add_u16(0); // List len placeholder
        
        add_u8(0); // Hostname type
        add_u16(hostname.size());
        for(char c : hostname) add_u8(c);
        
        uint16_t total_len = buffer.size() - list_len_pos - 2;
        poke_u16(list_len_pos, total_len);
        
        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void add_key_share() {
        add_u16(0x0033); // Key Share Type
        size_t len_pos = buffer.size();
        add_u16(0); // Len placeholder
        
        size_t share_len_pos = buffer.size();
        add_u16(0); // Share list len placeholder
        
        add_u16(0x001d); // Group X25519
        add_u16(32); // Key len
        for(int i=0; i<32; ++i) add_u8(0xBB); // Fake Key
        
        uint16_t list_len = buffer.size() - share_len_pos - 2;
        poke_u16(share_len_pos, list_len);
        
        uint16_t ext_len = buffer.size() - len_pos - 2;
        poke_u16(len_pos, ext_len);
    }

    void finish() {
        // Fix Extensions Length
        if (ext_len_pos > 0) {
            uint16_t ext_len = buffer.size() - ext_len_pos - 2;
            poke_u16(ext_len_pos, ext_len);
        }
        
        // Fix Handshake Length (3 bytes at offset 6, 7, 8)
        // Record(5) + Type(1) + Len(3) ...
        size_t handshake_len = buffer.size() - 5 - 4; 
        buffer[6] = (handshake_len >> 16) & 0xFF;
        buffer[7] = (handshake_len >> 8) & 0xFF;
        buffer[8] = handshake_len & 0xFF;

        // Fix Record Length (at offset 3, 4)
        size_t record_len = buffer.size() - 5;
        poke_u16(3, record_len);
    }

private:
    size_t ext_len_pos = 0;
    
    void add_u8(uint8_t v) { buffer.push_back(v); }
    void add_u16(uint16_t v) {
        buffer.push_back((v >> 8) & 0xFF);
        buffer.push_back(v & 0xFF);
    }
    void poke_u16(size_t pos, uint16_t v) {
        buffer[pos] = (v >> 8) & 0xFF;
        buffer[pos+1] = v & 0xFF;
    }
};

TEST(CHParserTest, ValidTLS13) {
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

TEST(CHParserTest, ValidTLS12) {
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_sni("legacy.com");
    // No Key Share
    builder.finish();
    
    auto info = ch_parser::parse(builder.buffer);
    
    EXPECT_EQ(info.sni, "legacy.com");
    EXPECT_FALSE(info.is_tls13); // No key share -> considered not full TLS 1.3 Reality compatible candidate
}

TEST(CHParserTest, NoSNI) {
    ClientHelloBuilder builder;
    builder.start_handshake();
    builder.add_key_share();
    builder.finish();
    
    auto info = ch_parser::parse(builder.buffer);
    
    EXPECT_TRUE(info.sni.empty());
    EXPECT_TRUE(info.is_tls13); // Key share is present
}

TEST(CHParserTest, Malformed_TooShort) {
    std::vector<uint8_t> buf = {0x16, 0x03, 0x01};
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}

TEST(CHParserTest, Malformed_NotClientHello) {
    std::vector<uint8_t> buf = {
        0x16, 0x03, 0x01, 0x00, 0x05, 
        0x02, // Server Hello
        0x00, 0x00, 0x01, 0x03
    };
    auto info = ch_parser::parse(buf);
    EXPECT_TRUE(info.sni.empty());
}
