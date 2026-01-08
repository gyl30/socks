#ifndef REALITY_MESSAGES_H
#define REALITY_MESSAGES_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include "reality_core.h"

namespace reality
{

class MessageBuilder
{
   public:
    static void push_u16(std::vector<uint8_t>& buf, uint16_t val)
    {
        buf.push_back((val >> 8) & 0xFF);
        buf.push_back(val & 0xFF);
    }

    static void push_u24(std::vector<uint8_t>& buf, uint32_t val)
    {
        buf.push_back((val >> 16) & 0xFF);
        buf.push_back((val >> 8) & 0xFF);
        buf.push_back(val & 0xFF);
    }

    static void push_u32(std::vector<uint8_t>& buf, uint32_t val)
    {
        buf.push_back((val >> 24) & 0xFF);
        buf.push_back((val >> 16) & 0xFF);
        buf.push_back((val >> 8) & 0xFF);
        buf.push_back(val & 0xFF);
    }

    static void push_bytes(std::vector<uint8_t>& buf, const std::vector<uint8_t>& data) { buf.insert(buf.end(), data.begin(), data.end()); }

    static void push_bytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) { buf.insert(buf.end(), data, data + len); }

    static void push_string(std::vector<uint8_t>& buf, const std::string& str) { buf.insert(buf.end(), str.begin(), str.end()); }
};

inline std::vector<uint8_t> write_record_header(uint8_t record_type, uint16_t length)
{
    std::vector<uint8_t> header;
    header.reserve(5);
    header.push_back(record_type);
    header.push_back(TLS1_2_VERSION_MAJOR);
    header.push_back(TLS1_2_VERSION_MINOR);
    MessageBuilder::push_u16(header, length);
    return header;
}

inline std::vector<uint8_t> construct_client_hello(const std::vector<uint8_t>& client_random,
                                                   const std::vector<uint8_t>& session_id,
                                                   const std::vector<uint8_t>& client_public_key,
                                                   const std::string& server_name,
                                                   const std::vector<uint16_t>& cipher_suites = {0x1301, 0x1302, 0x1303})
{
    std::vector<uint8_t> hello;

    hello.push_back(0x01);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);

    MessageBuilder::push_u16(hello, 0x0303);
    MessageBuilder::push_bytes(hello, client_random);

    hello.push_back(static_cast<uint8_t>(session_id.size()));
    MessageBuilder::push_bytes(hello, session_id);

    MessageBuilder::push_u16(hello, static_cast<uint16_t>(cipher_suites.size() * 2));
    for (uint16_t suite : cipher_suites)
    {
        MessageBuilder::push_u16(hello, suite);
    }

    hello.push_back(1);
    hello.push_back(0x00);

    std::vector<uint8_t> extensions;

    // 1. SNI Extension
    if (!server_name.empty())
    {
        MessageBuilder::push_u16(extensions, 0x0000);    // Type
        uint16_t sni_len = static_cast<uint16_t>(server_name.size());
        // Structure: ListLen(2) | NameType(1) | NameLen(2) | Name...
        uint16_t ext_data_len = 2 + 1 + 2 + sni_len;

        // BUG FIX: Was ext_data_len - 2, causing offset misalignment for subsequent extensions
        MessageBuilder::push_u16(extensions, ext_data_len);

        // ServerNameList Length
        MessageBuilder::push_u16(extensions, sni_len + 3);
        extensions.push_back(0x00);    // HostName Type
        MessageBuilder::push_u16(extensions, sni_len);
        MessageBuilder::push_string(extensions, server_name);
    }

    // 2. Supported Versions
    {
        MessageBuilder::push_u16(extensions, 0x002b);
        MessageBuilder::push_u16(extensions, 3);
        extensions.push_back(2);
        MessageBuilder::push_u16(extensions, 0x0304);
    }

    // 3. Supported Groups
    {
        MessageBuilder::push_u16(extensions, 0x000a);
        MessageBuilder::push_u16(extensions, 4);
        MessageBuilder::push_u16(extensions, 2);
        MessageBuilder::push_u16(extensions, 0x001d);
    }

    // 4. Key Share
    {
        MessageBuilder::push_u16(extensions, 0x0033);
        uint16_t key_len = static_cast<uint16_t>(client_public_key.size());
        uint16_t ext_len = 2 + 2 + 2 + key_len;
        MessageBuilder::push_u16(extensions, ext_len);

        MessageBuilder::push_u16(extensions, ext_len - 2);
        MessageBuilder::push_u16(extensions, 0x001d);
        MessageBuilder::push_u16(extensions, key_len);
        MessageBuilder::push_bytes(extensions, client_public_key);
    }

    // 5. Signature Algorithms
    {
        MessageBuilder::push_u16(extensions, 0x000d);
        MessageBuilder::push_u16(extensions, 4);
        MessageBuilder::push_u16(extensions, 2);
        MessageBuilder::push_u16(extensions, 0x0807);
    }

    MessageBuilder::push_u16(hello, static_cast<uint16_t>(extensions.size()));
    MessageBuilder::push_bytes(hello, extensions);

    size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    return hello;
}

inline std::vector<uint8_t> construct_server_hello(const std::vector<uint8_t>& server_random,
                                                   const std::vector<uint8_t>& session_id,
                                                   uint16_t cipher_suite,
                                                   const std::vector<uint8_t>& server_public_key)
{
    std::vector<uint8_t> hello;

    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);

    MessageBuilder::push_u16(hello, 0x0303);
    MessageBuilder::push_bytes(hello, server_random);

    hello.push_back(static_cast<uint8_t>(session_id.size()));
    MessageBuilder::push_bytes(hello, session_id);

    MessageBuilder::push_u16(hello, cipher_suite);
    hello.push_back(0x00);

    std::vector<uint8_t> extensions;

    {
        MessageBuilder::push_u16(extensions, 0x002b);
        MessageBuilder::push_u16(extensions, 2);
        MessageBuilder::push_u16(extensions, 0x0304);
    }

    {
        MessageBuilder::push_u16(extensions, 0x0033);
        uint16_t ext_len = 2 + 2 + static_cast<uint16_t>(server_public_key.size());
        MessageBuilder::push_u16(extensions, ext_len);
        MessageBuilder::push_u16(extensions, 0x001d);
        MessageBuilder::push_u16(extensions, static_cast<uint16_t>(server_public_key.size()));
        MessageBuilder::push_bytes(extensions, server_public_key);
    }

    MessageBuilder::push_u16(hello, static_cast<uint16_t>(extensions.size()));
    MessageBuilder::push_bytes(hello, extensions);

    size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    return hello;
}

inline std::vector<uint8_t> construct_encrypted_extensions()
{
    std::vector<uint8_t> msg;
    msg.push_back(0x08);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x02);
    msg.push_back(0x00);
    msg.push_back(0x00);
    return msg;
}

inline std::vector<uint8_t> construct_certificate(const std::vector<uint8_t>& cert_der)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x0b);

    std::vector<uint8_t> body;
    body.push_back(0x00);

    std::vector<uint8_t> list;
    MessageBuilder::push_u24(list, static_cast<uint32_t>(cert_der.size()));
    MessageBuilder::push_bytes(list, cert_der);
    MessageBuilder::push_u16(list, 0x0000);

    MessageBuilder::push_u24(body, static_cast<uint32_t>(list.size()));
    MessageBuilder::push_bytes(body, list);

    MessageBuilder::push_u24(msg, static_cast<uint32_t>(body.size()));
    MessageBuilder::push_bytes(msg, body);

    return msg;
}

inline std::vector<uint8_t> construct_certificate_verify(EVP_PKEY* signing_key, const std::vector<uint8_t>& handshake_hash)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x0f);

    std::vector<uint8_t> to_sign;
    to_sign.insert(to_sign.end(), 64, 0x20);
    std::string context_str = "TLS 1.3, server CertificateVerify";
    to_sign.insert(to_sign.end(), context_str.begin(), context_str.end());
    to_sign.push_back(0x00);
    to_sign.insert(to_sign.end(), handshake_hash.begin(), handshake_hash.end());

    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, signing_key);
    size_t sig_len = 0;
    EVP_DigestSign(mctx, NULL, &sig_len, to_sign.data(), to_sign.size());
    std::vector<uint8_t> signature(sig_len);
    EVP_DigestSign(mctx, signature.data(), &sig_len, to_sign.data(), to_sign.size());
    EVP_MD_CTX_free(mctx);
    signature.resize(sig_len);

    std::vector<uint8_t> body;
    MessageBuilder::push_u16(body, 0x0807);
    MessageBuilder::push_u16(body, static_cast<uint16_t>(signature.size()));
    MessageBuilder::push_bytes(body, signature);

    MessageBuilder::push_u24(msg, static_cast<uint32_t>(body.size()));
    MessageBuilder::push_bytes(msg, body);

    return msg;
}

inline std::vector<uint8_t> construct_finished(const std::vector<uint8_t>& verify_data)
{
    std::vector<uint8_t> msg;
    msg.push_back(0x14);
    MessageBuilder::push_u24(msg, static_cast<uint32_t>(verify_data.size()));
    MessageBuilder::push_bytes(msg, verify_data);
    return msg;
}

inline std::vector<uint8_t> extract_server_public_key(const std::vector<uint8_t>& server_hello)
{
    size_t pos = 0;
    if (server_hello.size() < 4)
        return {};

    if (server_hello[0] == 0x16)
    {
        pos += 5;
    }

    if (pos + 38 > server_hello.size())
        return {};
    if (server_hello[pos] != 0x02)
        return {};

    pos += 1 + 3 + 2 + 32;

    uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;

    pos += 2;
    pos += 1;

    if (pos + 2 > server_hello.size())
        return {};
    uint16_t ext_len = (server_hello[pos] << 8) | server_hello[pos + 1];
    pos += 2;

    size_t end = pos + ext_len;
    if (end > server_hello.size())
        return {};

    while (pos + 4 <= end)
    {
        uint16_t etype = (server_hello[pos] << 8) | server_hello[pos + 1];
        uint16_t elen = (server_hello[pos + 2] << 8) | server_hello[pos + 3];
        pos += 4;

        if (etype == 51)
        {
            if (elen >= 4)
            {
                uint16_t klen = (server_hello[pos + 2] << 8) | server_hello[pos + 3];
                if (klen == 32 && pos + 4 + 32 <= end)
                {
                    return std::vector<uint8_t>(server_hello.begin() + pos + 4, server_hello.begin() + pos + 4 + 32);
                }
            }
        }
        pos += elen;
    }
    return {};
}

}    // namespace reality

#endif
