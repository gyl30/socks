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
    static void push_u8(std::vector<uint8_t>& buf, uint8_t val) { buf.push_back(val); }

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

    static void append_ext(std::vector<uint8_t>& dest, const std::vector<uint8_t>& ext) { dest.insert(dest.end(), ext.begin(), ext.end()); }
};

class ChromeClientHelloBuilder
{
   public:
    static std::vector<uint8_t> build_grease_ext(uint16_t grease_val)
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, grease_val);
        MessageBuilder::push_u16(ext, 0x0000);
        return ext;
    }

    static std::vector<uint8_t> build_sni_ext(const std::string& host)
    {
        std::vector<uint8_t> ext;
        if (host.empty())
        {
            return ext;
        }

        MessageBuilder::push_u16(ext, 0x0000);

        std::vector<uint8_t> sn_list;
        std::vector<uint8_t> sn_entry;
        sn_entry.push_back(0x00);
        MessageBuilder::push_u16(sn_entry, static_cast<uint16_t>(host.size()));
        MessageBuilder::push_string(sn_entry, host);

        MessageBuilder::push_u16(sn_list, static_cast<uint16_t>(sn_entry.size()));
        MessageBuilder::push_bytes(sn_list, sn_entry);

        MessageBuilder::push_u16(ext, static_cast<uint16_t>(sn_list.size()));
        MessageBuilder::push_bytes(ext, sn_list);
        return ext;
    }

    static std::vector<uint8_t> build_extended_master_secret()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0017);
        MessageBuilder::push_u16(ext, 0x0000);
        return ext;
    }

    static std::vector<uint8_t> build_renegotiation_info()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0xff01);
        MessageBuilder::push_u16(ext, 0x0001);
        ext.push_back(0x00);
        return ext;
    }

    static std::vector<uint8_t> build_supported_groups(uint16_t grease_group)
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x000a);

        std::vector<uint8_t> groups;
        MessageBuilder::push_u16(groups, grease_group);
        MessageBuilder::push_u16(groups, 0x001d);
        MessageBuilder::push_u16(groups, 0x0017);
        MessageBuilder::push_u16(groups, 0x0018);

        MessageBuilder::push_u16(ext, static_cast<uint16_t>(groups.size() + 2));
        MessageBuilder::push_u16(ext, static_cast<uint16_t>(groups.size()));
        MessageBuilder::push_bytes(ext, groups);
        return ext;
    }

    static std::vector<uint8_t> build_ec_point_formats()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x000b);
        MessageBuilder::push_u16(ext, 0x0002);
        ext.push_back(0x01);
        ext.push_back(0x00);
        return ext;
    }

    static std::vector<uint8_t> build_session_ticket()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0023);
        MessageBuilder::push_u16(ext, 0x0000);
        return ext;
    }

    static std::vector<uint8_t> build_alpn()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0010);

        std::vector<uint8_t> protos;

        protos.push_back(2);
        protos.push_back('h');
        protos.push_back('2');

        protos.push_back(8);
        MessageBuilder::push_string(protos, "http/1.1");

        MessageBuilder::push_u16(ext, static_cast<uint16_t>(protos.size() + 2));
        MessageBuilder::push_u16(ext, static_cast<uint16_t>(protos.size()));
        MessageBuilder::push_bytes(ext, protos);
        return ext;
    }

    static std::vector<uint8_t> build_status_request()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0005);
        MessageBuilder::push_u16(ext, 0x0005);
        ext.push_back(0x01);
        MessageBuilder::push_u16(ext, 0x0000);
        MessageBuilder::push_u16(ext, 0x0000);
        return ext;
    }

    static std::vector<uint8_t> build_signature_algorithms()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x000d);

        std::vector<uint16_t> algs = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601};

        MessageBuilder::push_u16(ext, static_cast<uint16_t>((algs.size() * 2) + 2));
        MessageBuilder::push_u16(ext, static_cast<uint16_t>(algs.size() * 2));
        for (auto a : algs)
        {
            MessageBuilder::push_u16(ext, a);
        }

        return ext;
    }

    static std::vector<uint8_t> build_sct()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0012);
        MessageBuilder::push_u16(ext, 0x0000);
        return ext;
    }

    static std::vector<uint8_t> build_key_share(uint16_t grease_group, const std::vector<uint8_t>& pub_key)
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0033);

        std::vector<uint8_t> shares;

        MessageBuilder::push_u16(shares, grease_group);
        MessageBuilder::push_u16(shares, 1);
        shares.push_back(0x00);

        MessageBuilder::push_u16(shares, 0x001d);
        MessageBuilder::push_u16(shares, static_cast<uint16_t>(pub_key.size()));
        MessageBuilder::push_bytes(shares, pub_key);

        MessageBuilder::push_u16(ext, static_cast<uint16_t>(shares.size() + 2));
        MessageBuilder::push_u16(ext, static_cast<uint16_t>(shares.size()));
        MessageBuilder::push_bytes(ext, shares);
        return ext;
    }

    static std::vector<uint8_t> build_psk_key_exchange_modes()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x002d);
        MessageBuilder::push_u16(ext, 0x0002);
        ext.push_back(0x01);
        ext.push_back(0x01);
        return ext;
    }

    static std::vector<uint8_t> build_supported_versions(uint16_t grease_ver)
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x002b);

        std::vector<uint8_t> vers;
        MessageBuilder::push_u16(vers, grease_ver);
        MessageBuilder::push_u16(vers, 0x0304);
        MessageBuilder::push_u16(vers, 0x0303);

        MessageBuilder::push_u16(ext, static_cast<uint16_t>(vers.size() + 1));
        ext.push_back(static_cast<uint8_t>(vers.size()));
        MessageBuilder::push_bytes(ext, vers);
        return ext;
    }

    static std::vector<uint8_t> build_compress_certificate()
    {
        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x001b);
        MessageBuilder::push_u16(ext, 0x0003);
        ext.push_back(0x02);
        MessageBuilder::push_u16(ext, 0x0002);
        return ext;
    }

    static std::vector<uint8_t> build_padding(size_t current_len)
    {
        size_t target_len = 517;

        if (current_len >= target_len)
        {
            target_len = current_len + 32;
        }

        size_t padding_needed = target_len - current_len;

        if (padding_needed < 4)
        {
            padding_needed += 32;
        }

        size_t data_len = padding_needed - 4;

        std::vector<uint8_t> ext;
        MessageBuilder::push_u16(ext, 0x0015);
        MessageBuilder::push_u16(ext, static_cast<uint16_t>(data_len));
        ext.insert(ext.end(), data_len, 0x00);
        return ext;
    }
};

inline std::vector<uint8_t> write_record_header(uint8_t record_type, uint16_t length)
{
    std::vector<uint8_t> header;
    header.reserve(5);
    header.push_back(record_type);
    header.push_back(TLS1_2_VERSION_MAJOR);
    header.push_back(TLS1_0_VERSION_MINOR);
    MessageBuilder::push_u16(header, length);
    return header;
}

inline std::vector<uint8_t> construct_client_hello(const std::vector<uint8_t>& client_random,
                                                   const std::vector<uint8_t>& session_id,
                                                   const std::vector<uint8_t>& client_public_key,
                                                   const std::string& server_name)
{
    uint16_t g_cipher = CryptoUtil::get_random_grease();
    uint16_t g_ext1 = CryptoUtil::get_random_grease();
    uint16_t g_ext2 = CryptoUtil::get_random_grease();
    uint16_t g_group = CryptoUtil::get_random_grease();
    uint16_t g_ver = CryptoUtil::get_random_grease();

    std::vector<uint8_t> hello;

    hello.push_back(0x01);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);

    MessageBuilder::push_u16(hello, 0x0303);

    MessageBuilder::push_bytes(hello, client_random);

    hello.push_back(static_cast<uint8_t>(session_id.size()));
    MessageBuilder::push_bytes(hello, session_id);

    std::vector<uint16_t> suites = {
        g_cipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    MessageBuilder::push_u16(hello, static_cast<uint16_t>(suites.size() * 2));
    for (auto s : suites)
    {
        MessageBuilder::push_u16(hello, s);
    }

    hello.push_back(1);
    hello.push_back(0x00);

    std::vector<uint8_t> extensions;

    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_grease_ext(g_ext1));
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_sni_ext(server_name));
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_extended_master_secret());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_renegotiation_info());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_supported_groups(g_group));
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_ec_point_formats());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_session_ticket());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_alpn());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_status_request());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_signature_algorithms());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_sct());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_key_share(g_group, client_public_key));
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_psk_key_exchange_modes());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_supported_versions(g_ver));
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_compress_certificate());
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_grease_ext(g_ext2));

    size_t current_size = hello.size() + 2 + extensions.size();
    MessageBuilder::append_ext(extensions, ChromeClientHelloBuilder::build_padding(current_size));

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
    EVP_DigestSignInit(mctx, nullptr, nullptr, nullptr, signing_key);
    size_t sig_len = 0;
    EVP_DigestSign(mctx, nullptr, &sig_len, to_sign.data(), to_sign.size());
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
    uint32_t pos = 0;
    if (server_hello.size() < 4)
    {
        return {};
    }

    if (server_hello[0] == 0x16)
    {
        pos += 5;
    }

    if (pos + 38 > server_hello.size())
    {
        return {};
    }
    if (server_hello[pos] != 0x02)
    {
        return {};
    }

    pos += 1 + 3 + 2 + 32;

    uint8_t sid_len = server_hello[pos];
    pos += 1 + sid_len;

    pos += 2;
    pos += 1;

    if (pos + 2 > server_hello.size())
    {
        return {};
    }
    uint16_t ext_len = (server_hello[pos] << 8) | server_hello[pos + 1];
    pos += 2;

    size_t end = pos + ext_len;
    if (end > server_hello.size())
    {
        return {};
    }

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
                    return {server_hello.begin() + pos + 4, server_hello.begin() + pos + 4 + 32};
                }
            }
        }
        pos += elen;
    }
    return {};
}

}    // namespace reality

#endif
