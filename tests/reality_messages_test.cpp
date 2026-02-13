#include <cstdio>
#include <array>
#include <atomic>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <memory>
#include <cstddef>
#include <algorithm>
#include <optional>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "crypto_util.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "reality_fingerprint.h"

using reality::message_builder;
namespace tls_consts = reality::tls_consts;

extern "C" int __real_RAND_bytes(unsigned char* buf, int num);
extern "C" EVP_PKEY_CTX* __real_EVP_PKEY_CTX_new_id(int id, ENGINE* e);
extern "C" int __real_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
extern "C" int __real_EVP_PKEY_get_octet_string_param(const EVP_PKEY* pkey,
                                                       const char* key_name,
                                                       unsigned char* buf,
                                                       std::size_t max_buf_sz,
                                                       std::size_t* out_len);
extern "C" EVP_MD_CTX* __real_EVP_MD_CTX_new();
extern "C" int __real_EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, std::size_t* siglen, const unsigned char* tbs, std::size_t tbslen);

namespace
{

enum class pkey_octet_mode : int
{
    kPassThrough = 0,
    kSecondCallMismatchedLength = 1,
    kForceSuccessUncompressed = 2,
};

std::atomic<bool> g_force_rand_fail{false};
std::atomic<bool> g_force_pkey_ctx_new_null{false};
std::atomic<bool> g_force_pkey_keygen_fail{false};
std::atomic<bool> g_force_md_ctx_new_null{false};
std::atomic<bool> g_force_digest_sign_fail{false};
std::atomic<int> g_pkey_octet_mode{static_cast<int>(pkey_octet_mode::kPassThrough)};

void reset_reality_message_hooks()
{
    g_force_rand_fail.store(false, std::memory_order_release);
    g_force_pkey_ctx_new_null.store(false, std::memory_order_release);
    g_force_pkey_keygen_fail.store(false, std::memory_order_release);
    g_force_md_ctx_new_null.store(false, std::memory_order_release);
    g_force_digest_sign_fail.store(false, std::memory_order_release);
    g_pkey_octet_mode.store(static_cast<int>(pkey_octet_mode::kPassThrough), std::memory_order_release);
}

class hook_reset_guard
{
   public:
    ~hook_reset_guard() { reset_reality_message_hooks(); }
};

class generic_extension_blueprint final : public reality::extension_blueprint
{
   public:
    [[nodiscard]] reality::extension_type type() const override { return reality::extension_type::kGeneric; }
};

reality::fingerprint_spec make_minimal_key_share_spec(const std::uint16_t group)
{
    reality::fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec.compression_methods = {0x00};

    auto key_share = std::make_shared<reality::key_share_blueprint>();
    key_share->key_shares().push_back({group, {}});
    spec.extensions.push_back(key_share);
    return spec;
}

std::vector<std::uint8_t> build_server_hello_with_extensions(const std::vector<std::uint8_t>& extensions)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0x00);
    hello.push_back(0x00);
    hello.push_back(0x00);
    message_builder::push_u16(hello, tls_consts::kVer12);
    message_builder::push_bytes(hello, std::vector<std::uint8_t>(32, 0x11));
    hello.push_back(0x00);
    message_builder::push_u16(hello, tls_consts::cipher::kTlsAes128GcmSha256);
    hello.push_back(0x00);
    message_builder::push_u16(hello, static_cast<std::uint16_t>(extensions.size()));
    message_builder::push_bytes(hello, extensions);

    const std::size_t total_len = hello.size() - 4;
    hello[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xFF);
    hello[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    hello[3] = static_cast<std::uint8_t>(total_len & 0xFF);
    return hello;
}

std::vector<std::uint8_t> build_encrypted_extensions_with_raw_extensions(const std::vector<std::uint8_t>& extensions)
{
    std::vector<std::uint8_t> msg;
    msg.push_back(0x08);
    msg.push_back(0x00);
    msg.push_back(0x00);
    msg.push_back(0x00);
    message_builder::push_u16(msg, static_cast<std::uint16_t>(extensions.size()));
    message_builder::push_bytes(msg, extensions);

    const std::size_t total_len = msg.size() - 4;
    msg[1] = static_cast<std::uint8_t>((total_len >> 16) & 0xFF);
    msg[2] = static_cast<std::uint8_t>((total_len >> 8) & 0xFF);
    msg[3] = static_cast<std::uint8_t>(total_len & 0xFF);
    return msg;
}

std::optional<std::vector<std::uint8_t>> extract_extension_data_by_type(const std::vector<std::uint8_t>& ch, const std::uint16_t target_ext_type)
{
    if (ch.size() < 4 + 2 + 32 + 1 + 2 + 1 + 2)
    {
        return std::nullopt;
    }

    std::size_t pos = 4 + 2 + 32;
    const std::uint8_t sid_len = ch[pos++];
    if (pos + sid_len > ch.size())
    {
        return std::nullopt;
    }
    pos += sid_len;

    if (pos + 2 > ch.size())
    {
        return std::nullopt;
    }
    const std::uint16_t cipher_len = static_cast<std::uint16_t>((ch[pos] << 8) | ch[pos + 1]);
    pos += 2;
    if (pos + cipher_len > ch.size())
    {
        return std::nullopt;
    }
    pos += cipher_len;

    if (pos + 1 > ch.size())
    {
        return std::nullopt;
    }
    const std::uint8_t comp_len = ch[pos++];
    if (pos + comp_len > ch.size())
    {
        return std::nullopt;
    }
    pos += comp_len;

    if (pos + 2 > ch.size())
    {
        return std::nullopt;
    }
    const std::uint16_t exts_len = static_cast<std::uint16_t>((ch[pos] << 8) | ch[pos + 1]);
    pos += 2;
    if (pos + exts_len > ch.size())
    {
        return std::nullopt;
    }

    const std::size_t exts_end = pos + exts_len;
    while (pos + 4 <= exts_end)
    {
        const std::uint16_t ext_type = static_cast<std::uint16_t>((ch[pos] << 8) | ch[pos + 1]);
        const std::uint16_t ext_len = static_cast<std::uint16_t>((ch[pos + 2] << 8) | ch[pos + 3]);
        pos += 4;
        if (pos + ext_len > exts_end)
        {
            return std::nullopt;
        }

        if (ext_type == target_ext_type)
        {
            return std::vector<std::uint8_t>(ch.begin() + static_cast<std::ptrdiff_t>(pos),
                                             ch.begin() + static_cast<std::ptrdiff_t>(pos + ext_len));
        }

        pos += ext_len;
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> extract_key_share_data_by_group(const std::vector<std::uint8_t>& ch, const std::uint16_t target_group)
{
    const auto key_share_ext = extract_extension_data_by_type(ch, tls_consts::ext::kKeyShare);
    if (!key_share_ext.has_value() || key_share_ext->size() < 2)
    {
        return std::nullopt;
    }

    const auto& ext = *key_share_ext;
    const std::uint16_t share_list_len = static_cast<std::uint16_t>((ext[0] << 8) | ext[1]);
    if (static_cast<std::size_t>(2 + share_list_len) > ext.size())
    {
        return std::nullopt;
    }

    std::size_t share_pos = 2;
    const std::size_t share_end = 2 + share_list_len;
    while (share_pos + 4 <= share_end)
    {
        const std::uint16_t group = static_cast<std::uint16_t>((ext[share_pos] << 8) | ext[share_pos + 1]);
        const std::uint16_t key_len = static_cast<std::uint16_t>((ext[share_pos + 2] << 8) | ext[share_pos + 3]);
        share_pos += 4;
        if (share_pos + key_len > share_end)
        {
            return std::nullopt;
        }
        if (group == target_group)
        {
            return std::vector<std::uint8_t>(ext.begin() + static_cast<std::ptrdiff_t>(share_pos),
                                             ext.begin() + static_cast<std::ptrdiff_t>(share_pos + key_len));
        }
        share_pos += key_len;
    }
    return std::nullopt;
}

std::size_t expected_boring_padding_len(const std::size_t unpadded_len)
{
    if (unpadded_len <= 0xff || unpadded_len >= 0x200)
    {
        return 0;
    }

    std::size_t padding_len = 0x200 - unpadded_len;
    if (padding_len >= 5)
    {
        padding_len -= 4;
    }
    else
    {
        padding_len = 1;
    }
    return padding_len;
}

}    // namespace

extern "C" int __wrap_RAND_bytes(unsigned char* buf, int num)
{
    if (g_force_rand_fail.load(std::memory_order_acquire))
    {
        (void)buf;
        (void)num;
        return 0;
    }
    return __real_RAND_bytes(buf, num);
}

extern "C" EVP_PKEY_CTX* __wrap_EVP_PKEY_CTX_new_id(int id, ENGINE* e)
{
    if (g_force_pkey_ctx_new_null.load(std::memory_order_acquire))
    {
        (void)id;
        (void)e;
        return nullptr;
    }
    return __real_EVP_PKEY_CTX_new_id(id, e);
}

extern "C" int __wrap_EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey)
{
    if (g_force_pkey_keygen_fail.load(std::memory_order_acquire))
    {
        if (ppkey != nullptr)
        {
            *ppkey = nullptr;
        }
        return 0;
    }
    return __real_EVP_PKEY_keygen(ctx, ppkey);
}

extern "C" int __wrap_EVP_PKEY_get_octet_string_param(const EVP_PKEY* pkey,
                                                       const char* key_name,
                                                       unsigned char* buf,
                                                       std::size_t max_buf_sz,
                                                       std::size_t* out_len)
{
    const auto mode = static_cast<pkey_octet_mode>(g_pkey_octet_mode.load(std::memory_order_acquire));
    if (mode == pkey_octet_mode::kSecondCallMismatchedLength)
    {
        if (out_len != nullptr)
        {
            *out_len = (buf == nullptr) ? 65U : (max_buf_sz > 0 ? max_buf_sz - 1 : 0U);
        }
        if (buf != nullptr && max_buf_sz > 0)
        {
            std::memset(buf, 0x5A, max_buf_sz);
            buf[0] = 0x03;
        }
        return 1;
    }
    if (mode == pkey_octet_mode::kForceSuccessUncompressed)
    {
        if (buf == nullptr)
        {
            if (out_len != nullptr)
            {
                *out_len = 65U;
            }
            return 1;
        }
        if (max_buf_sz < 65U)
        {
            return 0;
        }
        std::memset(buf, 0x11, 65);
        buf[0] = 0x04;
        if (out_len != nullptr)
        {
            *out_len = 65U;
        }
        return 1;
    }
    return __real_EVP_PKEY_get_octet_string_param(pkey, key_name, buf, max_buf_sz, out_len);
}

extern "C" EVP_MD_CTX* __wrap_EVP_MD_CTX_new()
{
    if (g_force_md_ctx_new_null.load(std::memory_order_acquire))
    {
        return nullptr;
    }
    return __real_EVP_MD_CTX_new();
}

extern "C" int __wrap_EVP_DigestSign(EVP_MD_CTX* ctx, unsigned char* sigret, std::size_t* siglen, const unsigned char* tbs, std::size_t tbslen)
{
    if (g_force_digest_sign_fail.load(std::memory_order_acquire))
    {
        return 0;
    }
    return __real_EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}

TEST(RealityMessagesTest, RecordHeader)
{
    const auto header = reality::write_record_header(0x16, 0x1234);
    ASSERT_EQ(header.size(), 5);
    EXPECT_EQ(header[0], 0x16);
    EXPECT_EQ(header[1], 0x03);
    EXPECT_EQ(header[2], 0x03);
    EXPECT_EQ(header[3], 0x12);
    EXPECT_EQ(header[4], 0x34);
}

TEST(RealityMessagesTest, ServerHelloRoundTrip)
{
    const std::vector<std::uint8_t> random(32, 0xAA);
    const std::vector<std::uint8_t> session_id(32, 0xBB);
    const std::uint16_t cipher = 0x1301;
    const std::vector<std::uint8_t> pubkey(32, 0xCC);

    const auto sh = reality::construct_server_hello(random, session_id, cipher, tls_consts::group::kX25519, pubkey);

    const auto extracted_cipher = reality::extract_cipher_suite_from_server_hello(sh);
    ASSERT_TRUE(extracted_cipher.has_value());
    EXPECT_EQ(*extracted_cipher, cipher);

    const auto extracted_pub = reality::extract_server_public_key(sh);
    EXPECT_EQ(extracted_pub, pubkey);
}

TEST(RealityMessagesTest, EncryptedExtensionsALPN)
{
    const std::string alpn = "h2";
    const auto msg = reality::construct_encrypted_extensions(alpn);

    const auto extracted_alpn = reality::extract_alpn_from_encrypted_extensions(msg);
    ASSERT_TRUE(extracted_alpn.has_value());
    EXPECT_EQ(*extracted_alpn, alpn);
}

TEST(RealityMessagesTest, EncryptedExtensionsNoALPN)
{
    const auto msg = reality::construct_encrypted_extensions("");
    const auto extracted_alpn = reality::extract_alpn_from_encrypted_extensions(msg);

    EXPECT_FALSE(extracted_alpn.has_value());
}

TEST(RealityMessagesTest, ServerHelloInvalid)
{
    const std::vector<std::uint8_t> short_buf(10, 0x00);
    EXPECT_FALSE(reality::extract_cipher_suite_from_server_hello(short_buf).has_value());
    EXPECT_TRUE(reality::extract_server_public_key(short_buf).empty());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsOversizedExtensionsLength)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0x00);
    hello.push_back(0x00);
    hello.push_back(0x00);
    message_builder::push_u16(hello, 0x0303);
    const std::vector<std::uint8_t> random(32, 0x11);
    message_builder::push_bytes(hello, random);
    hello.push_back(0x00);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0x00);
    message_builder::push_u16(hello, 0x0010);

    EXPECT_FALSE(reality::extract_server_key_share(hello).has_value());
    EXPECT_TRUE(reality::extract_server_public_key(hello).empty());
}

TEST(RealityMessagesTest, client_hello_builderFirefox)
{
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kFirefox120);
    const std::vector<std::uint8_t> session_id(32, 0xEE);
    const std::vector<std::uint8_t> random(32, 0xAA);
    const std::vector<std::uint8_t> pubkey(32, 0xBB);
    const std::string host = "example.com";

    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);

    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, client_hello_builderChrome)
{
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
    const std::vector<std::uint8_t> session_id(32, 0xEE);
    const std::vector<std::uint8_t> random(32, 0xAA);
    const std::vector<std::uint8_t> pubkey(32, 0xBB);
    const std::string host = "google.com";

    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);
    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, ExtractServerPublicKeyNoKeyShare)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    const std::vector<std::uint8_t> random(32, 0xAA);
    message_builder::push_bytes(hello, random);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0);

    message_builder::push_u16(hello, 0);

    const std::size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<std::uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, static_cast<std::uint16_t>(hello.size()));
    message_builder::push_bytes(record, hello);

    const auto key = reality::extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, ExtractServerPublicKeyMalformedKeyShare)
{
    std::vector<std::uint8_t> hello;
    hello.push_back(0x02);
    hello.push_back(0);
    hello.push_back(0);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x0303);
    const std::vector<std::uint8_t> random(32, 0xAA);
    message_builder::push_bytes(hello, random);
    hello.push_back(0);
    message_builder::push_u16(hello, 0x1301);
    hello.push_back(0);

    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kKeyShare);
    message_builder::push_u16(extensions, 2);
    message_builder::push_u16(extensions, 0x001d);

    message_builder::push_u16(hello, static_cast<std::uint16_t>(extensions.size()));
    message_builder::push_bytes(hello, extensions);

    const std::size_t total_len = hello.size() - 4;
    hello[1] = (total_len >> 16) & 0xFF;
    hello[2] = (total_len >> 8) & 0xFF;
    hello[3] = total_len & 0xFF;

    std::vector<std::uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    message_builder::push_u16(record, static_cast<std::uint16_t>(hello.size()));
    message_builder::push_bytes(record, hello);

    const auto key = reality::extract_server_public_key(record);
    EXPECT_TRUE(key.empty());
}

TEST(RealityMessagesTest, CipherSuiteShort)
{
    const std::vector<std::uint8_t> buf = {0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0C, 0x03, 0x03};

    EXPECT_FALSE(reality::extract_cipher_suite_from_server_hello(buf).has_value());
}

TEST(RealityMessagesTest, ExtractALPNMalformed)
{
    std::vector<std::uint8_t> bad_msg = {0x08, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00, 0x05, 0x01, 0x61};
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(bad_msg).has_value());
}

TEST(RealityMessagesTest, CertificateVerifyParse)
{
    std::array<std::uint8_t, 32> priv{};
    ASSERT_EQ(RAND_bytes(priv.data(), static_cast<int>(priv.size())), 1);

    const reality::openssl_ptrs::evp_pkey_ptr priv_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size()));
    ASSERT_TRUE(priv_key);

    const std::vector<std::uint8_t> handshake_hash(32, 0x11);
    const auto cv = reality::construct_certificate_verify(priv_key.get(), handshake_hash);
    const auto info = reality::parse_certificate_verify(cv);
    ASSERT_TRUE(info.has_value());

    if (info.has_value())
    {
        EXPECT_EQ(info->scheme, 0x0807);
        EXPECT_FALSE(info->signature.empty());
    }
}

TEST(RealityMessagesTest, CertificateVerifyReturnsEmptyWhenMdCtxCreationFails)
{
    hook_reset_guard guard;

    std::array<std::uint8_t, 32> priv{};
    ASSERT_EQ(RAND_bytes(priv.data(), static_cast<int>(priv.size())), 1);

    const reality::openssl_ptrs::evp_pkey_ptr priv_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size()));
    ASSERT_TRUE(priv_key);

    g_force_md_ctx_new_null.store(true, std::memory_order_release);
    const auto cv = reality::construct_certificate_verify(priv_key.get(), std::vector<std::uint8_t>(32, 0x33));
    EXPECT_TRUE(cv.empty());
}

TEST(RealityMessagesTest, CertificateVerifyReturnsEmptyWhenDigestSignFails)
{
    hook_reset_guard guard;

    std::array<std::uint8_t, 32> priv{};
    ASSERT_EQ(RAND_bytes(priv.data(), static_cast<int>(priv.size())), 1);

    const reality::openssl_ptrs::evp_pkey_ptr priv_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, priv.data(), priv.size()));
    ASSERT_TRUE(priv_key);

    g_force_digest_sign_fail.store(true, std::memory_order_release);
    const auto cv = reality::construct_certificate_verify(priv_key.get(), std::vector<std::uint8_t>(32, 0x44));
    EXPECT_TRUE(cv.empty());
}

TEST(RealityMessagesTest, CertificateVerifySchemeSupport)
{
    EXPECT_TRUE(reality::is_supported_certificate_verify_scheme(0x0807));
    EXPECT_TRUE(reality::is_supported_certificate_verify_scheme(0x0804));
    EXPECT_FALSE(reality::is_supported_certificate_verify_scheme(0x0808));
}

TEST(RealityMessagesTest, ParseCertificateVerifyMalformed)
{
    std::vector<std::uint8_t> bad_cv = {0x0f, 0x00, 0x00, 0x01, 0x08};
    EXPECT_FALSE(reality::parse_certificate_verify(bad_cv).has_value());

    bad_cv = {0x0f, 0x00, 0x00, 0x03, 0x08, 0x07, 0x00};
    EXPECT_FALSE(reality::parse_certificate_verify(bad_cv).has_value());
}

TEST(RealityMessagesTest, MessageBuilderPushBytesFromPointer)
{
    std::vector<std::uint8_t> buf = {0x10};
    const std::uint8_t raw[] = {0xAA, 0xBB, 0xCC};
    message_builder::push_bytes(buf, raw, sizeof(raw));

    const std::vector<std::uint8_t> expected = {0x10, 0xAA, 0xBB, 0xCC};
    EXPECT_EQ(buf, expected);
}

TEST(RealityMessagesTest, ClientHelloSkipsUnknownGenericExtension)
{
    reality::fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec.compression_methods = {0x00};
    spec.extensions.push_back(std::make_shared<generic_extension_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0x01);
    const std::vector<std::uint8_t> random(32, 0x02);
    const std::vector<std::uint8_t> pubkey(32, 0x03);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    ASSERT_GT(ch.size(), 4U);

    std::size_t pos = 4 + 2 + 32;
    const std::uint8_t sid_len = ch[pos++];
    pos += sid_len;
    const std::uint16_t cipher_len = static_cast<std::uint16_t>((ch[pos] << 8) | ch[pos + 1]);
    pos += 2 + cipher_len;
    const std::uint8_t comp_len = ch[pos++];
    pos += comp_len;
    const std::uint16_t exts_len = static_cast<std::uint16_t>((ch[pos] << 8) | ch[pos + 1]);
    EXPECT_EQ(exts_len, 0);
}

TEST(RealityMessagesTest, ClientHelloKeyShareUnknownGroupUsesEmptyData)
{
    const auto spec = make_minimal_key_share_spec(0x9999);
    const std::vector<std::uint8_t> session_id(32, 0x11);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x33);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");

    const auto key_share = extract_key_share_data_by_group(ch, 0x9999);
    ASSERT_TRUE(key_share.has_value());
    EXPECT_TRUE(key_share->empty());
}

TEST(RealityMessagesTest, ClientHelloGreaseEchHandlesRandFailure)
{
    hook_reset_guard guard;
    reality::fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec.compression_methods = {0x00};
    spec.extensions.push_back(std::make_shared<reality::grease_ech_blueprint>());

    g_force_rand_fail.store(true, std::memory_order_release);
    const std::vector<std::uint8_t> session_id(32, 0x11);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x33);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    EXPECT_FALSE(ch.empty());
    EXPECT_FALSE(extract_extension_data_by_type(ch, tls_consts::ext::kGreaseEch).has_value());
}

TEST(RealityMessagesTest, ClientHelloPreSharedKeySkipsExtensionWhenRandFails)
{
    hook_reset_guard guard;
    reality::fingerprint_spec spec;
    spec.client_version = tls_consts::kVer12;
    spec.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec.compression_methods = {0x00};
    spec.extensions.push_back(std::make_shared<reality::pre_shared_key_blueprint>());

    g_force_rand_fail.store(true, std::memory_order_release);
    const std::vector<std::uint8_t> session_id(32, 0x11);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x33);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    EXPECT_FALSE(ch.empty());
    EXPECT_FALSE(extract_extension_data_by_type(ch, tls_consts::ext::kPreSharedKey).has_value());
}

TEST(RealityMessagesTest, Secp256r1KeyShareFallsBackWhenCtxCreationFails)
{
    hook_reset_guard guard;
    g_force_pkey_ctx_new_null.store(true, std::memory_order_release);

    const auto spec = make_minimal_key_share_spec(tls_consts::group::kSecp256r1);
    const std::vector<std::uint8_t> session_id(32, 0x31);
    const std::vector<std::uint8_t> random(32, 0x32);
    const std::vector<std::uint8_t> pubkey(32, 0x33);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    const auto key_share = extract_key_share_data_by_group(ch, tls_consts::group::kSecp256r1);
    ASSERT_TRUE(key_share.has_value());
    EXPECT_EQ(key_share->size(), 65U);
}

TEST(RealityMessagesTest, Secp256r1KeyShareFallsBackWhenKeygenFails)
{
    hook_reset_guard guard;
    g_force_pkey_keygen_fail.store(true, std::memory_order_release);

    const auto spec = make_minimal_key_share_spec(tls_consts::group::kSecp256r1);
    const std::vector<std::uint8_t> session_id(32, 0x41);
    const std::vector<std::uint8_t> random(32, 0x42);
    const std::vector<std::uint8_t> pubkey(32, 0x43);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    const auto key_share = extract_key_share_data_by_group(ch, tls_consts::group::kSecp256r1);
    ASSERT_TRUE(key_share.has_value());
    EXPECT_EQ(key_share->size(), 65U);
}

TEST(RealityMessagesTest, Secp256r1KeyShareFallsBackWhenOctetLengthMismatch)
{
    hook_reset_guard guard;
    g_pkey_octet_mode.store(static_cast<int>(pkey_octet_mode::kSecondCallMismatchedLength), std::memory_order_release);

    const auto spec = make_minimal_key_share_spec(tls_consts::group::kSecp256r1);
    const std::vector<std::uint8_t> session_id(32, 0x51);
    const std::vector<std::uint8_t> random(32, 0x52);
    const std::vector<std::uint8_t> pubkey(32, 0x53);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    const auto key_share = extract_key_share_data_by_group(ch, tls_consts::group::kSecp256r1);
    ASSERT_TRUE(key_share.has_value());
    EXPECT_EQ(key_share->size(), 65U);
}

TEST(RealityMessagesTest, Secp256r1KeyShareUsesGeneratedOctetStringWhenAvailable)
{
    hook_reset_guard guard;
    g_pkey_octet_mode.store(static_cast<int>(pkey_octet_mode::kForceSuccessUncompressed), std::memory_order_release);

    const auto spec = make_minimal_key_share_spec(tls_consts::group::kSecp256r1);
    const std::vector<std::uint8_t> session_id(32, 0x61);
    const std::vector<std::uint8_t> random(32, 0x62);
    const std::vector<std::uint8_t> pubkey(32, 0x63);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");
    const auto key_share = extract_key_share_data_by_group(ch, tls_consts::group::kSecp256r1);
    ASSERT_TRUE(key_share.has_value());
    ASSERT_EQ(key_share->size(), 65U);
    EXPECT_EQ((*key_share)[0], 0x04);
}

TEST(RealityMessagesTest, ParseCertificateVerifyRejectsSignatureLengthOverflow)
{
    const std::vector<std::uint8_t> bad_cv = {0x0f, 0x00, 0x00, 0x04, 0x08, 0x07, 0x00, 0x10};
    EXPECT_FALSE(reality::parse_certificate_verify(bad_cv).has_value());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsTooShortPrefix)
{
    const std::vector<std::uint8_t> short_msg = {0x16, 0x03, 0x03};
    EXPECT_FALSE(reality::extract_server_key_share(short_msg).has_value());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsMissingSessionIdLength)
{
    std::vector<std::uint8_t> hello = {0x02, 0x00, 0x00, 0x00};
    message_builder::push_u16(hello, tls_consts::kVer12);
    message_builder::push_bytes(hello, std::vector<std::uint8_t>(32, 0x21));
    EXPECT_FALSE(reality::extract_server_key_share(hello).has_value());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsHeaderOnlyKeyShare)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kKeyShare);
    message_builder::push_u16(extensions, 4);
    const auto hello = build_server_hello_with_extensions(extensions);
    EXPECT_FALSE(reality::extract_server_key_share(hello).has_value());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsTruncatedKeyShareData)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kKeyShare);
    message_builder::push_u16(extensions, 4);
    message_builder::push_u16(extensions, tls_consts::group::kX25519);
    message_builder::push_u16(extensions, 32);
    const auto hello = build_server_hello_with_extensions(extensions);
    EXPECT_FALSE(reality::extract_server_key_share(hello).has_value());
}

TEST(RealityMessagesTest, ExtractServerKeyShareRejectsExtensionPayloadOverflow)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kSupportedVersions);
    message_builder::push_u16(extensions, 16);
    extensions.push_back(0x03);
    const auto hello = build_server_hello_with_extensions(extensions);
    EXPECT_FALSE(reality::extract_server_key_share(hello).has_value());
}

TEST(RealityMessagesTest, ExtractServerPublicKeyRejectsWrongX25519Length)
{
    const auto sh = reality::construct_server_hello(
        std::vector<std::uint8_t>(32, 0x10), std::vector<std::uint8_t>(32, 0x20), 0x1301, tls_consts::group::kX25519, std::vector<std::uint8_t>(31, 0x30));
    EXPECT_TRUE(reality::extract_server_public_key(sh).empty());
}

TEST(RealityMessagesTest, ExtractServerPublicKeyRejectsUnsupportedGroup)
{
    const auto sh = reality::construct_server_hello(std::vector<std::uint8_t>(32, 0x10),
                                                    std::vector<std::uint8_t>(32, 0x20),
                                                    0x1301,
                                                    tls_consts::group::kSecp256r1,
                                                    std::vector<std::uint8_t>(65, 0x30));
    EXPECT_TRUE(reality::extract_server_public_key(sh).empty());
}

TEST(RealityMessagesTest, ExtractAlpnRejectsWrongHandshakeType)
{
    const std::vector<std::uint8_t> bad_msg = {0x09, 0x00, 0x00, 0x00, 0x00, 0x00};
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(bad_msg).has_value());
}

TEST(RealityMessagesTest, ExtractAlpnRejectsOversizedExtensionsRange)
{
    const std::vector<std::uint8_t> bad_msg = {0x08, 0x00, 0x00, 0x00, 0x00, 0x10};
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(bad_msg).has_value());
}

TEST(RealityMessagesTest, ExtractAlpnBreaksOnExtensionLengthOverflow)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kAlpn);
    message_builder::push_u16(extensions, 4);
    extensions.push_back(0x00);
    const auto msg = build_encrypted_extensions_with_raw_extensions(extensions);
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(msg).has_value());
}

TEST(RealityMessagesTest, ExtractAlpnRejectsTooShortAlpnBody)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kAlpn);
    message_builder::push_u16(extensions, 2);
    extensions.push_back(0x00);
    extensions.push_back(0x00);
    const auto msg = build_encrypted_extensions_with_raw_extensions(extensions);
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(msg).has_value());
}

TEST(RealityMessagesTest, ExtractAlpnRejectsZeroLengthProtocolList)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kAlpn);
    message_builder::push_u16(extensions, 3);
    extensions.push_back(0x00);
    extensions.push_back(0x00);
    extensions.push_back(0x01);
    const auto msg = build_encrypted_extensions_with_raw_extensions(extensions);
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(msg).has_value());
}

TEST(RealityMessagesTest, ExtractAlpnRejectsProtocolOverflow)
{
    std::vector<std::uint8_t> extensions;
    message_builder::push_u16(extensions, tls_consts::ext::kAlpn);
    message_builder::push_u16(extensions, 4);
    extensions.push_back(0x00);
    extensions.push_back(0x02);
    extensions.push_back(0x05);
    extensions.push_back(0x41);
    const auto msg = build_encrypted_extensions_with_raw_extensions(extensions);
    EXPECT_FALSE(reality::extract_alpn_from_encrypted_extensions(msg).has_value());
}

TEST(RealityMessagesTest, ComprehensiveClientHello)
{
    reality::fingerprint_spec spec;
    spec.client_version = 0x0303;
    spec.cipher_suites = {0x1301, 0x1302, 0x1303, reality::kGreasePlaceholder};
    spec.compression_methods = {0x00};

    spec.extensions.push_back(std::make_shared<reality::grease_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::sni_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::ems_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::renegotiation_blueprint>());

    auto groups = std::make_shared<reality::supported_groups_blueprint>();
    groups->groups() = {0x001d, reality::kGreasePlaceholder};
    spec.extensions.push_back(groups);

    auto ec_points = std::make_shared<reality::ec_point_formats_blueprint>();
    ec_points->formats() = {0x00};
    spec.extensions.push_back(ec_points);

    spec.extensions.push_back(std::make_shared<reality::session_ticket_blueprint>());

    auto alpn = std::make_shared<reality::alpn_blueprint>();
    alpn->protocols() = {"h2", "http/1.1"};
    spec.extensions.push_back(alpn);

    spec.extensions.push_back(std::make_shared<reality::status_request_blueprint>());

    auto sig_algs = std::make_shared<reality::signature_algorithms_blueprint>();
    sig_algs->algorithms() = {0x0403, 0x0804};
    spec.extensions.push_back(sig_algs);

    spec.extensions.push_back(std::make_shared<reality::sct_blueprint>());

    auto key_share = std::make_shared<reality::key_share_blueprint>();
    key_share->key_shares().push_back({0x001d, std::vector<uint8_t>(32, 0x01)});
    key_share->key_shares().push_back({reality::kGreasePlaceholder, {}});
    key_share->key_shares().push_back({reality::tls_consts::group::kSecp256r1, {}});
    spec.extensions.push_back(key_share);

    auto psk_modes = std::make_shared<reality::psk_key_exchange_modes_blueprint>();
    psk_modes->modes() = {0x01};
    spec.extensions.push_back(psk_modes);

    auto versions = std::make_shared<reality::supported_versions_blueprint>();
    versions->versions() = {0x0304, reality::kGreasePlaceholder};
    spec.extensions.push_back(versions);

    auto compress_cert = std::make_shared<reality::compress_cert_blueprint>();
    compress_cert->algorithms() = {0x0002};
    spec.extensions.push_back(compress_cert);

    auto app_settings = std::make_shared<reality::application_settings_blueprint>();
    app_settings->supported_protocols() = {"h2"};
    spec.extensions.push_back(app_settings);

    auto app_settings_new = std::make_shared<reality::application_settings_new_blueprint>();
    app_settings_new->supported_protocols() = {"h3"};
    spec.extensions.push_back(app_settings_new);

    spec.extensions.push_back(std::make_shared<reality::grease_ech_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::npn_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::channel_id_blueprint>());

    auto delegated_creds = std::make_shared<reality::delegated_credentials_blueprint>();
    delegated_creds->algorithms() = {0x0403};
    spec.extensions.push_back(delegated_creds);

    auto record_limit = std::make_shared<reality::record_size_limit_blueprint>();
    record_limit->limit() = 16384;
    spec.extensions.push_back(record_limit);

    spec.extensions.push_back(std::make_shared<reality::pre_shared_key_blueprint>());
    spec.extensions.push_back(std::make_shared<reality::padding_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0xEE);
    const std::vector<std::uint8_t> random(32, 0xAA);
    const std::vector<std::uint8_t> pubkey(32, 0xBB);
    const std::string host = "example.com";

    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, host);
    ASSERT_GT(ch.size(), 100);
    EXPECT_EQ(ch[0], 0x01);
}

TEST(RealityMessagesTest, FirefoxSecp256r1KeyShareIsValidPoint)
{
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kFirefox120);
    const std::vector<std::uint8_t> session_id(32, 0x11);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x33);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");

    const auto key_share = extract_key_share_data_by_group(ch, tls_consts::group::kSecp256r1);
    ASSERT_TRUE(key_share.has_value());
    ASSERT_EQ(key_share->size(), 65);
    EXPECT_EQ((*key_share)[0], 0x04);

    const std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), &EC_GROUP_free);
    ASSERT_NE(group.get(), nullptr);
    const std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(group.get()), &EC_POINT_free);
    ASSERT_NE(point.get(), nullptr);
    EXPECT_EQ(EC_POINT_oct2point(group.get(), point.get(), key_share->data(), key_share->size(), nullptr), 1);
}

TEST(RealityMessagesTest, ChromeGreaseEchMatchesBoringShape)
{
    const auto spec = reality::fingerprint_factory::get(reality::fingerprint_type::kChrome120);
    const std::vector<std::uint8_t> session_id(32, 0x41);
    const std::vector<std::uint8_t> random(32, 0x42);
    const std::vector<std::uint8_t> pubkey(32, 0x43);
    const auto ch = reality::client_hello_builder::build(spec, session_id, random, pubkey, "example.com");

    const auto ech = extract_extension_data_by_type(ch, tls_consts::ext::kGreaseEch);
    ASSERT_TRUE(ech.has_value());
    ASSERT_GE(ech->size(), 1 + 2 + 2 + 1 + 2 + 32 + 2 + 144);
    const auto& data = *ech;

    EXPECT_EQ(data[0], 0x00);
    EXPECT_EQ(static_cast<std::uint16_t>((data[1] << 8) | data[2]), 0x0001);
    EXPECT_EQ(static_cast<std::uint16_t>((data[3] << 8) | data[4]), 0x0001);

    std::size_t pos = 6;
    ASSERT_GE(data.size(), pos + 2);
    const std::uint16_t enc_len = static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
    EXPECT_EQ(enc_len, 32);
    pos += 2;

    ASSERT_GE(data.size(), pos + enc_len + 2);
    pos += enc_len;
    const std::uint16_t payload_len = static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
    pos += 2;
    ASSERT_EQ(data.size(), pos + payload_len);
    EXPECT_TRUE(payload_len == 144 || payload_len == 176 || payload_len == 208 || payload_len == 240);
}

TEST(RealityMessagesTest, PaddingUsesBoringStyleFormula)
{
    auto spec_no_padding = reality::fingerprint_factory::get(reality::fingerprint_type::kFirefox120);
    std::erase_if(spec_no_padding.extensions,
                  [](const std::shared_ptr<reality::extension_blueprint>& ext)
                  {
                      return ext->type() == reality::extension_type::kPadding;
                  });

    auto spec_with_padding = spec_no_padding;
    spec_with_padding.extensions.push_back(std::make_shared<reality::padding_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0x21);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x23);
    const auto no_pad = reality::client_hello_builder::build(spec_no_padding, session_id, random, pubkey, "example.com");
    const auto with_pad = reality::client_hello_builder::build(spec_with_padding, session_id, random, pubkey, "example.com");

    const auto padding = extract_extension_data_by_type(with_pad, tls_consts::ext::kPadding);
    ASSERT_TRUE(padding.has_value());

    const std::size_t unpadded_len = no_pad.size() + 4;
    EXPECT_EQ(padding->size(), expected_boring_padding_len(unpadded_len));
}

TEST(RealityMessagesTest, PaddingDisabledForShortClientHello)
{
    reality::fingerprint_spec spec_no_padding;
    spec_no_padding.client_version = tls_consts::kVer12;
    spec_no_padding.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec_no_padding.compression_methods = {0x00};

    auto spec_with_padding = spec_no_padding;
    spec_with_padding.extensions.push_back(std::make_shared<reality::padding_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0x11);
    const std::vector<std::uint8_t> random(32, 0x12);
    const std::vector<std::uint8_t> pubkey(32, 0x13);
    const auto no_pad = reality::client_hello_builder::build(spec_no_padding, session_id, random, pubkey, "x.com");
    const auto with_pad = reality::client_hello_builder::build(spec_with_padding, session_id, random, pubkey, "x.com");

    ASSERT_LT(no_pad.size() + 4, 0x100);
    const auto padding = extract_extension_data_by_type(with_pad, tls_consts::ext::kPadding);
    ASSERT_TRUE(padding.has_value());
    EXPECT_EQ(padding->size(), 0);
}

TEST(RealityMessagesTest, PaddingNearUpperBoundUsesSingleByte)
{
    reality::fingerprint_spec spec_no_padding;
    spec_no_padding.client_version = tls_consts::kVer12;
    spec_no_padding.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec_no_padding.compression_methods = {0x00};
    spec_no_padding.extensions.push_back(std::make_shared<reality::sni_blueprint>());

    auto spec_with_padding = spec_no_padding;
    spec_with_padding.extensions.push_back(std::make_shared<reality::padding_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0x31);
    const std::vector<std::uint8_t> random(32, 0x32);
    const std::vector<std::uint8_t> pubkey(32, 0x33);

    std::optional<std::string> near_upper_bound_host;
    std::size_t near_upper_bound_unpadded_len = 0;
    for (std::size_t host_len = 1; host_len <= 900; ++host_len)
    {
        const std::string candidate_host(host_len, 'a');
        const auto no_pad = reality::client_hello_builder::build(spec_no_padding, session_id, random, pubkey, candidate_host);
        const std::size_t unpadded_len = no_pad.size() + 4;
        if (unpadded_len >= 0x1fc && unpadded_len <= 0x1ff)
        {
            near_upper_bound_host = candidate_host;
            near_upper_bound_unpadded_len = unpadded_len;
            break;
        }
    }

    ASSERT_TRUE(near_upper_bound_host.has_value());
    const auto with_pad = reality::client_hello_builder::build(spec_with_padding, session_id, random, pubkey, *near_upper_bound_host);
    const auto padding = extract_extension_data_by_type(with_pad, tls_consts::ext::kPadding);
    ASSERT_TRUE(padding.has_value());
    EXPECT_EQ(expected_boring_padding_len(near_upper_bound_unpadded_len), 1);
    EXPECT_EQ(padding->size(), 1);
}

TEST(RealityMessagesTest, PaddingDisabledForOversizedClientHello)
{
    reality::fingerprint_spec spec_no_padding;
    spec_no_padding.client_version = tls_consts::kVer12;
    spec_no_padding.cipher_suites = {tls_consts::cipher::kTlsAes128GcmSha256};
    spec_no_padding.compression_methods = {0x00};
    spec_no_padding.extensions.push_back(std::make_shared<reality::sni_blueprint>());

    auto spec_with_padding = spec_no_padding;
    spec_with_padding.extensions.push_back(std::make_shared<reality::padding_blueprint>());

    const std::vector<std::uint8_t> session_id(32, 0x21);
    const std::vector<std::uint8_t> random(32, 0x22);
    const std::vector<std::uint8_t> pubkey(32, 0x23);
    const std::string long_host(700, 'a');
    const auto no_pad = reality::client_hello_builder::build(spec_no_padding, session_id, random, pubkey, long_host);
    const auto with_pad = reality::client_hello_builder::build(spec_with_padding, session_id, random, pubkey, long_host);

    ASSERT_GT(no_pad.size() + 4, 0x1ff);
    const auto padding = extract_extension_data_by_type(with_pad, tls_consts::ext::kPadding);
    ASSERT_TRUE(padding.has_value());
    EXPECT_EQ(padding->size(), 0);
}
