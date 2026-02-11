#include <cstdio>
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <algorithm>
#include <system_error>

#include <gtest/gtest.h>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/rand.h>
}

#include "crypto_util.h"
#include "reality_core.h"
#include "reality_messages.h"
#include "reality_fingerprint.h"

using reality::message_builder;
namespace tls_consts = reality::tls_consts;

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
