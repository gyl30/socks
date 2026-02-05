#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

namespace reality
{

static constexpr std::uint8_t K_REALITY_INFO[] = "REALITY";
static constexpr std::uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
static constexpr std::uint8_t CONTENT_TYPE_ALERT = 0x15;
static constexpr std::uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
static constexpr std::uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

static constexpr std::size_t TLS_RECORD_HEADER_SIZE = 5;
static constexpr std::size_t AEAD_TAG_SIZE = 16;
static constexpr std::size_t MAX_TLS_PLAINTEXT_LEN = 16384;

static constexpr std::uint16_t GREASE_PLACEHOLDER = 0x0A0A;

namespace tls_consts
{
constexpr std::uint16_t VER_1_0 = 0x0301;
constexpr std::uint16_t VER_1_1 = 0x0302;
constexpr std::uint16_t VER_1_2 = 0x0303;
constexpr std::uint16_t VER_1_3 = 0x0304;

namespace ext
{
constexpr std::uint16_t SNI = 0x0000;
constexpr std::uint16_t STATUS_REQUEST = 0x0005;
constexpr std::uint16_t SUPPORTED_GROUPS = 0x000a;
constexpr std::uint16_t EC_POINT_FORMATS = 0x000b;
constexpr std::uint16_t SIGNATURE_ALG = 0x000d;
constexpr std::uint16_t ALPN = 0x0010;
constexpr std::uint16_t SCT = 0x0012;
constexpr std::uint16_t PADDING = 0x0015;
constexpr std::uint16_t EXT_MASTER_SECRET = 0x0017;
constexpr std::uint16_t COMPRESS_CERT = 0x001b;
constexpr std::uint16_t RECORD_SIZE_LIMIT = 0x001c;
constexpr std::uint16_t SESSION_TICKET = 0x0023;
constexpr std::uint16_t PRE_SHARED_KEY = 0x0029;
constexpr std::uint16_t SUPPORTED_VERSIONS = 0x002b;
constexpr std::uint16_t PSK_KEY_EXCHANGE_MODES = 0x002d;
constexpr std::uint16_t KEY_SHARE = 0x0033;
constexpr std::uint16_t DELEGATED_CREDENTIALS = 0x0022;
constexpr std::uint16_t CHANNEL_ID = 0x3003;
constexpr std::uint16_t CHANNEL_ID_LEGACY = 0x7550;
constexpr std::uint16_t NPN = 0x3374;
constexpr std::uint16_t APPLICATION_SETTINGS = 0x4469;
constexpr std::uint16_t APPLICATION_SETTINGS_NEW = 0x44cd;
constexpr std::uint16_t RENEGOTIATION_INFO = 0xff01;
constexpr std::uint16_t ECH_OUTER_EXTENSIONS = 0xfd00;
constexpr std::uint16_t GREASE_ECH = 0xfe0d;
}    // namespace ext

namespace group
{
constexpr std::uint16_t SECP256R1 = 0x0017;
constexpr std::uint16_t SECP384R1 = 0x0018;
constexpr std::uint16_t SECP521R1 = 0x0019;
constexpr std::uint16_t X25519 = 0x001d;
constexpr std::uint16_t FFDHE2048 = 0x0100;
constexpr std::uint16_t FFDHE3072 = 0x0101;

constexpr std::uint16_t X25519_KYBER768_DRAFT00 = 0x6399;
constexpr std::uint16_t X25519_KYBER512_DRAFT00 = 0xfe30;
constexpr std::uint16_t X25519_MLKEM768 = 0x11EC;
}    // namespace group

namespace sig_alg
{
constexpr std::uint16_t RSA_PKCS1_SHA1 = 0x0201;
constexpr std::uint16_t ECDSA_SHA1 = 0x0203;
constexpr std::uint16_t RSA_PKCS1_SHA256 = 0x0401;
constexpr std::uint16_t ECDSA_SECP256R1_SHA256 = 0x0403;
constexpr std::uint16_t RSA_PKCS1_SHA384 = 0x0501;
constexpr std::uint16_t ECDSA_SECP384R1_SHA384 = 0x0503;
constexpr std::uint16_t RSA_PKCS1_SHA512 = 0x0601;
constexpr std::uint16_t ECDSA_SECP521R1_SHA512 = 0x0603;
constexpr std::uint16_t RSA_PSS_RSAE_SHA256 = 0x0804;
constexpr std::uint16_t RSA_PSS_RSAE_SHA384 = 0x0805;
constexpr std::uint16_t RSA_PSS_RSAE_SHA512 = 0x0806;

constexpr std::uint16_t FAKE_DSA_SHA1 = 0x0202;
constexpr std::uint16_t FAKE_DSA_SHA256 = 0x0402;
}    // namespace sig_alg

namespace compress
{
constexpr std::uint16_t DEFLATE = 0x0001;
constexpr std::uint16_t BROTLI = 0x0002;
}    // namespace compress

namespace cipher
{

constexpr std::uint16_t TLS_AES_128_GCM_SHA256 = 0x1301;
constexpr std::uint16_t TLS_AES_256_GCM_SHA384 = 0x1302;
constexpr std::uint16_t TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = 0xcca9;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = 0xcca8;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_OLD = 0xcc13;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_OLD = 0xcc14;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xc008;
constexpr std::uint16_t TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xc007;
constexpr std::uint16_t TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xc011;

constexpr std::uint16_t TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c;
constexpr std::uint16_t TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d;
constexpr std::uint16_t TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f;
constexpr std::uint16_t TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
constexpr std::uint16_t TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c;
constexpr std::uint16_t TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d;
constexpr std::uint16_t TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a;
constexpr std::uint16_t TLS_RSA_WITH_RC4_128_SHA = 0x0005;
constexpr std::uint16_t TLS_RSA_WITH_RC4_128_MD5 = 0x0004;

constexpr std::uint16_t TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033;
constexpr std::uint16_t TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039;
constexpr std::uint16_t TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067;
constexpr std::uint16_t TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006b;
constexpr std::uint16_t TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032;
}    // namespace cipher

}    // namespace tls_consts

namespace openssl_ptrs
{
struct evp_pkey_deleter
{
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct evp_pkey_ctx_deleter
{
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct evp_cipher_ctx_deleter
{
    void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
struct evp_md_ctx_deleter
{
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct x509_deleter
{
    void operator()(X509* p) const { X509_free(p); }
};

using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
using evp_pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, evp_pkey_ctx_deleter>;
using evp_cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, evp_cipher_ctx_deleter>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, evp_md_ctx_deleter>;
using x509_ptr = std::unique_ptr<X509, x509_deleter>;
}    // namespace openssl_ptrs

struct handshake_keys
{
    std::vector<std::uint8_t> client_handshake_traffic_secret;
    std::vector<std::uint8_t> server_handshake_traffic_secret;
    std::vector<std::uint8_t> master_secret;
};

}    // namespace reality

#endif
