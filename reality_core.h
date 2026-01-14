#ifndef REALITY_CORE_H
#define REALITY_CORE_H

#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

namespace reality
{

static constexpr uint8_t K_REALITY_INFO[] = "REALITY";
static constexpr uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
static constexpr uint8_t CONTENT_TYPE_ALERT = 0x15;
static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
static constexpr uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

static constexpr size_t TLS_RECORD_HEADER_SIZE = 5;
static constexpr size_t AEAD_TAG_SIZE = 16;
static constexpr size_t MAX_TLS_PLAINTEXT_LEN = 16384;

namespace tls_consts
{
constexpr uint16_t VER_1_2 = 0x0303;
constexpr uint16_t VER_1_3 = 0x0304;

namespace ext
{
constexpr uint16_t SNI = 0x0000;
constexpr uint16_t STATUS_REQUEST = 0x0005;
constexpr uint16_t SUPPORTED_GROUPS = 0x000a;
constexpr uint16_t EC_POINT_FORMATS = 0x000b;
constexpr uint16_t SIGNATURE_ALG = 0x000d;
constexpr uint16_t ALPN = 0x0010;
constexpr uint16_t PADDING = 0x0015;
constexpr uint16_t EXT_MASTER_SECRET = 0x0017;
constexpr uint16_t COMPRESS_CERT = 0x001b;
constexpr uint16_t SUPPORTED_VERSIONS = 0x002b;
constexpr uint16_t KEY_SHARE = 0x0033;
constexpr uint16_t PRE_SHARED_KEY = 0x0029;
constexpr uint16_t RENEGOTIATION_INFO = 0xff01;
}    // namespace ext

namespace group
{
constexpr uint16_t X25519 = 0x001d;
}
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
    std::vector<uint8_t> client_handshake_traffic_secret;
    std::vector<uint8_t> server_handshake_traffic_secret;
    std::vector<uint8_t> master_secret;
};

}    // namespace reality

#endif
