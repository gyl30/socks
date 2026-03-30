#ifndef TLS_CORE_H
#define TLS_CORE_H

#include <memory>
#include <vector>
#include <cstdint>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/types.h>
}

namespace tls
{
constexpr uint8_t kHandshakeTypeNewSessionTicket = 0x04;
constexpr uint8_t kHandshakeTypeKeyUpdate = 0x18;

inline constexpr uint8_t kContentTypeChangeCipherSpec = 0x14;
inline constexpr uint8_t kContentTypeAlert = 0x15;
inline constexpr uint8_t kContentTypeHandshake = 0x16;
inline constexpr uint8_t kContentTypeApplicationData = 0x17;

inline constexpr std::size_t kTlsRecordHeaderSize = 5;
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kMaxTlsPlaintextLen = 16384;
inline constexpr std::size_t kMaxTlsInnerPlaintextLen = kMaxTlsPlaintextLen + 1;
inline constexpr std::size_t kMaxTlsApplicationDataPaddingLen = 63;
inline constexpr std::size_t kMaxTlsApplicationDataPayloadLen = kMaxTlsInnerPlaintextLen - 1 - kMaxTlsApplicationDataPaddingLen;
inline constexpr std::size_t kMlkem768PublicKeySize = 1184;
inline constexpr std::size_t kMlkem768PrivateKeySize = 2400;
inline constexpr std::size_t kMlkem768CiphertextSize = 1088;
inline constexpr std::size_t kMlkem768SharedSecretSize = 32;

inline constexpr uint16_t kGreasePlaceholder = 0x0A0A;

namespace consts
{
constexpr uint16_t kVer10 = 0x0301;
constexpr uint16_t kVer11 = 0x0302;
constexpr uint16_t kVer12 = 0x0303;
constexpr uint16_t kVer13 = 0x0304;

namespace ext
{
constexpr uint16_t kSni = 0x0000;
constexpr uint16_t kStatusRequest = 0x0005;
constexpr uint16_t kSupportedGroups = 0x000a;
constexpr uint16_t kEcPointFormats = 0x000b;
constexpr uint16_t kSignatureAlg = 0x000d;
constexpr uint16_t kAlpn = 0x0010;
constexpr uint16_t kSct = 0x0012;
constexpr uint16_t kPadding = 0x0015;
constexpr uint16_t kExtMasterSecret = 0x0017;
constexpr uint16_t kCompressCert = 0x001b;
constexpr uint16_t kRecordSizeLimit = 0x001c;
constexpr uint16_t kSessionTicket = 0x0023;
constexpr uint16_t kPreSharedKey = 0x0029;
constexpr uint16_t kSupportedVersions = 0x002b;
constexpr uint16_t kPskKeyExchangeModes = 0x002d;
constexpr uint16_t kKeyShare = 0x0033;
constexpr uint16_t kDelegatedCredentials = 0x0022;
constexpr uint16_t kChannelId = 0x3003;
constexpr uint16_t kChannelIdLegacy = 0x7550;
constexpr uint16_t kNpn = 0x3374;
constexpr uint16_t kApplicationSettings = 0x4469;
constexpr uint16_t kApplicationSettingsNew = 0x44cd;
constexpr uint16_t kRenegotiationInfo = 0xff01;
constexpr uint16_t kEchOuterExtensions = 0xfd00;
constexpr uint16_t kGreaseEch = 0xfe0d;
}    // namespace ext

namespace group
{
constexpr uint16_t kSecp256r1 = 0x0017;
constexpr uint16_t kSecp384r1 = 0x0018;
constexpr uint16_t kSecp521r1 = 0x0019;
constexpr uint16_t kX25519 = 0x001d;
constexpr uint16_t kX25519MLKEM768 = 0x11ec;
constexpr uint16_t kFfdhe2048 = 0x0100;
constexpr uint16_t kFfdhe3072 = 0x0101;

}    // namespace group

namespace sig_alg
{
constexpr uint16_t kRsaPkcs1Sha1 = 0x0201;
constexpr uint16_t kEcdsaSha1 = 0x0203;
constexpr uint16_t kRsaPkcs1Sha256 = 0x0401;
constexpr uint16_t kEcdsaSecp256r1Sha256 = 0x0403;
constexpr uint16_t kRsaPkcs1Sha384 = 0x0501;
constexpr uint16_t kEcdsaSecp384r1Sha384 = 0x0503;
constexpr uint16_t kRsaPkcs1Sha512 = 0x0601;
constexpr uint16_t kEcdsaSecp521r1Sha512 = 0x0603;
constexpr uint16_t kRsaPssRsaeSha256 = 0x0804;
constexpr uint16_t kRsaPssRsaeSha384 = 0x0805;
constexpr uint16_t kRsaPssRsaeSha512 = 0x0806;
constexpr uint16_t kEd25519 = 0x0807;

constexpr uint16_t kFakeDsaSha1 = 0x0202;
constexpr uint16_t kFakeDsaSha256 = 0x0402;
}    // namespace sig_alg

namespace compress
{
constexpr uint16_t kDeflate = 0x0001;
constexpr uint16_t kBrotli = 0x0002;
}    // namespace compress

namespace cipher
{

constexpr uint16_t kTlsAes128GcmSha256 = 0x1301;
constexpr uint16_t kTlsAes256GcmSha384 = 0x1302;
constexpr uint16_t kTlsChacha20Poly1305Sha256 = 0x1303;
constexpr uint16_t kTlsFallbackScsv = 0x5600;

constexpr uint16_t kTlsEcdheEcdsaWithAes128GcmSha256 = 0xc02b;
constexpr uint16_t kTlsEcdheRsaWithAes128GcmSha256 = 0xc02f;
constexpr uint16_t kTlsEcdheEcdsaWithAes256GcmSha384 = 0xc02c;
constexpr uint16_t kTlsEcdheRsaWithAes256GcmSha384 = 0xc030;
constexpr uint16_t kTlsEcdheEcdsaWithChacha20Poly1305 = 0xcca9;
constexpr uint16_t kTlsEcdheRsaWithChacha20Poly1305 = 0xcca8;
constexpr uint16_t kTlsEcdheRsaWithChacha20Poly1305Old = 0xcc13;
constexpr uint16_t kTlsEcdheEcdsaWithChacha20Poly1305Old = 0xcc14;
constexpr uint16_t kTlsEcdheRsaWithAes128CbcSha = 0xc013;
constexpr uint16_t kTlsEcdheRsaWithAes256CbcSha = 0xc014;
constexpr uint16_t kTlsEcdheEcdsaWithAes128CbcSha = 0xc009;
constexpr uint16_t kTlsEcdheEcdsaWithAes256CbcSha = 0xc00a;
constexpr uint16_t kTlsEcdheRsaWithAes128CbcSha256 = 0xc027;
constexpr uint16_t kTlsEcdheRsaWithAes256CbcSha384 = 0xc028;
constexpr uint16_t kTlsEcdheEcdsaWithAes128CbcSha256 = 0xc023;
constexpr uint16_t kTlsEcdheEcdsaWithAes256CbcSha384 = 0xc024;
constexpr uint16_t kTlsEcdheRsaWith3desEdeCbcSha = 0xc012;
constexpr uint16_t kTlsEcdheEcdsaWith3desEdeCbcSha = 0xc008;
constexpr uint16_t kTlsEcdheEcdsaWithRc4128Sha = 0xc007;
constexpr uint16_t kTlsEcdheRsaWithRc4128Sha = 0xc011;

constexpr uint16_t kTlsRsaWithAes128GcmSha256 = 0x009c;
constexpr uint16_t kTlsRsaWithAes256GcmSha384 = 0x009d;
constexpr uint16_t kTlsRsaWithAes128CbcSha = 0x002f;
constexpr uint16_t kTlsRsaWithAes256CbcSha = 0x0035;
constexpr uint16_t kTlsRsaWithAes128CbcSha256 = 0x003c;
constexpr uint16_t kTlsRsaWithAes256CbcSha256 = 0x003d;
constexpr uint16_t kTlsRsaWith3desEdeCbcSha = 0x000a;
constexpr uint16_t kTlsRsaWithRc4128Sha = 0x0005;
constexpr uint16_t kTlsRsaWithRc4128Md5 = 0x0004;

constexpr uint16_t kTlsDheRsaWithAes128CbcSha = 0x0033;
constexpr uint16_t kTlsDheRsaWithAes256CbcSha = 0x0039;
constexpr uint16_t kTlsDheRsaWithAes128CbcSha256 = 0x0067;
constexpr uint16_t kTlsDheRsaWithAes256CbcSha256 = 0x006b;
constexpr uint16_t kTlsDheDssWithAes128CbcSha = 0x0032;
}    // namespace cipher

}    // namespace consts

namespace openssl_ptrs
{
class evp_pkey_deleter
{
   public:
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
class evp_pkey_ctx_deleter
{
   public:
    void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
class evp_cipher_ctx_deleter
{
   public:
    void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
class evp_md_ctx_deleter
{
   public:
    void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
class x509_deleter
{
   public:
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

}    // namespace tls

#endif
