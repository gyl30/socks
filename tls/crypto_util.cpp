#include <span>
#include <array>
#include <mutex>
#include <cctype>
#include <limits>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>

#include <boost/system/errc.hpp>

extern "C"
{
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/asn1.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "tls/core.h"
#include "tls/cipher_context.h"
#include "tls/crypto_util.h"
namespace tls
{

void ensure_openssl_initialized()
{
    static std::once_flag init_flag;
    std::call_once(init_flag, []() { (void)OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr); });
}

namespace crypto_util
{

namespace
{

void normalize_base64_url(std::string& text)
{
    for (char& c : text)
    {
        if (c == '-')
        {
            c = '+';
        }
        else if (c == '_')
        {
            c = '/';
        }
    }

    const std::size_t rem = text.size() % 4;
    if (rem != 0)
    {
        text.append(4 - rem, '=');
    }
}

std::size_t base64_real_length(const std::string& padded_input, const std::size_t decoded_len)
{
    std::size_t real_len = decoded_len;
    if (!padded_input.empty() && padded_input.back() == '=')
    {
        real_len--;
    }
    if (padded_input.size() >= 2 && padded_input[padded_input.size() - 2] == '=')
    {
        real_len--;
    }
    return real_len;
}

int hex_nibble(const char ch)
{
    const auto value = static_cast<unsigned char>(ch);
    if (value >= static_cast<unsigned char>('0') && value <= static_cast<unsigned char>('9'))
    {
        return value - static_cast<unsigned char>('0');
    }
    if (value >= static_cast<unsigned char>('a') && value <= static_cast<unsigned char>('f'))
    {
        return 10 + (value - static_cast<unsigned char>('a'));
    }
    if (value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('F'))
    {
        return 10 + (value - static_cast<unsigned char>('A'));
    }
    return -1;
}

bool is_hex_separator(const char ch)
{
    const auto value = static_cast<unsigned char>(ch);
    return ch == ':' || ch == '-' || std::isspace(value) != 0;
}

const EVP_MD* tls13_signature_digest(const uint16_t signature_scheme, boost::system::error_code& ec)
{
    using tls::consts::sig_alg::kEcdsaSecp256r1Sha256;
    using tls::consts::sig_alg::kEcdsaSecp384r1Sha384;
    using tls::consts::sig_alg::kEcdsaSecp521r1Sha512;
    using tls::consts::sig_alg::kEd25519;
    using tls::consts::sig_alg::kRsaPkcs1Sha256;
    using tls::consts::sig_alg::kRsaPkcs1Sha384;
    using tls::consts::sig_alg::kRsaPkcs1Sha512;
    using tls::consts::sig_alg::kRsaPssRsaeSha256;
    using tls::consts::sig_alg::kRsaPssRsaeSha384;
    using tls::consts::sig_alg::kRsaPssRsaeSha512;

    switch (signature_scheme)
    {
        case kEd25519:
            return nullptr;
        case kEcdsaSecp256r1Sha256:
        case kRsaPkcs1Sha256:
        case kRsaPssRsaeSha256:
            return EVP_sha256();
        case kEcdsaSecp384r1Sha384:
        case kRsaPkcs1Sha384:
        case kRsaPssRsaeSha384:
            return EVP_sha384();
        case kEcdsaSecp521r1Sha512:
        case kRsaPkcs1Sha512:
        case kRsaPssRsaeSha512:
            return EVP_sha512();
        default:
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return nullptr;
    }
}

bool tls13_signature_scheme_matches_key(const uint16_t signature_scheme, const EVP_PKEY* pub_key)
{
    using tls::consts::sig_alg::kEcdsaSecp256r1Sha256;
    using tls::consts::sig_alg::kEcdsaSecp384r1Sha384;
    using tls::consts::sig_alg::kEcdsaSecp521r1Sha512;
    using tls::consts::sig_alg::kEd25519;
    using tls::consts::sig_alg::kRsaPkcs1Sha256;
    using tls::consts::sig_alg::kRsaPkcs1Sha384;
    using tls::consts::sig_alg::kRsaPkcs1Sha512;
    using tls::consts::sig_alg::kRsaPssRsaeSha256;
    using tls::consts::sig_alg::kRsaPssRsaeSha384;
    using tls::consts::sig_alg::kRsaPssRsaeSha512;

    const int key_type = EVP_PKEY_base_id(pub_key);
    switch (signature_scheme)
    {
        case kEd25519:
            return key_type == EVP_PKEY_ED25519;
        case kEcdsaSecp256r1Sha256:
        case kEcdsaSecp384r1Sha384:
        case kEcdsaSecp521r1Sha512:
            return key_type == EVP_PKEY_EC;
        case kRsaPkcs1Sha256:
        case kRsaPkcs1Sha384:
        case kRsaPkcs1Sha512:
        case kRsaPssRsaeSha256:
        case kRsaPssRsaeSha384:
        case kRsaPssRsaeSha512:
            return key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS;
        default:
            return false;
    }
}

bool tls13_signature_scheme_is_rsa_pss(const uint16_t signature_scheme)
{
    using tls::consts::sig_alg::kRsaPssRsaeSha256;
    using tls::consts::sig_alg::kRsaPssRsaeSha384;
    using tls::consts::sig_alg::kRsaPssRsaeSha512;
    return signature_scheme == kRsaPssRsaeSha256 || signature_scheme == kRsaPssRsaeSha384 || signature_scheme == kRsaPssRsaeSha512;
}

openssl_ptrs::evp_pkey_ctx_ptr create_hkdf_context(const EVP_MD* md, const int mode, boost::system::error_code& ec)
{
    openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (ctx == nullptr || EVP_PKEY_derive_init(ctx.get()) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), md) <= 0 || EVP_PKEY_CTX_set_hkdf_mode(ctx.get(), mode) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return ctx;
}

void set_hkdf_key_material(const openssl_ptrs::evp_pkey_ctx_ptr& ctx, const std::vector<uint8_t>& key, boost::system::error_code& ec)
{
    if (key.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), static_cast<int>(key.size())) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
}

void set_optional_hkdf_salt(const openssl_ptrs::evp_pkey_ctx_ptr& ctx, const std::vector<uint8_t>& salt, boost::system::error_code& ec)
{
    if (salt.empty())
    {
        return;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
}

void validate_x25519_keys(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& peer_public_key, boost::system::error_code& ec)
{
    if (private_key.size() != 32 || peer_public_key.size() != 32)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
}

std::pair<openssl_ptrs::evp_pkey_ptr, openssl_ptrs::evp_pkey_ptr> create_x25519_key_objects(const std::vector<uint8_t>& private_key,
                                                                                            const std::vector<uint8_t>& peer_public_key,
                                                                                            boost::system::error_code& ec)
{
    openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
    openssl_ptrs::evp_pkey_ptr pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), 32));
    if (pkey == nullptr || pub == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return std::pair{std::move(pkey), std::move(pub)};
}

std::vector<uint8_t> derive_x25519_shared_secret(const openssl_ptrs::evp_pkey_ptr& pkey,
                                                 const openssl_ptrs::evp_pkey_ptr& pub,
                                                 boost::system::error_code& ec)
{
    const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (ctx == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return {};
    }
    std::size_t len = 32;
    std::vector<uint8_t> shared(32, 0);
    if (EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0 ||
        EVP_PKEY_derive(ctx.get(), shared.data(), &len) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return shared;
}

bool validate_mlkem768_public_key(const std::vector<uint8_t>& public_key, boost::system::error_code& ec)
{
    if (public_key.size() != kMlkem768PublicKeySize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    return true;
}

bool validate_mlkem768_private_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    if (private_key.size() != kMlkem768PrivateKeySize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    return true;
}

bool validate_mlkem768_ciphertext(const std::vector<uint8_t>& ciphertext, boost::system::error_code& ec)
{
    if (ciphertext.size() != kMlkem768CiphertextSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    return true;
}

openssl_ptrs::evp_pkey_ptr create_mlkem768_private_key_object(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    if (!validate_mlkem768_private_key(private_key, ec))
    {
        return nullptr;
    }

    openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key_ex(nullptr, "ML-KEM-768", nullptr, private_key.data(), private_key.size()));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return pkey;
}

openssl_ptrs::evp_pkey_ptr create_mlkem768_public_key_object(const std::vector<uint8_t>& public_key, boost::system::error_code& ec)
{
    if (!validate_mlkem768_public_key(public_key, ec))
    {
        return nullptr;
    }

    openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_public_key_ex(nullptr, "ML-KEM-768", nullptr, public_key.data(), public_key.size()));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return pkey;
}

bool export_mlkem768_keypair(const EVP_PKEY* pkey, std::vector<uint8_t>& public_key, std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    std::size_t public_key_len = 0;
    std::size_t private_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &public_key_len) != 1 || EVP_PKEY_get_raw_private_key(pkey, nullptr, &private_key_len) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return false;
    }

    public_key.assign(public_key_len, 0);
    private_key.assign(private_key_len, 0);
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &public_key_len) != 1 ||
        EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &private_key_len) != 1)
    {
        public_key.clear();
        private_key.clear();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return false;
    }

    public_key.resize(public_key_len);
    private_key.resize(private_key_len);
    if (!validate_mlkem768_public_key(public_key, ec) || !validate_mlkem768_private_key(private_key, ec))
    {
        public_key.clear();
        private_key.clear();
        return false;
    }
    return true;
}

openssl_ptrs::evp_pkey_ptr create_ed25519_private_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    if (private_key.size() != 32)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return nullptr;
    }

    openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size()));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return pkey;
}

openssl_ptrs::x509_ptr parse_x509_from_der(const std::vector<uint8_t>& cert_der, boost::system::error_code& ec)
{
    if (cert_der.empty() || cert_der.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return nullptr;
    }

    using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    const bio_ptr cert_bio(BIO_new_mem_buf(cert_der.data(), static_cast<int>(cert_der.size())), &BIO_free);
    if (cert_bio == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return nullptr;
    }

    openssl_ptrs::x509_ptr x509(d2i_X509_bio(cert_bio.get(), nullptr));
    if (x509 == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }
    return x509;
}

std::vector<uint8_t> serialize_x509_to_der(const X509* cert, boost::system::error_code& ec)
{
    if (cert == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<uint8_t> der(static_cast<std::size_t>(der_len));
    unsigned char* out = der.data();
    if (i2d_X509(cert, &out) != der_len)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return der;
}

void validate_aead_decrypt_inputs(const EVP_CIPHER* cipher,
                                  const std::vector<uint8_t>& key,
                                  const std::span<const uint8_t> nonce,
                                  const std::span<const uint8_t> ciphertext,
                                  const std::span<uint8_t> output_buffer,
                                  std::size_t& plaintext_len,
                                  boost::system::error_code& ec)
{
    if (cipher == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (key.size() != static_cast<std::size_t>(EVP_CIPHER_key_length(cipher)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (nonce.size() != 12)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (ciphertext.size() < kAeadTagSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    plaintext_len = ciphertext.size() - kAeadTagSize;
    if (plaintext_len > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    if (output_buffer.size() < plaintext_len)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::no_buffer_space);
        return;
    }
}

void apply_aead_tag(const cipher_context& ctx,
                    const std::span<const uint8_t> ciphertext,
                    const std::size_t plaintext_len,
                    boost::system::error_code& ec)
{
    const uint8_t* tag = ciphertext.data() + plaintext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kAeadTagSize, const_cast<void*>(static_cast<const void*>(tag))) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return;
    }
}

std::size_t decrypt_aead_payload(const cipher_context& ctx,
                                 const std::span<const uint8_t> aad,
                                 const std::span<const uint8_t> ciphertext,
                                 const std::size_t plaintext_len,
                                 const std::span<uint8_t> output_buffer,
                                 boost::system::error_code& ec)
{
    if (aad.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        plaintext_len > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return 0;
    }

    int update_len = 0;
    int plaintext_update_len = 0;

    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &update_len, aad.data(), static_cast<int>(aad.size())) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return 0;
    }

    if (EVP_DecryptUpdate(ctx.get(), output_buffer.data(), &plaintext_update_len, ciphertext.data(), static_cast<int>(plaintext_len)) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return 0;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), output_buffer.data() + plaintext_update_len, &final_len) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return 0;
    }

    return static_cast<std::size_t>(plaintext_update_len) + static_cast<std::size_t>(final_len);
}

}    // namespace

std::string bytes_to_hex(const std::vector<uint8_t>& bytes)
{
    static constexpr std::array<char, 16> kHexTable = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string hex;
    hex.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        const auto value = bytes[i];
        hex[2 * i] = kHexTable[(value >> 4) & 0x0F];
        hex[(2 * i) + 1] = kHexTable[value & 0x0F];
    }
    return hex;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex)
{
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    int high_nibble = -1;
    for (const char ch : hex)
    {
        if (is_hex_separator(ch))
        {
            continue;
        }

        const int nibble = hex_nibble(ch);
        if (nibble < 0)
        {
            return {};
        }
        if (high_nibble < 0)
        {
            high_nibble = nibble;
            continue;
        }

        const auto byte = static_cast<uint8_t>((high_nibble << 4) | nibble);
        result.push_back(byte);
        high_nibble = -1;
    }

    if (high_nibble >= 0)
    {
        return {};
    }
    return result;
}

bool base64_url_decode(const std::string& input, std::vector<uint8_t>& out)
{
    ensure_openssl_initialized();

    out.clear();
    if (input.empty())
    {
        return true;
    }

    std::string tmp = input;
    normalize_base64_url(tmp);

    out.resize((tmp.size() / 4) * 3);
    const int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(tmp.data()), static_cast<int>(tmp.size()));
    if (len < 0)
    {
        out.clear();
        return false;
    }

    const std::size_t real_len = base64_real_length(tmp, static_cast<std::size_t>(len));
    if (real_len > out.size())
    {
        out.clear();
        return false;
    }
    out.resize(real_len);
    return true;
}

uint16_t random_grease()
{
    ensure_openssl_initialized();

    uint8_t idx = 0;
    if (RAND_bytes(&idx, 1) != 1)
    {
        idx = 0;
    }
    static constexpr std::array<uint16_t, 16> kGreaseValues = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

    return kGreaseValues[idx % kGreaseValues.size()];
}

bool generate_x25519_keypair(uint8_t out_public[32], uint8_t out_private[32])
{
    ensure_openssl_initialized();

    const openssl_ptrs::evp_pkey_ctx_ptr pkey_ctx_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));

    if (pkey_ctx_ptr != nullptr && EVP_PKEY_keygen_init(pkey_ctx_ptr.get()) > 0)
    {
        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(pkey_ctx_ptr.get(), &raw_pkey) > 0)
        {
            const openssl_ptrs::evp_pkey_ptr pkey(raw_pkey);
            std::size_t len = 32;
            if (EVP_PKEY_get_raw_public_key(pkey.get(), out_public, &len) != 1 || len != 32)
            {
                OPENSSL_cleanse(out_public, 32);
                OPENSSL_cleanse(out_private, 32);
                return false;
            }
            len = 32;
            if (EVP_PKEY_get_raw_private_key(pkey.get(), out_private, &len) != 1 || len != 32)
            {
                OPENSSL_cleanse(out_public, 32);
                OPENSSL_cleanse(out_private, 32);
                return false;
            }
            return true;
        }
    }

    OPENSSL_cleanse(out_public, 32);
    OPENSSL_cleanse(out_private, 32);
    return false;
}

bool generate_ed25519_keypair(uint8_t out_public[32], uint8_t out_private[32])
{
    ensure_openssl_initialized();

    const openssl_ptrs::evp_pkey_ctx_ptr pkey_ctx_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    if (pkey_ctx_ptr != nullptr && EVP_PKEY_keygen_init(pkey_ctx_ptr.get()) > 0)
    {
        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(pkey_ctx_ptr.get(), &raw_pkey) > 0)
        {
            const openssl_ptrs::evp_pkey_ptr pkey(raw_pkey);
            std::size_t len = 32;
            if (EVP_PKEY_get_raw_public_key(pkey.get(), out_public, &len) != 1 || len != 32)
            {
                OPENSSL_cleanse(out_public, 32);
                OPENSSL_cleanse(out_private, 32);
                return false;
            }
            len = 32;
            if (EVP_PKEY_get_raw_private_key(pkey.get(), out_private, &len) != 1 || len != 32)
            {
                OPENSSL_cleanse(out_public, 32);
                OPENSSL_cleanse(out_private, 32);
                return false;
            }
            return true;
        }
    }

    OPENSSL_cleanse(out_public, 32);
    OPENSSL_cleanse(out_private, 32);
    return false;
}

std::vector<uint8_t> extract_public_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    if (private_key.size() != 32)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::size_t len = 32;
    std::vector<uint8_t> public_key(32);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &len) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    return public_key;
}

std::vector<uint8_t> extract_ed25519_public_key(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    if (private_key.size() != 32)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), 32));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::size_t len = 32;
    std::vector<uint8_t> public_key(32);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &len) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    return public_key;
}

std::vector<uint8_t> x25519_derive(const std::vector<uint8_t>& private_key,
                                   const std::vector<uint8_t>& peer_public_key,
                                   boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    validate_x25519_keys(private_key, peer_public_key, ec);
    if (ec)
    {
        return {};
    }
    auto keys = create_x25519_key_objects(private_key, peer_public_key, ec);
    if (ec)
    {
        return {};
    }
    return derive_x25519_shared_secret(keys.first, keys.second, ec);
}

bool generate_mlkem768_keypair(std::vector<uint8_t>& public_key, std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768"));
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return false;
    }
    return export_mlkem768_keypair(pkey.get(), public_key, private_key, ec);
}

std::vector<uint8_t> mlkem768_encapsulate(const std::vector<uint8_t>& public_key, std::vector<uint8_t>& shared_secret, boost::system::error_code& ec)
{
    ensure_openssl_initialized();
    shared_secret.clear();
    const auto pkey = create_mlkem768_public_key_object(public_key, ec);
    if (ec)
    {
        return {};
    }

    const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (ctx == nullptr || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::size_t ciphertext_len = 0;
    std::size_t shared_secret_len = 0;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ciphertext_len, nullptr, &shared_secret_len) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<uint8_t> ciphertext(ciphertext_len, 0);
    shared_secret.assign(shared_secret_len, 0);
    if (EVP_PKEY_encapsulate(ctx.get(), ciphertext.data(), &ciphertext_len, shared_secret.data(), &shared_secret_len) <= 0)
    {
        ciphertext.clear();
        shared_secret.clear();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    ciphertext.resize(ciphertext_len);
    shared_secret.resize(shared_secret_len);
    if (!validate_mlkem768_ciphertext(ciphertext, ec) || shared_secret.size() != kMlkem768SharedSecretSize)
    {
        ciphertext.clear();
        shared_secret.clear();
        if (!ec)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        }
        return {};
    }
    return ciphertext;
}

std::vector<uint8_t> mlkem768_decapsulate(const std::vector<uint8_t>& private_key,
                                          const std::vector<uint8_t>& ciphertext,
                                          boost::system::error_code& ec)
{
    ensure_openssl_initialized();
    if (!validate_mlkem768_ciphertext(ciphertext, ec))
    {
        return {};
    }

    const auto pkey = create_mlkem768_private_key_object(private_key, ec);
    if (ec)
    {
        return {};
    }

    const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (ctx == nullptr || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::size_t shared_secret_len = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &shared_secret_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<uint8_t> shared_secret(shared_secret_len, 0);
    if (EVP_PKEY_decapsulate(ctx.get(), shared_secret.data(), &shared_secret_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        shared_secret.clear();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    shared_secret.resize(shared_secret_len);
    if (shared_secret.size() != kMlkem768SharedSecretSize)
    {
        shared_secret.clear();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return shared_secret;
}

std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm, const EVP_MD* md, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    auto evp_pkey_ctx = create_hkdf_context(md, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY, ec);
    if (ec)
    {
        return {};
    }

    set_optional_hkdf_salt(evp_pkey_ctx, salt, ec);
    if (ec)
    {
        return {};
    }

    set_hkdf_key_material(evp_pkey_ctx, ikm, ec);
    if (ec)
    {
        return {};
    }

    const int md_size = EVP_MD_size(md);
    if (md_size <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    auto out_len = static_cast<std::size_t>(md_size);
    std::vector<uint8_t> prk(out_len);
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), prk.data(), &out_len) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    prk.resize(out_len);
    return prk;
}

std::vector<uint8_t> hkdf_expand(
    const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, const std::size_t len, const EVP_MD* md, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    if (len == 0)
    {
        return std::vector<uint8_t>{};
    }

    auto evp_pkey_ctx = create_hkdf_context(md, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY, ec);
    if (ec)
    {
        return {};
    }

    set_hkdf_key_material(evp_pkey_ctx, prk, ec);
    if (ec)
    {
        return {};
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(evp_pkey_ctx.get(), info.data(), static_cast<int>(info.size())) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::size_t out_len = len;
    std::vector<uint8_t> okm(out_len);
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), okm.data(), &out_len) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    okm.resize(out_len);
    return okm;
}

std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret,
                                       const std::string& label,
                                       const std::vector<uint8_t>& context,
                                       std::size_t length,
                                       const EVP_MD* md,
                                       boost::system::error_code& ec)
{
    std::string full_label = "tls13 " + label;
    if (length > std::numeric_limits<uint16_t>::max() || full_label.size() > std::numeric_limits<uint8_t>::max() ||
        context.size() > std::numeric_limits<uint8_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<uint8_t> hkdf_label;
    hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());
    hkdf_label.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(length & 0xFF));
    hkdf_label.push_back(static_cast<uint8_t>(full_label.size()));
    hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
    hkdf_label.push_back(static_cast<uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

    return hkdf_expand(secret, hkdf_label, length, md, ec);
}

std::size_t aead_decrypt(const cipher_context& ctx,
                         const EVP_CIPHER* cipher,
                         const std::vector<uint8_t>& key,
                         const std::span<const uint8_t> nonce,
                         const std::span<const uint8_t> ciphertext,
                         const std::span<const uint8_t> aad,
                         const std::span<uint8_t> output_buffer,
                         boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    std::size_t pt_len = 0;
    validate_aead_decrypt_inputs(cipher, key, nonce, ciphertext, output_buffer, pt_len, ec);
    if (ec)
    {
        return 0;
    }

    if (!ctx.init(false, cipher, key.data(), nonce.data(), nonce.size()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return 0;
    }

    apply_aead_tag(ctx, ciphertext, pt_len, ec);
    if (ec)
    {
        return 0;
    }

    return decrypt_aead_payload(ctx, aad, ciphertext, pt_len, output_buffer, ec);
}

std::vector<uint8_t> aead_decrypt(const EVP_CIPHER* cipher,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& nonce,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad,
                                  boost::system::error_code& ec)
{
    const cipher_context ctx;
    if (ciphertext.size() < kAeadTagSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    std::vector<uint8_t> out(ciphertext.size() - kAeadTagSize);
    auto n = aead_decrypt(ctx, cipher, key, nonce, ciphertext, aad, out, ec);
    if (ec)
    {
        return {};
    }
    out.resize(n);
    return out;
}

void aead_encrypt_append(const cipher_context& ctx,
                         const EVP_CIPHER* cipher,
                         const std::vector<uint8_t>& key,
                         const std::vector<uint8_t>& nonce,
                         const std::vector<uint8_t>& plaintext,
                         std::span<const uint8_t> aad,
                         std::vector<uint8_t>& output_buffer,
                         boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    if (cipher == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (key.size() != static_cast<std::size_t>(EVP_CIPHER_key_length(cipher)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (nonce.size() != 12)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return;
    }
    if (aad.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        plaintext.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    if (!ctx.init(true, cipher, key.data(), nonce.data(), nonce.size()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }

    int out_len = 0;
    int len = 0;

    const std::size_t current_size = output_buffer.size();
    output_buffer.resize(current_size + plaintext.size() + kAeadTagSize);
    uint8_t* out_ptr = output_buffer.data() + current_size;
    const auto rollback_output = [&output_buffer, current_size]() { output_buffer.resize(current_size); };

    if (!aad.empty())
    {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        {
            rollback_output();
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return;
        }
    }

    if (EVP_EncryptUpdate(ctx.get(), out_ptr, &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1)
    {
        rollback_output();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out_ptr + out_len, &final_len) != 1)
    {
        rollback_output();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }

    if (out_len < 0 || final_len < 0)
    {
        rollback_output();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAeadTagSize, out_ptr + out_len + final_len) != 1)
    {
        rollback_output();
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
    output_buffer.resize(current_size + static_cast<std::size_t>(out_len) + static_cast<std::size_t>(final_len) + kAeadTagSize);
}

std::vector<uint8_t> aead_encrypt(const EVP_CIPHER* cipher,
                                  const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& nonce,
                                  const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& aad,
                                  boost::system::error_code& ec)
{
    const cipher_context ctx;
    std::vector<uint8_t> out;
    aead_encrypt_append(ctx, cipher, key, nonce, plaintext, aad, out, ec);
    if (ec)
    {
        return {};
    }
    return out;
}

openssl_ptrs::evp_pkey_ptr extract_pubkey_from_cert(const std::vector<uint8_t>& cert_der, boost::system::error_code& ec)
{
    ensure_openssl_initialized();
    auto x509 = parse_x509_from_der(cert_der, ec);
    if (ec)
    {
        return nullptr;
    }

    EVP_PKEY* pkey = X509_get_pubkey(x509.get());
    if (pkey == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return nullptr;
    }

    return openssl_ptrs::evp_pkey_ptr(pkey);
}

std::vector<uint8_t> extract_raw_public_key(const EVP_PKEY* key, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    if (key == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::size_t key_len = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &key_len) != 1 || key_len == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    std::vector<uint8_t> raw_key(key_len);
    if (EVP_PKEY_get_raw_public_key(key, raw_key.data(), &key_len) != 1 || key_len == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    raw_key.resize(key_len);
    return raw_key;
}

std::vector<uint8_t> extract_certificate_signature(const std::vector<uint8_t>& cert_der, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    auto x509 = parse_x509_from_der(cert_der, ec);
    if (ec)
    {
        return {};
    }

    const ASN1_BIT_STRING* signature = nullptr;
    const X509_ALGOR* algorithm = nullptr;
    X509_get0_signature(&signature, &algorithm, x509.get());
    (void)algorithm;
    if (signature == nullptr || signature->data == nullptr || signature->length <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    std::vector<uint8_t> ret(signature->data, signature->data + signature->length);
    return ret;
}

std::vector<uint8_t> create_self_signed_ed25519_certificate(const std::vector<uint8_t>& private_key, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    auto pkey = create_ed25519_private_key(private_key, ec);
    if (ec)
    {
        return {};
    }

    const openssl_ptrs::x509_ptr cert(X509_new());
    if (cert == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return {};
    }
    if (X509_set_version(cert.get(), 2) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), -86400) == nullptr || X509_gmtime_adj(X509_getm_notAfter(cert.get()), 31536000L) == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    if (X509_set_pubkey(cert.get(), pkey.get()) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    X509_NAME* subject = X509_get_subject_name(cert.get());
    if (subject == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    static constexpr unsigned char kCommonName[] = "REALITY";
    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, kCommonName, -1, -1, 0) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    if (X509_set_issuer_name(cert.get(), subject) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    const openssl_ptrs::evp_md_ctx_ptr mctx(EVP_MD_CTX_new());
    if (mctx == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return {};
    }
    if (EVP_DigestSignInit(mctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    if (X509_sign_ctx(cert.get(), mctx.get()) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }

    auto cert_der = serialize_x509_to_der(cert.get(), ec);
    if (ec)
    {
        return {};
    }
    auto signature = extract_certificate_signature(cert_der, ec);
    if (ec)
    {
        return {};
    }
    if (signature.size() != 64)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    return cert_der;
}

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    unsigned int out_len = 0;
    std::array<uint8_t, EVP_MAX_MD_SIZE> out = {};
    if (HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out.data(), &out_len) == nullptr || out_len == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return {};
    }
    std::vector<uint8_t> ret(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(out_len));
    return ret;
}

void verify_tls13_signature(EVP_PKEY* pub_key,
                            const uint16_t signature_scheme,
                            const std::vector<uint8_t>& transcript_hash,
                            const std::vector<uint8_t>& signature,
                            boost::system::error_code& ec)
{
    ensure_openssl_initialized();
    if (pub_key == nullptr || signature.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
    if (!tls13_signature_scheme_matches_key(signature_scheme, pub_key))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
    const auto* md = tls13_signature_digest(signature_scheme, ec);
    if (ec)
    {
        return;
    }

    std::vector<uint8_t> to_verify(64, 0x20);

    const std::string context_str = "TLS 1.3, server CertificateVerify";
    to_verify.insert(to_verify.end(), context_str.begin(), context_str.end());

    to_verify.push_back(0x00);

    to_verify.insert(to_verify.end(), transcript_hash.begin(), transcript_hash.end());

    const openssl_ptrs::evp_md_ctx_ptr mctx(EVP_MD_CTX_new());
    if (mctx == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        return;
    }

    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(mctx.get(), &pctx, md, nullptr, pub_key) <= 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
    if (tls13_signature_scheme_is_rsa_pss(signature_scheme))
    {
        if (pctx == nullptr)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return;
        }
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
            return;
        }
    }

    const int res = EVP_DigestVerify(mctx.get(), signature.data(), signature.size(), to_verify.data(), to_verify.size());

    if (res != 1)
    {
        LOG_ERROR("signature verification failed");
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        return;
    }
}

}    // namespace crypto_util

}    // namespace tls
