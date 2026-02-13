#include <span>
#include <array>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>
#include <algorithm>
#include <system_error>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
}

#include "log.h"
#include "crypto_util.h"
#include "cipher_context.h"

namespace reality
{

void ensure_openssl_initialized()
{
    static std::once_flag init_flag;
    std::call_once(
        init_flag,
        []()
        {
            (void)OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr);
        });
}

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

openssl_ptrs::evp_pkey_ctx_ptr create_hkdf_context(const EVP_MD* md, const int mode, std::error_code& ec)
{
    openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (ctx == nullptr || EVP_PKEY_derive_init(ctx.get()) <= 0)
    {
        ec = std::make_error_code(std::errc::not_enough_memory);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), md) <= 0 || EVP_PKEY_CTX_set_hkdf_mode(ctx.get(), mode) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return nullptr;
    }
    return ctx;
}

bool set_hkdf_key_material(const openssl_ptrs::evp_pkey_ctx_ptr& ctx, const std::vector<std::uint8_t>& key, std::error_code& ec)
{
    if (key.empty())
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), key.data(), static_cast<int>(key.size())) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }
    return true;
}

bool set_optional_hkdf_salt(const openssl_ptrs::evp_pkey_ctx_ptr& ctx, const std::vector<std::uint8_t>& salt, std::error_code& ec)
{
    if (salt.empty())
    {
        return true;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }
    return true;
}

bool validate_x25519_keys(const std::vector<std::uint8_t>& private_key, const std::vector<std::uint8_t>& peer_public_key, std::error_code& ec)
{
    if (private_key.size() != 32 || peer_public_key.size() != 32)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    return true;
}

bool create_x25519_key_objects(const std::vector<std::uint8_t>& private_key,
                               const std::vector<std::uint8_t>& peer_public_key,
                               openssl_ptrs::evp_pkey_ptr& pkey,
                               openssl_ptrs::evp_pkey_ptr& pub,
                               std::error_code& ec)
{
    pkey = openssl_ptrs::evp_pkey_ptr(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
    pub = openssl_ptrs::evp_pkey_ptr(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public_key.data(), 32));
    if (pkey == nullptr || pub == nullptr)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }
    return true;
}

bool derive_x25519_shared_secret(const openssl_ptrs::evp_pkey_ptr& pkey,
                                 const openssl_ptrs::evp_pkey_ptr& pub,
                                 std::vector<std::uint8_t>& shared,
                                 std::error_code& ec)
{
    const openssl_ptrs::evp_pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
    if (ctx == nullptr)
    {
        ec = std::make_error_code(std::errc::not_enough_memory);
        return false;
    }
    std::size_t len = 32;
    shared.assign(32, 0);
    if (EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0 || EVP_PKEY_derive(ctx.get(), shared.data(), &len) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }
    return true;
}

bool validate_aead_decrypt_inputs(const EVP_CIPHER* cipher,
                                  const std::vector<std::uint8_t>& key,
                                  const std::span<const std::uint8_t> nonce,
                                  const std::span<const std::uint8_t> ciphertext,
                                  const std::span<std::uint8_t> output_buffer,
                                  std::size_t& plaintext_len,
                                  std::error_code& ec)
{
    if (key.size() != static_cast<std::size_t>(EVP_CIPHER_key_length(cipher)))
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    if (nonce.size() != 12)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    if (ciphertext.size() < kAeadTagSize)
    {
        ec = std::make_error_code(std::errc::message_size);
        return false;
    }

    plaintext_len = ciphertext.size() - kAeadTagSize;
    if (output_buffer.size() < plaintext_len)
    {
        ec = std::make_error_code(std::errc::no_buffer_space);
        return false;
    }
    return true;
}

bool apply_aead_tag(const cipher_context& ctx, const std::span<const std::uint8_t> ciphertext, const std::size_t plaintext_len, std::error_code& ec)
{
    const std::uint8_t* tag = ciphertext.data() + plaintext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kAeadTagSize, const_cast<void*>(static_cast<const void*>(tag))) != 1)
    {
        ec = std::make_error_code(std::errc::bad_message);
        return false;
    }
    return true;
}

bool decrypt_aead_payload(const cipher_context& ctx,
                          const std::span<const std::uint8_t> aad,
                          const std::span<const std::uint8_t> ciphertext,
                          const std::size_t plaintext_len,
                          const std::span<std::uint8_t> output_buffer,
                          std::size_t& out_len,
                          std::error_code& ec)
{
    int update_len = 0;
    int plaintext_update_len = 0;

    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &update_len, aad.data(), static_cast<int>(aad.size())) != 1)
    {
        ec = std::make_error_code(std::errc::bad_message);
        return false;
    }

    if (EVP_DecryptUpdate(ctx.get(), output_buffer.data(), &plaintext_update_len, ciphertext.data(), static_cast<int>(plaintext_len)) != 1)
    {
        ec = std::make_error_code(std::errc::bad_message);
        return false;
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), output_buffer.data() + plaintext_update_len, &final_len) <= 0)
    {
        ec = std::make_error_code(std::errc::bad_message);
        return false;
    }

    out_len = static_cast<std::size_t>(plaintext_update_len) + static_cast<std::size_t>(final_len);
    return true;
}

}    // namespace

std::string crypto_util::bytes_to_hex(const std::vector<std::uint8_t>& bytes)
{
    static constexpr std::array<char, 16> kHexTable = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string hex;
    hex.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i)
    {
        const auto value = bytes[i];
        hex[2 * i] = kHexTable[(value >> 4) & 0x0F];
        hex[2 * i + 1] = kHexTable[value & 0x0F];
    }
    return hex;
}

std::vector<std::uint8_t> crypto_util::hex_to_bytes(const std::string& hex)
{
    ensure_openssl_initialized();

    long len = 0;
    std::uint8_t* buf = OPENSSL_hexstr2buf(hex.c_str(), &len);
    if (buf == nullptr)
    {
        return {};
    }
    const std::vector<std::uint8_t> result{buf, buf + len};
    OPENSSL_free(buf);
    return result;
}

bool crypto_util::base64_url_decode(const std::string& input, std::vector<std::uint8_t>& out)
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

std::uint16_t crypto_util::random_grease()
{
    ensure_openssl_initialized();

    std::uint8_t idx = 0;
    if (RAND_bytes(&idx, 1) != 1)
    {
        idx = 0;
    }
    static constexpr std::array<std::uint16_t, 16> kGreaseValues = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa};

    return kGreaseValues[idx % kGreaseValues.size()];
}

bool crypto_util::generate_x25519_keypair(std::uint8_t out_public[32], std::uint8_t out_private[32])
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
            EVP_PKEY_get_raw_public_key(pkey.get(), out_public, &len);
            len = 32;
            EVP_PKEY_get_raw_private_key(pkey.get(), out_private, &len);
            return true;
        }
    }

    OPENSSL_cleanse(out_public, 32);
    OPENSSL_cleanse(out_private, 32);
    return false;
}

std::vector<std::uint8_t> crypto_util::extract_public_key(const std::vector<std::uint8_t>& private_key, std::error_code& ec)
{
    ensure_openssl_initialized();

    if (private_key.size() != 32)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), 32));
    if (pkey == nullptr)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }

    std::size_t len = 32;
    std::vector<std::uint8_t> public_key(32);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &len) != 1)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }

    ec.clear();
    return public_key;
}

std::vector<std::uint8_t> crypto_util::extract_ed25519_public_key(const std::vector<std::uint8_t>& private_key, std::error_code& ec)
{
    ensure_openssl_initialized();

    if (private_key.size() != 32)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    const openssl_ptrs::evp_pkey_ptr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(), 32));
    if (pkey == nullptr)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }

    std::size_t len = 32;
    std::vector<std::uint8_t> public_key(32);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), public_key.data(), &len) != 1)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }

    ec.clear();
    return public_key;
}

std::vector<std::uint8_t> crypto_util::x25519_derive(const std::vector<std::uint8_t>& private_key,
                                                     const std::vector<std::uint8_t>& peer_public_key,
                                                     std::error_code& ec)
{
    ensure_openssl_initialized();

    if (!validate_x25519_keys(private_key, peer_public_key, ec))
    {
        return {};
    }
    openssl_ptrs::evp_pkey_ptr pkey;
    openssl_ptrs::evp_pkey_ptr pub;
    if (!create_x25519_key_objects(private_key, peer_public_key, pkey, pub, ec))
    {
        return {};
    }
    std::vector<std::uint8_t> shared;
    if (!derive_x25519_shared_secret(pkey, pub, shared, ec))
    {
        return {};
    }
    ec.clear();
    return shared;
}

std::vector<std::uint8_t> crypto_util::hkdf_extract(const std::vector<std::uint8_t>& salt,
                                                    const std::vector<std::uint8_t>& ikm,
                                                    const EVP_MD* md,
                                                    std::error_code& ec)
{
    ensure_openssl_initialized();

    const auto evp_pkey_ctx = create_hkdf_context(md, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY, ec);
    if (evp_pkey_ctx == nullptr)
    {
        return {};
    }

    if (!set_optional_hkdf_salt(evp_pkey_ctx, salt, ec))
    {
        return {};
    }

    if (!set_hkdf_key_material(evp_pkey_ctx, ikm, ec))
    {
        return {};
    }

    std::size_t out_len = EVP_MD_size(md);
    std::vector<std::uint8_t> prk(out_len);
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), prk.data(), &out_len) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }
    prk.resize(out_len);
    ec.clear();
    return prk;
}

std::vector<std::uint8_t> crypto_util::hkdf_expand(
    const std::vector<std::uint8_t>& prk, const std::vector<std::uint8_t>& info, const std::size_t len, const EVP_MD* md, std::error_code& ec)
{
    ensure_openssl_initialized();

    if (len == 0)
    {
        ec.clear();
        return {};
    }

    const auto evp_pkey_ctx = create_hkdf_context(md, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY, ec);
    if (evp_pkey_ctx == nullptr)
    {
        return {};
    }

    if (!set_hkdf_key_material(evp_pkey_ctx, prk, ec))
    {
        return {};
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(evp_pkey_ctx.get(), info.data(), static_cast<int>(info.size())) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }

    std::size_t out_len = len;
    std::vector<std::uint8_t> okm(out_len);
    if (EVP_PKEY_derive(evp_pkey_ctx.get(), okm.data(), &out_len) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {};
    }
    okm.resize(out_len);
    ec.clear();
    return okm;
}

std::vector<std::uint8_t> crypto_util::hkdf_expand_label(const std::vector<std::uint8_t>& secret,
                                                         const std::string& label,
                                                         const std::vector<std::uint8_t>& context,
                                                         std::size_t length,
                                                         const EVP_MD* md,
                                                         std::error_code& ec)
{
    std::string full_label = "tls13 " + label;
    std::vector<std::uint8_t> hkdf_label;
    hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());
    hkdf_label.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
    hkdf_label.push_back(static_cast<std::uint8_t>(length & 0xFF));
    hkdf_label.push_back(static_cast<std::uint8_t>(full_label.size()));
    hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());
    hkdf_label.push_back(static_cast<std::uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

    return hkdf_expand(secret, hkdf_label, length, md, ec);
}

std::size_t crypto_util::aead_decrypt(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const std::vector<std::uint8_t>& key,
                                      const std::span<const std::uint8_t> nonce,
                                      const std::span<const std::uint8_t> ciphertext,
                                      const std::span<const std::uint8_t> aad,
                                      const std::span<std::uint8_t> output_buffer,
                                      std::error_code& ec)
{
    ensure_openssl_initialized();

    std::size_t pt_len = 0;
    if (!validate_aead_decrypt_inputs(cipher, key, nonce, ciphertext, output_buffer, pt_len, ec))
    {
        return 0;
    }

    if (!ctx.init(false, cipher, key.data(), nonce.data(), nonce.size()))
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return 0;
    }

    if (!apply_aead_tag(ctx, ciphertext, pt_len, ec))
    {
        return 0;
    }

    std::size_t out_len = 0;
    if (!decrypt_aead_payload(ctx, aad, ciphertext, pt_len, output_buffer, out_len, ec))
    {
        return 0;
    }

    ec.clear();
    return out_len;
}

std::vector<std::uint8_t> crypto_util::aead_decrypt(const EVP_CIPHER* cipher,
                                                    const std::vector<std::uint8_t>& key,
                                                    const std::vector<std::uint8_t>& nonce,
                                                    const std::vector<std::uint8_t>& ciphertext,
                                                    const std::vector<std::uint8_t>& aad,
                                                    std::error_code& ec)
{
    const cipher_context ctx;
    if (ciphertext.size() < kAeadTagSize)
    {
        ec = std::make_error_code(std::errc::message_size);
        return {};
    }
    std::vector<std::uint8_t> out(ciphertext.size() - kAeadTagSize);
    const std::size_t n = aead_decrypt(ctx, cipher, key, nonce, ciphertext, aad, out, ec);
    if (ec)
    {
        return {};
    }
    out.resize(n);
    return out;
}

void crypto_util::aead_encrypt_append(const cipher_context& ctx,
                                      const EVP_CIPHER* cipher,
                                      const std::vector<std::uint8_t>& key,
                                      const std::vector<std::uint8_t>& nonce,
                                      const std::vector<std::uint8_t>& plaintext,
                                      std::span<const std::uint8_t> aad,
                                      std::vector<std::uint8_t>& output_buffer,
                                      std::error_code& ec)
{
    ensure_openssl_initialized();

    if (key.size() != static_cast<std::size_t>(EVP_CIPHER_key_length(cipher)))
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }
    if (nonce.size() != 12)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }
    if (!ctx.init(true, cipher, key.data(), nonce.data(), nonce.size()))
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return;
    }

    int out_len = 0;
    int len = 0;

    std::size_t current_size = output_buffer.size();
    output_buffer.resize(current_size + plaintext.size() + kAeadTagSize);
    std::uint8_t* out_ptr = output_buffer.data() + current_size;

    if (!aad.empty())
    {
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size()));
    }

    EVP_EncryptUpdate(ctx.get(), out_ptr, &out_len, plaintext.data(), static_cast<int>(plaintext.size()));

    int final_len = 0;
    EVP_EncryptFinal_ex(ctx.get(), out_ptr + out_len, &final_len);

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAeadTagSize, out_ptr + out_len + final_len);

    output_buffer.resize(current_size + out_len + final_len + kAeadTagSize);
    ec.clear();
}

std::vector<std::uint8_t> crypto_util::aead_encrypt(const EVP_CIPHER* cipher,
                                                    const std::vector<std::uint8_t>& key,
                                                    const std::vector<std::uint8_t>& nonce,
                                                    const std::vector<std::uint8_t>& plaintext,
                                                    const std::vector<std::uint8_t>& aad,
                                                    std::error_code& ec)
{
    const cipher_context ctx;
    std::vector<std::uint8_t> out;
    aead_encrypt_append(ctx, cipher, key, nonce, plaintext, aad, out, ec);
    return out;
}

openssl_ptrs::evp_pkey_ptr crypto_util::extract_pubkey_from_cert(const std::vector<std::uint8_t>& cert_der, std::error_code& ec)
{
    ensure_openssl_initialized();

    const std::uint8_t* p = cert_der.data();

    const openssl_ptrs::x509_ptr x509(d2i_X509(nullptr, &p, static_cast<long>(cert_der.size())));
    if (x509 == nullptr)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {nullptr};
    }

    EVP_PKEY* pkey = X509_get_pubkey(x509.get());
    if (pkey == nullptr)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return {nullptr};
    }

    return openssl_ptrs::evp_pkey_ptr(pkey);
}

bool crypto_util::verify_tls13_signature(EVP_PKEY* pub_key,
                                         const std::vector<std::uint8_t>& transcript_hash,
                                         const std::vector<std::uint8_t>& signature,
                                         std::error_code& ec)
{
    ensure_openssl_initialized();

    std::vector<std::uint8_t> to_verify(64, 0x20);

    const std::string context_str = "TLS 1.3, server CertificateVerify";
    to_verify.insert(to_verify.end(), context_str.begin(), context_str.end());

    to_verify.push_back(0x00);

    to_verify.insert(to_verify.end(), transcript_hash.begin(), transcript_hash.end());

    const openssl_ptrs::evp_md_ctx_ptr mctx(EVP_MD_CTX_new());
    if (mctx == nullptr)
    {
        ec = std::make_error_code(std::errc::not_enough_memory);
        return false;
    }

    if (EVP_DigestVerifyInit(mctx.get(), nullptr, nullptr, nullptr, pub_key) <= 0)
    {
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }

    const int res = EVP_DigestVerify(mctx.get(), signature.data(), signature.size(), to_verify.data(), to_verify.size());

    if (res != 1)
    {
        LOG_ERROR("signature verification failed");
        ec = std::make_error_code(std::errc::protocol_error);
        return false;
    }

    ec.clear();
    return true;
}

}    // namespace reality
