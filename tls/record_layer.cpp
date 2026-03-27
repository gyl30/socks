#include <span>
#include <array>
#include <limits>
#include <vector>
#include <cstddef>
#include <cstring>

#include <boost/system/error_code.hpp>

extern "C"
{
#include <openssl/rand.h>
#include <openssl/types.h>
}

#include "tls/core.h"
#include "tls/crypto_util.h"
#include "tls/record_layer.h"
#include "tls/cipher_context.h"

namespace tls
{

namespace
{

constexpr std::size_t kNonceSeqXorBytes = 8;

void validate_record_for_decrypt(const std::span<const std::uint8_t> record_data, boost::system::error_code& ec)
{
    ec.clear();
    if (record_data.size() >= kTlsRecordHeaderSize + kAeadTagSize)
    {
        return;
    }
    ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
}

void validate_nonce_iv_size(const std::span<const std::uint8_t> iv, boost::system::error_code& ec)
{
    ec.clear();
    if (iv.size() >= kNonceSeqXorBytes)
    {
        return;
    }
    ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
}

std::vector<std::uint8_t> make_record_nonce(const std::span<const std::uint8_t> iv, const std::uint64_t seq)
{
    std::vector<std::uint8_t> nonce(iv.begin(), iv.end());
    for (std::size_t i = 0; i < kNonceSeqXorBytes; ++i)
    {
        const auto shift = static_cast<unsigned int>(8U * i);
        nonce[nonce.size() - 1 - i] ^= static_cast<std::uint8_t>((seq >> shift) & 0xFFU);
    }
    return nonce;
}

std::size_t trim_padding_and_read_content_type(const std::span<std::uint8_t> output_buffer,
                                               std::uint8_t& out_content_type,
                                               boost::system::error_code& ec)
{
    ec.clear();
    std::size_t written = output_buffer.size();
    while (written > 0 && output_buffer[written - 1] == 0)
    {
        --written;
    }
    if (written == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return 0;
    }
    out_content_type = output_buffer[written - 1];
    return written - 1;
}

void validate_inner_plaintext_len(const std::size_t plaintext_len, boost::system::error_code& ec)
{
    ec.clear();
    if (plaintext_len <= kMaxTlsInnerPlaintextLen)
    {
        return;
    }
    ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
}

}    // namespace

void record_layer::encrypt_record_append(const cipher_context& ctx,
                                         const EVP_CIPHER* cipher,
                                         const std::vector<std::uint8_t>& key,
                                         const std::vector<std::uint8_t>& iv,
                                         const std::uint64_t seq,
                                         const std::vector<std::uint8_t>& plaintext,
                                         const std::uint8_t content_type,
                                         std::vector<std::uint8_t>& output_buffer,
                                         boost::system::error_code& ec)
{
    ec.clear();
    ensure_openssl_initialized();

    if (plaintext.size() > kMaxTlsPlaintextLen)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    validate_nonce_iv_size(iv, ec);
    if (ec)
    {
        return;
    }

    const auto nonce = make_record_nonce(iv, seq);

    std::vector<std::uint8_t> inner_plaintext;
    std::size_t padding_len = 0;

    if (content_type == kContentTypeApplicationData)
    {
        std::uint8_t padding_seed = 0;
        if (RAND_bytes(&padding_seed, 1) != 1)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
            return;
        }

        padding_len = static_cast<std::size_t>(padding_seed % 64);
    }

    inner_plaintext.reserve(plaintext.size() + 1 + padding_len);
    inner_plaintext.insert(inner_plaintext.end(), plaintext.begin(), plaintext.end());
    inner_plaintext.push_back(content_type);

    if (padding_len > 0)
    {
        inner_plaintext.insert(inner_plaintext.end(), padding_len, 0x00);
    }
    validate_inner_plaintext_len(inner_plaintext.size(), ec);
    if (ec)
    {
        return;
    }

    const auto total_ciphertext_len = inner_plaintext.size() + kAeadTagSize;
    if (total_ciphertext_len > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    const auto ciphertext_len = static_cast<std::uint16_t>(total_ciphertext_len);

    std::array<std::uint8_t, 5> temp_header;
    temp_header[0] = kContentTypeApplicationData;
    temp_header[1] = 0x03;
    temp_header[2] = 0x03;
    temp_header[3] = static_cast<std::uint8_t>((ciphertext_len >> 8) & 0xFF);
    temp_header[4] = static_cast<std::uint8_t>(ciphertext_len & 0xFF);

    output_buffer.insert(output_buffer.end(), temp_header.begin(), temp_header.end());
    crypto_util::aead_encrypt_append(ctx, cipher, key, nonce, inner_plaintext, temp_header, output_buffer, ec);
}

std::vector<std::uint8_t> record_layer::encrypt_tls_record(const EVP_CIPHER* cipher,
                                                           const std::vector<std::uint8_t>& key,
                                                           const std::vector<std::uint8_t>& iv,
                                                           const std::uint64_t seq,
                                                           const std::vector<std::uint8_t>& plaintext,
                                                           const std::uint8_t content_type,
                                                           boost::system::error_code& ec)
{
    const cipher_context ctx;
    std::vector<std::uint8_t> out;
    encrypt_record_append(ctx, cipher, key, iv, seq, plaintext, content_type, out, ec);
    if (ec)
    {
        return {};
    }
    return out;
}

std::size_t record_layer::decrypt_tls_record(const cipher_context& ctx,
                                             const EVP_CIPHER* cipher,
                                             const std::vector<std::uint8_t>& key,
                                             const std::vector<std::uint8_t>& iv,
                                             const std::uint64_t seq,
                                             const std::span<const std::uint8_t> record_data,
                                             const std::span<std::uint8_t> output_buffer,
                                             std::uint8_t& out_content_type,
                                             boost::system::error_code& ec)
{
    ensure_openssl_initialized();

    validate_record_for_decrypt(record_data, ec);
    if (ec)
    {
        return 0;
    }
    validate_nonce_iv_size(iv, ec);
    if (ec)
    {
        return 0;
    }

    const auto aad = record_data.subspan(0, kTlsRecordHeaderSize);
    const auto ciphertext = record_data.subspan(kTlsRecordHeaderSize);
    auto nonce = make_record_nonce(iv, seq);

    auto written = crypto_util::aead_decrypt(ctx, cipher, key, nonce, ciphertext, aad, output_buffer, ec);
    if (ec)
    {
        return 0;
    }
    validate_inner_plaintext_len(written, ec);
    if (ec)
    {
        return 0;
    }
    return trim_padding_and_read_content_type(output_buffer.subspan(0, written), out_content_type, ec);
}

std::vector<std::uint8_t> record_layer::decrypt_record(const EVP_CIPHER* cipher,
                                                       const std::vector<std::uint8_t>& key,
                                                       const std::vector<std::uint8_t>& iv,
                                                       const std::uint64_t seq,
                                                       const std::vector<std::uint8_t>& ciphertext_with_header,
                                                       std::uint8_t& out_content_type,
                                                       boost::system::error_code& ec)
{
    ec.clear();
    const cipher_context ctx;
    if (ciphertext_with_header.size() < kTlsRecordHeaderSize + kAeadTagSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    std::vector<std::uint8_t> out(ciphertext_with_header.size() - kTlsRecordHeaderSize - kAeadTagSize);
    auto decrypt_result = decrypt_tls_record(ctx, cipher, key, iv, seq, ciphertext_with_header, out, out_content_type, ec);
    if (ec)
    {
        return {};
    }
    out.resize(decrypt_result);
    return out;
}
}    // namespace tls
