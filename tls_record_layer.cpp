// NOLINTBEGIN(misc-include-cleaner)
#include <boost/system/error_code.hpp>
#include <boost/system/detail/errc.hpp>
#include <openssl/types.h>
#include <span>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <expected>

#include <boost/system/errc.hpp>

extern "C"
{
#include <openssl/rand.h>
}

#include "crypto_util.h"
#include "reality_core.h"
#include "cipher_context.h"
#include "tls_record_layer.h"

namespace reality
{

namespace
{

std::expected<void, boost::system::error_code> validate_record_for_decrypt(const std::span<const std::uint8_t> record_data)
{
    if (record_data.size() >= kTlsRecordHeaderSize + kAeadTagSize)
    {
        return {};
    }
    return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::message_size));
}

std::vector<std::uint8_t> make_record_nonce(const std::vector<std::uint8_t>& iv, const std::uint64_t seq)
{
    std::vector<std::uint8_t> nonce = iv;
    for (int i = 0; i < 8; ++i)
    {
        nonce[nonce.size() - 1 - i] ^= static_cast<std::uint8_t>((seq >> (8 * i)) & 0xFF);
    }
    return nonce;
}

std::expected<std::size_t, boost::system::error_code> trim_padding_and_read_content_type(const std::span<std::uint8_t> output_buffer,
                                                                                           std::uint8_t& out_content_type)
{
    std::size_t written = output_buffer.size();
    while (written > 0 && output_buffer[written - 1] == 0)
    {
        --written;
    }
    if (written == 0)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::bad_message));
    }
    out_content_type = output_buffer[written - 1];
    return written - 1;
}

}    // namespace

std::expected<void, boost::system::error_code> tls_record_layer::encrypt_record_append(const cipher_context& ctx,
                                                                                        const EVP_CIPHER* cipher,
                                                                                        const std::vector<std::uint8_t>& key,
                                                                                        const std::vector<std::uint8_t>& iv,
                                                                                        const std::uint64_t seq,
                                                                                        const std::vector<std::uint8_t>& plaintext,
                                                                                        const std::uint8_t content_type,
                                                                                        std::vector<std::uint8_t>& output_buffer)
{
    ensure_openssl_initialized();

    const auto nonce = make_record_nonce(iv, seq);

    std::vector<std::uint8_t> inner_plaintext;
    std::size_t padding_len = 0;

    if (content_type == kContentTypeApplicationData)
    {
        std::uint8_t padding_seed = 0;
        if (RAND_bytes(&padding_seed, 1) != 1)
        {
            return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::operation_canceled));
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

    const auto ciphertext_len = static_cast<std::uint16_t>(inner_plaintext.size() + kAeadTagSize);

    std::array<std::uint8_t, 5> temp_header;
    temp_header[0] = kContentTypeApplicationData;
    temp_header[1] = 0x03;
    temp_header[2] = 0x03;
    temp_header[3] = static_cast<std::uint8_t>((ciphertext_len >> 8) & 0xFF);
    temp_header[4] = static_cast<std::uint8_t>(ciphertext_len & 0xFF);

    output_buffer.insert(output_buffer.end(), temp_header.begin(), temp_header.end());
    return crypto_util::aead_encrypt_append(ctx, cipher, key, nonce, inner_plaintext, temp_header, output_buffer);
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> tls_record_layer::encrypt_record(const EVP_CIPHER* cipher,
                                                                                                      const std::vector<std::uint8_t>& key,
                                                                                                      const std::vector<std::uint8_t>& iv,
                                                                                                      const std::uint64_t seq,
                                                                                                      const std::vector<std::uint8_t>& plaintext,
                                                                                                      const std::uint8_t content_type)
{
    const cipher_context ctx;
    std::vector<std::uint8_t> out;
    auto encrypt_result = encrypt_record_append(ctx, cipher, key, iv, seq, plaintext, content_type, out);
    if (!encrypt_result)
    {
        return std::unexpected(encrypt_result.error());
    }
    return out;
}

std::expected<std::size_t, boost::system::error_code> tls_record_layer::decrypt_record(const cipher_context& ctx,
                                                                                         const EVP_CIPHER* cipher,
                                                                                         const std::vector<std::uint8_t>& key,
                                                                                         const std::vector<std::uint8_t>& iv,
                                                                                         const std::uint64_t seq,
                                                                                         const std::span<const std::uint8_t> record_data,
                                                                                         const std::span<std::uint8_t> output_buffer,
                                                                                         std::uint8_t& out_content_type)
{
    ensure_openssl_initialized();

    if (auto validate_result = validate_record_for_decrypt(record_data); !validate_result)
    {
        return std::unexpected(validate_result.error());
    }

    const auto aad = record_data.subspan(0, kTlsRecordHeaderSize);
    const auto ciphertext = record_data.subspan(kTlsRecordHeaderSize);
    auto nonce = make_record_nonce(iv, seq);

    auto written = crypto_util::aead_decrypt(ctx, cipher, key, nonce, ciphertext, aad, output_buffer);
    if (!written)
    {
        return std::unexpected(written.error());
    }
    return trim_padding_and_read_content_type(output_buffer.subspan(0, *written), out_content_type);
}

std::expected<std::vector<std::uint8_t>, boost::system::error_code> tls_record_layer::decrypt_record(const EVP_CIPHER* cipher,
                                                                                                      const std::vector<std::uint8_t>& key,
                                                                                                      const std::vector<std::uint8_t>& iv,
                                                                                                      const std::uint64_t seq,
                                                                                                      const std::vector<std::uint8_t>& ciphertext_with_header,
                                                                                                      std::uint8_t& out_content_type)
{
    const cipher_context ctx;
    if (ciphertext_with_header.size() < kTlsRecordHeaderSize + kAeadTagSize)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::message_size));
    }
    std::vector<std::uint8_t> out(ciphertext_with_header.size() - kTlsRecordHeaderSize - kAeadTagSize);
    auto decrypt_result = decrypt_record(ctx, cipher, key, iv, seq, ciphertext_with_header, out, out_content_type);
    if (!decrypt_result)
    {
        return std::unexpected(decrypt_result.error());
    }
    out.resize(*decrypt_result);
    return out;
}
}    // namespace reality
// NOLINTEND(misc-include-cleaner)
