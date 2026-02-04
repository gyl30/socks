#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <system_error>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "crypto_util.h"
#include "reality_core.h"
#include "cipher_context.h"
#include "tls_record_layer.h"

namespace reality
{

void tls_record_layer::encrypt_record_append(const cipher_context& ctx,
                                             const EVP_CIPHER* cipher,
                                             const std::vector<uint8_t>& key,
                                             const std::vector<uint8_t>& iv,
                                             const uint64_t seq,
                                             const std::vector<uint8_t>& plaintext,
                                             const uint8_t content_type,
                                             std::vector<uint8_t>& output_buffer,
                                             std::error_code& ec)
{
    std::vector<uint8_t> nonce = iv;
    for (int i = 0; i < 8; ++i)
    {
        nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
    }

    std::vector<uint8_t> inner_plaintext;
    size_t padding_len = 0;

    if (content_type == CONTENT_TYPE_APPLICATION_DATA)
    {
        uint8_t r;
        if (RAND_bytes(&r, 1) != 1)
        {
            ec = std::make_error_code(std::errc::operation_canceled);
            return;
        }

        padding_len = static_cast<size_t>(r % 64);
    }

    inner_plaintext.reserve(plaintext.size() + 1 + padding_len);
    inner_plaintext.insert(inner_plaintext.end(), plaintext.begin(), plaintext.end());
    inner_plaintext.push_back(content_type);

    if (padding_len > 0)
    {
        inner_plaintext.insert(inner_plaintext.end(), padding_len, 0x00);
    }

    const auto ciphertext_len = static_cast<uint16_t>(inner_plaintext.size() + AEAD_TAG_SIZE);

    std::array<uint8_t, 5> temp_header;
    temp_header[0] = CONTENT_TYPE_APPLICATION_DATA;
    temp_header[1] = 0x03;
    temp_header[2] = 0x03;
    temp_header[3] = static_cast<uint8_t>((ciphertext_len >> 8) & 0xFF);
    temp_header[4] = static_cast<uint8_t>(ciphertext_len & 0xFF);

    output_buffer.insert(output_buffer.end(), temp_header.begin(), temp_header.end());
    crypto_util::aead_encrypt_append(ctx, cipher, key, nonce, inner_plaintext, temp_header, output_buffer, ec);
}

std::vector<uint8_t> tls_record_layer::encrypt_record(const EVP_CIPHER* cipher,
                                                      const std::vector<uint8_t>& key,
                                                      const std::vector<uint8_t>& iv,
                                                      const uint64_t seq,
                                                      const std::vector<uint8_t>& plaintext,
                                                      const uint8_t content_type,
                                                      std::error_code& ec)
{
    const cipher_context ctx;
    std::vector<uint8_t> out;
    encrypt_record_append(ctx, cipher, key, iv, seq, plaintext, content_type, out, ec);
    return out;
}

size_t tls_record_layer::decrypt_record(const cipher_context& ctx,
                                        const EVP_CIPHER* cipher,
                                        const std::vector<uint8_t>& key,
                                        const std::vector<uint8_t>& iv,
                                        const uint64_t seq,
                                        const std::span<const uint8_t> record_data,
                                        const std::span<uint8_t> output_buffer,
                                        uint8_t& out_content_type,
                                        std::error_code& ec)
{
    if (record_data.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
    {
        ec = std::make_error_code(std::errc::message_size);
        return 0;
    }

    const auto aad = record_data.subspan(0, TLS_RECORD_HEADER_SIZE);
    const auto ciphertext = record_data.subspan(TLS_RECORD_HEADER_SIZE);

    std::vector<uint8_t> nonce = iv;
    for (int i = 0; i < 8; ++i)
    {
        nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
    }

    size_t written = crypto_util::aead_decrypt(ctx, cipher, key, nonce, ciphertext, aad, output_buffer, ec);
    if (ec)
    {
        return 0;
    }

    while (written > 0 && output_buffer[written - 1] == 0)
    {
        written--;
    }

    if (written == 0)
    {
        ec = std::make_error_code(std::errc::bad_message);
        return 0;
    }

    out_content_type = output_buffer[written - 1];
    written--;

    ec.clear();
    return written;
}

std::vector<uint8_t> tls_record_layer::decrypt_record(const EVP_CIPHER* cipher,
                                                      const std::vector<uint8_t>& key,
                                                      const std::vector<uint8_t>& iv,
                                                      const uint64_t seq,
                                                      const std::vector<uint8_t>& ciphertext_with_header,
                                                      uint8_t& out_content_type,
                                                      std::error_code& ec)
{
    const cipher_context ctx;
    if (ciphertext_with_header.size() < TLS_RECORD_HEADER_SIZE + AEAD_TAG_SIZE)
    {
        ec = std::make_error_code(std::errc::message_size);
        return {};
    }
    std::vector<uint8_t> out(ciphertext_with_header.size() - TLS_RECORD_HEADER_SIZE - AEAD_TAG_SIZE);
    const size_t n = decrypt_record(ctx, cipher, key, iv, seq, ciphertext_with_header, out, out_content_type, ec);
    if (ec)
    {
        return {};
    }
    out.resize(n);
    return out;
}

}    // namespace reality
