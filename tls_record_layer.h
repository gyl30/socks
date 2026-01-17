#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <vector>
#include <cstring>
#include <span>
#include <array>
#include <iomanip>

#include "crypto_util.h"

namespace reality
{
class tls_record_layer
{
   public:
    static void encrypt_record_append(const cipher_context& ctx,
                                      const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      uint64_t seq,
                                      const std::vector<uint8_t>& plaintext,
                                      uint8_t content_type,
                                      std::vector<uint8_t>& output_buffer,
                                      std::error_code& ec)
    {
        std::vector<uint8_t> nonce = iv;
        for (int i = 0; i < 8; ++i)
        {
            nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((seq >> (8 * i)) & 0xFF);
        }

        std::vector<uint8_t> inner_plaintext;
        inner_plaintext.reserve(plaintext.size() + 1);
        inner_plaintext.insert(inner_plaintext.end(), plaintext.begin(), plaintext.end());
        inner_plaintext.push_back(content_type);

        const auto ciphertext_len = static_cast<uint16_t>(inner_plaintext.size() + AEAD_TAG_SIZE);

        std::array<uint8_t, 5> temp_header;
        temp_header[0] = CONTENT_TYPE_APPLICATION_DATA;
        temp_header[1] = static_cast<uint8_t>((tls_consts::VER_1_2 >> 8) & 0xFF);
        temp_header[2] = static_cast<uint8_t>(tls_consts::VER_1_2 & 0xFF);
        temp_header[3] = static_cast<uint8_t>((ciphertext_len >> 8) & 0xFF);
        temp_header[4] = static_cast<uint8_t>(ciphertext_len & 0xFF);

        output_buffer.insert(output_buffer.end(), temp_header.begin(), temp_header.end());

        crypto_util::aes_gcm_encrypt_append(ctx, key, nonce, inner_plaintext, temp_header, output_buffer, ec);
    }

    [[nodiscard]] static std::vector<uint8_t> encrypt_record(const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
                                                             const std::vector<uint8_t>& plaintext,
                                                             uint8_t content_type,
                                                             std::error_code& ec)
    {
        const cipher_context ctx;
        std::vector<uint8_t> out;
        encrypt_record_append(ctx, key, iv, seq, plaintext, content_type, out, ec);
        return out;
    }

    static size_t decrypt_record(const cipher_context& ctx,
                                 const std::vector<uint8_t>& key,
                                 const std::vector<uint8_t>& iv,
                                 uint64_t seq,
                                 std::span<const uint8_t> record_data,
                                 std::span<uint8_t> output_buffer,
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

        size_t written = crypto_util::aes_gcm_decrypt(ctx, key, nonce, ciphertext, aad, output_buffer, ec);
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

    [[nodiscard]] static std::vector<uint8_t> decrypt_record(const std::vector<uint8_t>& key,
                                                             const std::vector<uint8_t>& iv,
                                                             uint64_t seq,
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
        const size_t n = decrypt_record(ctx, key, iv, seq, ciphertext_with_header, out, out_content_type, ec);
        if (ec)
        {
            return {};
        }
        out.resize(n);
        return out;
    }
};

}    // namespace reality

#endif
