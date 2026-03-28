#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <array>
#include <span>
#include <optional>
#include <vector>
#include <cstddef>
#include <cstdint>

extern "C"
{
#include <openssl/types.h>
}

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include "tls/cipher_context.h"

namespace mux
{

struct tls_record
{
    std::uint8_t content_type = 0;
    std::span<const std::uint8_t> payload;
};

class reality_engine
{
   public:
    static constexpr std::size_t kMaxBufSize = 65UL * 1024;

    reality_engine(std::vector<std::uint8_t> r_key,
                   std::vector<std::uint8_t> r_iv,
                   std::vector<std::uint8_t> w_key,
                   std::vector<std::uint8_t> w_iv,
                   const EVP_CIPHER* cipher);

    reality_engine(reality_engine&&) = default;
    reality_engine& operator=(reality_engine&&) = delete;

    [[nodiscard]] boost::asio::mutable_buffer read_buffer(std::size_t size_hint, boost::system::error_code& ec);

    void commit_read(std::size_t n);

    [[nodiscard]] std::optional<tls_record> decrypt_record(boost::system::error_code& ec);

    [[nodiscard]] std::span<const std::uint8_t> encrypt_record(const std::vector<std::uint8_t>& plaintext, boost::system::error_code& ec);

   private:
    void decrypt_tls_record(std::uint8_t& content_type, std::size_t& payload_len, boost::system::error_code& ec);

    std::vector<std::uint8_t> read_key_;
    std::vector<std::uint8_t> read_iv_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_iv_;
    ::tls::cipher_context decrypt_ctx_;
    ::tls::cipher_context encrypt_ctx_;
    std::uint64_t read_seq_ = 0;
    std::uint64_t write_seq_ = 0;
    const EVP_CIPHER* cipher_;
    std::array<std::uint8_t, kMaxBufSize> rx_buf_{};
    std::size_t rx_buf_offset_ = 0;
    std::size_t rx_buf_size_ = 0;
    std::vector<std::uint8_t> tx_buf_;
    std::array<std::uint8_t, kMaxBufSize> scratch_buf_{};
};

}    // namespace mux

#endif
