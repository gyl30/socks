#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <span>
#include <memory>
#include <vector>
#include <cstddef>
#include <functional>

extern "C"
{
#include <openssl/types.h>
}

#include <boost/asio/awaitable.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/error_code.hpp>

#include "tls/cipher_context.h"

namespace mux
{

class reality_engine
{
   public:
    using record_callback = std::function<boost::asio::awaitable<void>(std::uint8_t, std::span<const std::uint8_t>, boost::system::error_code&)>;

    static constexpr auto kInitialBufSize = 16 * 1024;
    static constexpr auto kMaxBufSize = 64 * 1024;

    reality_engine(std::vector<std::uint8_t> r_key,
                   std::vector<std::uint8_t> r_iv,
                   std::vector<std::uint8_t> w_key,
                   std::vector<std::uint8_t> w_iv,
                   const EVP_CIPHER* cipher);

    reality_engine(reality_engine&&) = default;
    reality_engine& operator=(reality_engine&&) = delete;

    [[nodiscard]] boost::asio::streambuf::mutable_buffers_type read_buffer(std::size_t size_hint, boost::system::error_code& ec) const;

    void commit_read(const std::size_t n) const { rx_buf_->commit(n); }

    [[nodiscard]] boost::asio::awaitable<void> process_available_records(const record_callback& callback, boost::system::error_code& ec);

    [[nodiscard]] std::span<const std::uint8_t> encrypt(const std::vector<std::uint8_t>& plaintext, boost::system::error_code& ec);

   private:
    void try_decrypt_next_record(std::uint8_t& content_type, std::size_t& payload_len, boost::system::error_code& ec);

    std::vector<std::uint8_t> read_key_;
    std::vector<std::uint8_t> read_iv_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_iv_;
    ::tls::cipher_context decrypt_ctx_;
    ::tls::cipher_context encrypt_ctx_;
    std::uint64_t read_seq_ = 0;
    std::uint64_t write_seq_ = 0;
    std::unique_ptr<boost::asio::streambuf> rx_buf_;
    const EVP_CIPHER* cipher_;
    std::vector<std::uint8_t> tx_buf_;
    std::vector<std::uint8_t> record_buf_;
    std::vector<std::uint8_t> scratch_buf_;
};

}    // namespace mux

#endif
