#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <span>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <system_error>

#include <asio/error.hpp>
#include <asio/streambuf.hpp>

#include "reality_core.h"
#include "cipher_context.h"

namespace mux
{

class reality_engine
{
   public:
    using record_callback = std::function<void(std::uint8_t, std::span<const std::uint8_t>)>;

    static constexpr auto kInitialBufSize = 16 * 1024;
    static constexpr auto kMaxBufSize = 64 * 1024;

    reality_engine(std::vector<std::uint8_t> r_key,
                   std::vector<std::uint8_t> r_iv,
                   std::vector<std::uint8_t> w_key,
                   std::vector<std::uint8_t> w_iv,
                   const EVP_CIPHER* cipher);

    reality_engine(reality_engine&&) = default;
    reality_engine& operator=(reality_engine&&) = delete;

    [[nodiscard]] auto read_buffer(const std::size_t size_hint = 4096) { return rx_buf_->prepare(size_hint); }

    void commit_read(const std::size_t n) { rx_buf_->commit(n); }

    [[nodiscard]] std::expected<void, std::error_code> process_available_records(const record_callback& callback);

    [[nodiscard]] std::expected<std::span<const std::uint8_t>, std::error_code> encrypt(const std::vector<std::uint8_t>& plaintext);

   private:
    [[nodiscard]] std::expected<bool, std::error_code> try_decrypt_next_record(std::uint8_t& content_type, std::size_t& payload_len);

    std::vector<std::uint8_t> read_key_;
    std::vector<std::uint8_t> read_iv_;
    std::vector<std::uint8_t> write_key_;
    std::vector<std::uint8_t> write_iv_;
    reality::cipher_context decrypt_ctx_;
    reality::cipher_context encrypt_ctx_;
    std::uint64_t read_seq_ = 0;
    std::uint64_t write_seq_ = 0;
    std::unique_ptr<asio::streambuf> rx_buf_;
    const EVP_CIPHER* cipher_;
    std::vector<std::uint8_t> tx_buf_;
    std::vector<std::uint8_t> scratch_buf_;
};

}    // namespace mux

#endif
