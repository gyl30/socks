#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <asio.hpp>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <vector>
#include <asio/streambuf.hpp>
#include "cipher_context.h"
#include "reality_core.h"

class reality_engine
{
   public:
    static constexpr auto INITIAL_BUF_SIZE = 16 * 1024;
    static constexpr auto MAX_BUF_SIZE = 64 * 1024;

    reality_engine(
        std::vector<uint8_t> r_key, std::vector<uint8_t> r_iv, std::vector<uint8_t> w_key, std::vector<uint8_t> w_iv, const EVP_CIPHER* cipher);

    reality_engine(reality_engine&&) = default;
    reality_engine& operator=(reality_engine&&) = delete;

    [[nodiscard]] auto get_read_buffer(size_t size_hint = 4096) const { return rx_buf_->prepare(size_hint); }

    void commit_read(size_t n) const { rx_buf_->commit(n); }

    template <typename Callback>
    void process_available_records(std::error_code& ec, Callback&& callback)
    {
        ec.clear();
        uint8_t content_type = 0;
        size_t payload_len = 0;

        while (try_decrypt_next_record(content_type, payload_len, ec))
        {
            if (ec)
            {
                return;
            }

            callback(content_type, std::span<const uint8_t>(scratch_buf_.data(), payload_len));

            if (content_type == reality::CONTENT_TYPE_ALERT)
            {
                ec = asio::error::eof;
                return;
            }
        }
    }

    [[nodiscard]] std::span<const uint8_t> encrypt(const std::vector<uint8_t>& plaintext, std::error_code& ec);

   private:
    bool try_decrypt_next_record(uint8_t& content_type, size_t& payload_len, std::error_code& ec);

    std::vector<uint8_t> read_key_;
    std::vector<uint8_t> read_iv_;
    std::vector<uint8_t> write_key_;
    std::vector<uint8_t> write_iv_;
    reality::cipher_context decrypt_ctx_;
    reality::cipher_context encrypt_ctx_;
    uint64_t read_seq_ = 0;
    uint64_t write_seq_ = 0;
    std::unique_ptr<asio::streambuf> rx_buf_;
    const EVP_CIPHER* cipher_;
    std::vector<uint8_t> tx_buf_;
    std::vector<uint8_t> scratch_buf_;
};

#endif
