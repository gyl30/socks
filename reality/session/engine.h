#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

#include "reality/session/session.h"
#include "tls/cipher_context.h"

namespace mux
{

struct tls_record
{
    uint8_t content_type = 0;
    std::span<const uint8_t> payload;
};

class reality_engine
{
   public:
    static constexpr std::size_t kMaxBufSize = 65UL * 1024;

    explicit reality_engine(reality::reality_record_context context);

    reality_engine(reality_engine&&) = default;
    reality_engine& operator=(reality_engine&&) = delete;

    [[nodiscard]] boost::asio::mutable_buffer read_buffer(std::size_t size_hint, boost::system::error_code& ec);

    void commit_read(std::size_t n);

    [[nodiscard]] std::optional<tls_record> decrypt_record(boost::system::error_code& ec);

    [[nodiscard]] std::span<const uint8_t> encrypt_record(const std::vector<uint8_t>& plaintext, boost::system::error_code& ec);

   private:
    void decrypt_tls_record(uint8_t& content_type, std::size_t& payload_len, boost::system::error_code& ec);

    reality::reality_record_context context_;
    tls::cipher_context decrypt_ctx_;
    tls::cipher_context encrypt_ctx_;
    uint64_t read_seq_ = 0;
    uint64_t write_seq_ = 0;
    std::array<uint8_t, kMaxBufSize> rx_buf_{};
    std::size_t rx_buf_offset_ = 0;
    std::size_t rx_buf_size_ = 0;
    std::vector<uint8_t> tx_buf_;
    std::array<uint8_t, kMaxBufSize> scratch_buf_{};
};

}    // namespace mux

#endif
