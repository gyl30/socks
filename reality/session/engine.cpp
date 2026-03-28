#include <span>
#include <array>
#include <optional>
#include <vector>
#include <utility>
#include <cstddef>
#include <algorithm>

extern "C"
{
#include <openssl/types.h>
}

#include <boost/asio.hpp>
#include "tls/core.h"
#include "tls/record_layer.h"
#include "reality/session/engine.h"

namespace mux
{

namespace
{
constexpr std::size_t kMaxTlsCiphertextRecordLen = tls::kMaxTlsPlaintextLen + 256;
}    // namespace

reality_engine::reality_engine(std::vector<std::uint8_t> r_key,
                               std::vector<std::uint8_t> r_iv,
                               std::vector<std::uint8_t> w_key,
                               std::vector<std::uint8_t> w_iv,
                               const EVP_CIPHER* cipher)
    : read_key_(std::move(r_key)),
      read_iv_(std::move(r_iv)),
      write_key_(std::move(w_key)),
      write_iv_(std::move(w_iv)),
      cipher_(cipher)
{
    tx_buf_.reserve(kMaxBufSize);
}

boost::asio::mutable_buffer reality_engine::read_buffer(std::size_t size_hint, boost::system::error_code& ec)
{
    if (rx_buf_size_ >= rx_buf_.size())
    {
        ec = boost::asio::error::no_buffer_space;
        return boost::asio::buffer(rx_buf_.data(), static_cast<std::size_t>(0));
    }

    auto tail_available = rx_buf_.size() - (rx_buf_offset_ + rx_buf_size_);
    if (rx_buf_offset_ != 0 && size_hint > tail_available)
    {
        std::memmove(rx_buf_.data(), rx_buf_.data() + static_cast<std::ptrdiff_t>(rx_buf_offset_), rx_buf_size_);
        rx_buf_offset_ = 0;
        tail_available = rx_buf_.size() - rx_buf_size_;
    }

    size_hint = std::min(size_hint, tail_available);
    return boost::asio::buffer(rx_buf_.data() + static_cast<std::ptrdiff_t>(rx_buf_offset_ + rx_buf_size_), size_hint);
}

void reality_engine::commit_read(const std::size_t n)
{
    rx_buf_size_ += n;
}

std::span<const std::uint8_t> reality_engine::encrypt_record(const std::vector<std::uint8_t>& plaintext, boost::system::error_code& ec)
{
    tx_buf_.clear();

    if (plaintext.empty())
    {
        return std::span<const std::uint8_t>{};
    }
    std::vector<std::uint8_t> plaintext_chunk;
    plaintext_chunk.reserve(tls::kMaxTlsApplicationDataPayloadLen);
    for (std::size_t offset = 0; offset < plaintext.size();)
    {
        const auto chunk_len = std::min(plaintext.size() - offset, tls::kMaxTlsApplicationDataPayloadLen);
        plaintext_chunk.assign(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                               plaintext.begin() + static_cast<std::ptrdiff_t>(offset + chunk_len));
        tls::record_layer::encrypt_record_append(
            encrypt_ctx_, cipher_, write_key_, write_iv_, write_seq_, plaintext_chunk, tls::kContentTypeApplicationData, tx_buf_, ec);
        if (ec)
        {
            return std::span<const std::uint8_t>{};
        }
        write_seq_++;
        offset += chunk_len;
    }

    return std::span<const std::uint8_t>{tx_buf_.data(), tx_buf_.size()};
}

std::optional<mux::tls_record> reality_engine::decrypt_record(boost::system::error_code& ec)
{
    std::uint8_t content_type = 0;
    std::size_t payload_len = 0;
    const auto buffered_before = rx_buf_size_;
    decrypt_tls_record(content_type, payload_len, ec);
    if (ec)
    {
        return std::nullopt;
    }

    if (rx_buf_size_ == buffered_before)
    {
        return std::nullopt;
    }

    return mux::tls_record{.content_type = content_type, .payload = std::span<const std::uint8_t>(scratch_buf_.data(), payload_len)};
}

void reality_engine::decrypt_tls_record(std::uint8_t& content_type, std::size_t& payload_len, boost::system::error_code& ec)
{
    if (rx_buf_size_ < tls::kTlsRecordHeaderSize)
    {
        return;
    }

    const auto* record_header = rx_buf_.data() + static_cast<std::ptrdiff_t>(rx_buf_offset_);
    const auto record_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(record_header[3]) << 8) | record_header[4]);
    if (record_len > kMaxTlsCiphertextRecordLen)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    const std::uint32_t frame_size = tls::kTlsRecordHeaderSize + record_len;

    if (rx_buf_size_ < frame_size)
    {
        return;
    }

    const std::span<const std::uint8_t> record_data(record_header, frame_size);

    payload_len = tls::record_layer::decrypt_tls_record(
        decrypt_ctx_, cipher_, read_key_, read_iv_, read_seq_, record_data, std::span<std::uint8_t>(scratch_buf_), content_type, ec);
    if (ec)
    {
        return;
    }

    read_seq_++;
    rx_buf_offset_ += frame_size;
    rx_buf_size_ -= frame_size;
    if (rx_buf_size_ == 0)
    {
        rx_buf_offset_ = 0;
    }
}

}    // namespace mux
