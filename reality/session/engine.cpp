#include <span>
#include <array>
#include <memory>
#include <vector>
#include <utility>
#include <cstddef>
#include <algorithm>

extern "C"
{
#include <openssl/types.h>
}

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/streambuf.hpp>

#include "tls/core.h"
#include "tls/record_layer.h"
#include "reality/session/engine.h"

namespace mux
{

namespace
{
constexpr std::size_t kMaxTlsCiphertextRecordLen = ::tls::kMaxTlsPlaintextLen + 256;
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
      rx_buf_(std::make_unique<boost::asio::streambuf>(kMaxBufSize)),
      cipher_(cipher)
{
    rx_buf_->prepare(kInitialBufSize);
    scratch_buf_.resize(kMaxBufSize);
    tx_buf_.reserve(kMaxBufSize);
    record_buf_.reserve(kMaxBufSize);
}

boost::asio::streambuf::mutable_buffers_type reality_engine::read_buffer(std::size_t size_hint, boost::system::error_code& ec) const
{
    ec.clear();
    const auto max_size = rx_buf_->max_size();
    const auto current_size = rx_buf_->size();
    if (current_size >= max_size)
    {
        ec = boost::asio::error::no_buffer_space;
        return rx_buf_->prepare(0);
    }
    const auto remaining = max_size - current_size;
    size_hint = std::min(size_hint, remaining);
    return rx_buf_->prepare(size_hint);
}

std::span<const std::uint8_t> reality_engine::encrypt(const std::vector<std::uint8_t>& plaintext, boost::system::error_code& ec)
{
    tx_buf_.clear();

    if (plaintext.empty())
    {
        return std::span<const std::uint8_t>{};
    }
    ec.clear();
    std::vector<std::uint8_t> plaintext_chunk;
    plaintext_chunk.reserve(::tls::kMaxTlsApplicationDataPayloadLen);
    for (std::size_t offset = 0; offset < plaintext.size();)
    {
        const auto chunk_len = std::min(plaintext.size() - offset, ::tls::kMaxTlsApplicationDataPayloadLen);
        plaintext_chunk.assign(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                               plaintext.begin() + static_cast<std::ptrdiff_t>(offset + chunk_len));
        ::tls::record_layer::encrypt_record_append(
            encrypt_ctx_, cipher_, write_key_, write_iv_, write_seq_, plaintext_chunk, ::tls::kContentTypeApplicationData, tx_buf_, ec);
        if (ec)
        {
            return std::span<const std::uint8_t>{};
        }
        write_seq_++;
        offset += chunk_len;
    }

    return std::span<const std::uint8_t>{tx_buf_.data(), tx_buf_.size()};
}

boost::asio::awaitable<void> reality_engine::process_available_records(const record_callback& callback, boost::system::error_code& ec)
{
    for (;;)
    {
        const auto buffered_before = rx_buf_->size();
        std::uint8_t content_type = 0;
        std::size_t payload_len = 0;
        try_decrypt_next_record(content_type, payload_len, ec);
        if (ec)
        {
            co_return;
        }
        if (rx_buf_->size() == buffered_before)
        {
            // No complete TLS record is available yet.
            co_return;
        }
        co_await callback(content_type, std::span<const std::uint8_t>(scratch_buf_.data(), payload_len), ec);
        if (ec)
        {
            co_return;
        }
        if (content_type == ::tls::kContentTypeAlert)
        {
            ec = boost::asio::error::eof;
            co_return;
        }
    }
}

void reality_engine::try_decrypt_next_record(std::uint8_t& content_type, std::size_t& payload_len, boost::system::error_code& ec)
{
    if (rx_buf_->size() < ::tls::kTlsRecordHeaderSize)
    {
        return;
    }

    const auto data_buffers = rx_buf_->data();
    std::array<std::uint8_t, ::tls::kTlsRecordHeaderSize> record_header{};
    if (boost::asio::buffer_copy(boost::asio::buffer(record_header), data_buffers) < ::tls::kTlsRecordHeaderSize)
    {
        return;
    }

    const auto record_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(record_header[3]) << 8) | record_header[4]);
    if (record_len > kMaxTlsCiphertextRecordLen)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }

    const std::uint32_t frame_size = ::tls::kTlsRecordHeaderSize + record_len;

    if (rx_buf_->size() < frame_size)
    {
        return;
    }

    record_buf_.resize(frame_size);
    if (boost::asio::buffer_copy(boost::asio::buffer(record_buf_), data_buffers) < frame_size)
    {
        ec = boost::asio::error::fault;
        return;
    }

    const std::span<const std::uint8_t> record_data(record_buf_.data(), frame_size);

    payload_len = ::tls::record_layer::decrypt_record(
        decrypt_ctx_, cipher_, read_key_, read_iv_, read_seq_, record_data, std::span<std::uint8_t>(scratch_buf_), content_type, ec);
    if (ec)
    {
        return;
    }

    read_seq_++;
    rx_buf_->consume(frame_size);
}

}    // namespace mux
