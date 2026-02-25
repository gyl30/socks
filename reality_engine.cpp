#include <span>
#include <array>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <expected>

#include <openssl/types.h>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include "reality_core.h"
#include "reality_engine.h"
#include "tls_record_layer.h"

namespace mux
{

namespace
{
constexpr std::size_t kMaxTlsCiphertextRecordLen = reality::kMaxTlsPlaintextLen + 256;
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

std::expected<std::span<const std::uint8_t>, boost::system::error_code> reality_engine::encrypt(const std::vector<std::uint8_t>& plaintext)
{
    tx_buf_.clear();

    if (plaintext.empty())
    {
        return std::span<const std::uint8_t>{};
    }
    auto r = reality::tls_record_layer::encrypt_record_append(
        encrypt_ctx_, cipher_, write_key_, write_iv_, write_seq_, plaintext, reality::kContentTypeApplicationData, tx_buf_);
    if (!r)
    {
        return std::unexpected(r.error());
    }

    write_seq_++;

    return std::span<const std::uint8_t>{tx_buf_.data(), tx_buf_.size()};
}

std::expected<void, boost::system::error_code> reality_engine::process_available_records(const record_callback& callback)
{
    std::uint8_t content_type = 0;
    std::size_t payload_len = 0;

    for (;;)
    {
        const auto decrypt_res = try_decrypt_next_record(content_type, payload_len);
        if (!decrypt_res)
        {
            return std::unexpected(decrypt_res.error());
        }
        if (!*decrypt_res)
        {
            break;
        }

        callback(content_type, std::span<const std::uint8_t>(scratch_buf_.data(), payload_len));

        if (content_type == reality::kContentTypeAlert)
        {
            return std::unexpected(boost::asio::error::eof);
        }
    }
    return {};
}

std::expected<bool, boost::system::error_code> reality_engine::try_decrypt_next_record(std::uint8_t& content_type, std::size_t& payload_len)
{
    if (rx_buf_->size() < reality::kTlsRecordHeaderSize)
    {
        return false;
    }

    const auto data_buffers = rx_buf_->data();
    std::array<std::uint8_t, reality::kTlsRecordHeaderSize> record_header{};
    if (boost::asio::buffer_copy(boost::asio::buffer(record_header), data_buffers) < reality::kTlsRecordHeaderSize)
    {
        return false;
    }

    const auto record_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(record_header[3]) << 8) | record_header[4]);
    if (record_len > kMaxTlsCiphertextRecordLen)
    {
        return std::unexpected(boost::system::errc::make_error_code(boost::system::errc::message_size));
    }

    const std::uint32_t frame_size = reality::kTlsRecordHeaderSize + record_len;

    if (rx_buf_->size() < frame_size)
    {
        return false;
    }

    record_buf_.resize(frame_size);
    if (boost::asio::buffer_copy(boost::asio::buffer(record_buf_), data_buffers) < frame_size)
    {
        return std::unexpected(boost::asio::error::fault);
    }

    const std::span<const std::uint8_t> record_data(record_buf_.data(), frame_size);

    auto decrypted = reality::tls_record_layer::decrypt_record(
        decrypt_ctx_, cipher_, read_key_, read_iv_, read_seq_, record_data, std::span<std::uint8_t>(scratch_buf_), content_type);

    if (!decrypted)
    {
        return std::unexpected(decrypted.error());
    }

    const std::size_t decrypted_len = *decrypted;

    read_seq_++;
    rx_buf_->consume(frame_size);
    payload_len = decrypted_len;
    return true;
}

}    // namespace mux
