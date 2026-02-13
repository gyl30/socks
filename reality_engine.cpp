#include "reality_engine.h"
#include "tls_record_layer.h"

namespace mux
{

reality_engine::reality_engine(std::vector<std::uint8_t> r_key,
                               std::vector<std::uint8_t> r_iv,
                               std::vector<std::uint8_t> w_key,
                               std::vector<std::uint8_t> w_iv,
                               const EVP_CIPHER* cipher)
    : read_key_(std::move(r_key)),
      read_iv_(std::move(r_iv)),
      write_key_(std::move(w_key)),
      write_iv_(std::move(w_iv)),
      rx_buf_(std::make_unique<asio::streambuf>(kMaxBufSize)),
      cipher_(cipher)
{
    rx_buf_->prepare(kInitialBufSize);
    scratch_buf_.resize(kMaxBufSize);
    tx_buf_.reserve(kMaxBufSize);
}

std::span<const std::uint8_t> reality_engine::encrypt(const std::vector<std::uint8_t>& plaintext, std::error_code& ec)
{
    ec.clear();
    tx_buf_.clear();

    if (plaintext.empty())
    {
        return {};
    }
    reality::tls_record_layer::encrypt_record_append(
        encrypt_ctx_, cipher_, write_key_, write_iv_, write_seq_, plaintext, reality::kContentTypeApplicationData, tx_buf_, ec);
    if (ec)
    {
        return {};
    }

    write_seq_++;

    return {tx_buf_.data(), tx_buf_.size()};
}

void reality_engine::process_available_records(std::error_code& ec, const record_callback& callback)
{
    ec.clear();
    std::uint8_t content_type = 0;
    std::size_t payload_len = 0;

    while (try_decrypt_next_record(content_type, payload_len, ec))
    {
        if (ec)
        {
            return;
        }

        callback(content_type, std::span<const std::uint8_t>(scratch_buf_.data(), payload_len));

        if (content_type == reality::kContentTypeAlert)
        {
            ec = asio::error::eof;
            return;
        }
    }
}

bool reality_engine::try_decrypt_next_record(std::uint8_t& content_type, std::size_t& payload_len, std::error_code& ec)
{
    if (rx_buf_->size() < reality::kTlsRecordHeaderSize)
    {
        return false;
    }

    const auto* p = static_cast<const std::uint8_t*>(rx_buf_->data().data());
    const auto record_len = static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[3]) << 8) | p[4]);
    const std::uint32_t frame_size = reality::kTlsRecordHeaderSize + record_len;

    if (rx_buf_->size() < frame_size)
    {
        return false;
    }

    const std::span<const std::uint8_t> record_data(p, frame_size);

    const std::size_t decrypted_len = reality::tls_record_layer::decrypt_record(
        decrypt_ctx_, cipher_, read_key_, read_iv_, read_seq_, record_data, std::span<std::uint8_t>(scratch_buf_), content_type, ec);

    if (ec)
    {
        return true;
    }

    read_seq_++;
    rx_buf_->consume(frame_size);
    payload_len = decrypted_len;
    return true;
}

}    // namespace mux
