#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <vector>
#include <cstring>
#include <span>
#include <memory>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include <boost/asio/streambuf.hpp>
#include "reality_core.h"
#include "log.h"

class reality_engine
{
   public:
    static constexpr auto INITIAL_BUF_SIZE = 16 * 1024;
    static constexpr auto MAX_BUF_SIZE = 64 * 1024;
    static constexpr auto SCRATCH_BUF_SIZE = 18 * 1024;
    static constexpr auto TX_BUF_INITIAL_SIZE = 16 * 1024;

    reality_engine(std::vector<uint8_t> r_key, std::vector<uint8_t> r_iv, std::vector<uint8_t> w_key, std::vector<uint8_t> w_iv)
        : read_key_(std::move(r_key)),
          read_iv_(std::move(r_iv)),
          write_key_(std::move(w_key)),
          write_iv_(std::move(w_iv)),
          rx_buf_(std::make_unique<boost::asio::streambuf>(MAX_BUF_SIZE))
    {
        rx_buf_->prepare(INITIAL_BUF_SIZE);
        tx_buf_.reserve(TX_BUF_INITIAL_SIZE);
        scratch_buf_.resize(SCRATCH_BUF_SIZE);
    }

    auto get_read_buffer(size_t size_hint = 4096) { return rx_buf_->prepare(size_hint); }

    void commit_read(size_t n) { rx_buf_->commit(n); }

    template <typename Callback>
    void process_available_records(boost::system::error_code& ec, Callback&& callback)
    {
        ec.clear();

        while (rx_buf_->size() >= reality::TLS_RECORD_HEADER_SIZE)
        {
            const auto* p = static_cast<const uint8_t*>(rx_buf_->data().data());
            const auto record_len = static_cast<uint16_t>((static_cast<uint16_t>(p[3]) << 8) | p[4]);
            const uint32_t frame_size = reality::TLS_RECORD_HEADER_SIZE + record_len;

            if (rx_buf_->size() < frame_size)
            {
                break;
            }

            const std::span<const uint8_t> record_data(p, frame_size);

            uint8_t content_type = 0;

            if (scratch_buf_.size() < frame_size)
            {
                scratch_buf_.resize(frame_size);
            }

            size_t decrypted_len = reality::tls_record_layer::decrypt_record(
                read_key_, read_iv_, read_seq_, record_data, std::span<uint8_t>(scratch_buf_), content_type, ec);

            if (ec)
            {
                LOG_ERROR("reality engine decrypt failed at seq {} error {}", read_seq_, ec.message());
                return;
            }

            read_seq_++;
            rx_buf_->consume(frame_size);

            callback(content_type, std::span<const uint8_t>(scratch_buf_.data(), decrypted_len));

            if (content_type == reality::CONTENT_TYPE_ALERT)
            {
                LOG_INFO("reality engine received tls alert closing connection");
                ec = boost::asio::error::eof;
                return;
            }
        }
    }

    [[nodiscard]] std::span<const uint8_t> encrypt(const std::vector<uint8_t>& plaintext, boost::system::error_code& ec)
    {
        ec.clear();
        tx_buf_.clear();

        if (plaintext.empty())
        {
            return {};
        }

        reality::tls_record_layer::encrypt_record_append(
            write_key_, write_iv_, write_seq_, plaintext, reality::CONTENT_TYPE_APPLICATION_DATA, tx_buf_, ec);

        if (ec)
        {
            LOG_ERROR("reality engine encrypt failed at seq {} error {}", write_seq_, ec.message());
            return {};
        }

        write_seq_++;

        return {tx_buf_.data(), tx_buf_.size()};
    }

   private:
    std::vector<uint8_t> read_key_;
    std::vector<uint8_t> read_iv_;
    std::vector<uint8_t> write_key_;
    std::vector<uint8_t> write_iv_;
    uint64_t read_seq_ = 0;
    uint64_t write_seq_ = 0;
    std::unique_ptr<boost::asio::streambuf> rx_buf_;

    std::vector<uint8_t> tx_buf_;
    std::vector<uint8_t> scratch_buf_;
};

#endif
