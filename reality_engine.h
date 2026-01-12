#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <vector>
#include <cstring>
#include <span>
#include <boost/system/error_code.hpp>
#include <boost/asio.hpp>
#include "reality_core.h"
#include "log.h"

class reality_engine
{
   public:
    static constexpr auto RX_BUF_SIZE = 18 * 1024;
    static constexpr auto COMPACT_THRESHOLD = 4 * 1024;
    static constexpr auto TX_BUF_INITIAL_SIZE = 16 * 1024;
    static constexpr auto SCRATCH_BUF_SIZE = 18 * 1024;

    reality_engine(std::vector<uint8_t> r_key, std::vector<uint8_t> r_iv, std::vector<uint8_t> w_key, std::vector<uint8_t> w_iv)
        : read_key_(std::move(r_key)), read_iv_(std::move(r_iv)), write_key_(std::move(w_key)), write_iv_(std::move(w_iv))
    {
        rx_buf_.resize(RX_BUF_SIZE);
        tx_buf_.reserve(TX_BUF_INITIAL_SIZE);
        scratch_buf_.resize(SCRATCH_BUF_SIZE);
        LOG_DEBUG("reality engine initialized rx buffer size {} bytes", RX_BUF_SIZE);
    }

    [[nodiscard]] std::span<uint8_t> get_write_buffer()
    {
        compact_if_needed();
        return {rx_buf_.data() + rx_end_, rx_buf_.size() - rx_end_};
    }

    void commit_written(size_t n) { rx_end_ += n; }

    /**
     * @brief 处理缓冲区中的 TLS 记录，解密并通过回调传递数据，避免 vector 拷贝。
     * @tparam Callback 类型 void(uint8_t type, std::span<const uint8_t> data)
     */
    template <typename Callback>
    void process_available_records(boost::system::error_code& ec, Callback&& callback)
    {
        ec.clear();

        while (true)
        {
            const size_t available = rx_end_ - rx_pos_;
            if (available < reality::TLS_RECORD_HEADER_SIZE)
            {
                break;
            }

            const uint8_t* p = rx_buf_.data() + rx_pos_;
            const auto record_len = static_cast<uint16_t>((static_cast<uint16_t>(p[3]) << 8) | p[4]);
            const uint32_t frame_size = reality::TLS_RECORD_HEADER_SIZE + record_len;

            if (available < frame_size)
            {
                break;
            }

            const std::span<const uint8_t> record_data(rx_buf_.data() + rx_pos_, frame_size);
            rx_pos_ += frame_size;

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

            LOG_TRACE("reality engine decrypted seq {} type {} len {}", read_seq_, static_cast<int>(content_type), decrypted_len);
            read_seq_++;

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

        LOG_TRACE("reality engine encrypted seq {} len {} to {}", write_seq_, plaintext.size(), tx_buf_.size());
        write_seq_++;

        return {tx_buf_.data(), tx_buf_.size()};
    }

   private:
    void compact_if_needed()
    {
        const size_t space_at_tail = rx_buf_.size() - rx_end_;
        if (space_at_tail < COMPACT_THRESHOLD)
        {
            if (rx_pos_ > 0)
            {
                const size_t data_len = rx_end_ - rx_pos_;
                if (data_len > 0)
                {
                    std::memmove(rx_buf_.data(), rx_buf_.data() + rx_pos_, data_len);
                }
                rx_pos_ = 0;
                rx_end_ = data_len;
            }
        }
    }

    std::vector<uint8_t> read_key_;
    std::vector<uint8_t> read_iv_;
    std::vector<uint8_t> write_key_;
    std::vector<uint8_t> write_iv_;
    uint64_t read_seq_ = 0;
    uint64_t write_seq_ = 0;
    std::vector<uint8_t> rx_buf_;
    uint32_t rx_pos_ = 0;
    uint32_t rx_end_ = 0;

    std::vector<uint8_t> tx_buf_;
    std::vector<uint8_t> scratch_buf_;
};

#endif
