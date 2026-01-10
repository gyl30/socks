#ifndef REALITY_ENGINE_H
#define REALITY_ENGINE_H

#include <vector>
#include <cstring>
#include <memory>
#include <span>
#include <algorithm>
#include <boost/system/error_code.hpp>
#include "reality_core.h"
#include "log.h"

class RealityEngine
{
   public:
    static constexpr size_t RX_BUF_SIZE = 18 * 1024;
    static constexpr size_t COMPACT_THRESHOLD = 4 * 1024;

    RealityEngine(std::vector<uint8_t> r_key, std::vector<uint8_t> r_iv, std::vector<uint8_t> w_key, std::vector<uint8_t> w_iv)
        : read_key_(std::move(r_key)), read_iv_(std::move(r_iv)), write_key_(std::move(w_key)), write_iv_(std::move(w_iv))
    {
        rx_buf_.resize(RX_BUF_SIZE);
        LOG_DEBUG("[RealityEngine] Initialized. RX Buffer: {} bytes", RX_BUF_SIZE);
    }

    std::span<uint8_t> get_write_buffer()
    {
        compact_if_needed();
        return {rx_buf_.data() + rx_end_, rx_buf_.size() - rx_end_};
    }

    void commit_written(size_t n) { rx_end_ += n; }

    std::vector<std::vector<uint8_t>> decrypt_available_records(boost::system::error_code& ec)
    {
        std::vector<std::vector<uint8_t>> plaintexts;
        ec.clear();

        while (true)
        {
            size_t available = rx_end_ - rx_pos_;
            if (available < reality::TLS_RECORD_HEADER_SIZE)
                break;

            const uint8_t* p = rx_buf_.data() + rx_pos_;
            uint16_t record_len = (static_cast<uint16_t>(p[3]) << 8) | p[4];
            size_t frame_size = reality::TLS_RECORD_HEADER_SIZE + record_len;

            if (available < frame_size)
            {
                break;
            }

            std::vector<uint8_t> record_data(rx_buf_.begin() + rx_pos_, rx_buf_.begin() + rx_pos_ + frame_size);
            rx_pos_ += frame_size;

            uint8_t content_type = 0;
            auto plaintext = reality::TlsRecordLayer::decrypt_record(read_key_, read_iv_, read_seq_, record_data, content_type, ec);

            if (ec)
            {
                LOG_ERROR("[RealityEngine] Decrypt failed at seq={}: {}", read_seq_, ec.message());
                return {};
            }

            const char* type_str = "Unknown";
            if (content_type == reality::CONTENT_TYPE_APPLICATION_DATA)
                type_str = "AppData";
            else if (content_type == reality::CONTENT_TYPE_HANDSHAKE)
                type_str = "Handshake";
            else if (content_type == reality::CONTENT_TYPE_ALERT)
                type_str = "Alert";
            else if (content_type == reality::CONTENT_TYPE_CHANGE_CIPHER_SPEC)
                type_str = "CCS";

            LOG_TRACE("[RealityEngine] Decrypted seq={} type={} len={}", read_seq_, type_str, plaintext.size());
            read_seq_++;

            if (content_type == reality::CONTENT_TYPE_APPLICATION_DATA && !plaintext.empty())
            {
                plaintexts.push_back(std::move(plaintext));
            }
            else if (content_type == reality::CONTENT_TYPE_ALERT)
            {
                LOG_INFO("[RealityEngine] Received TLS Alert. Closing connection.");
                ec = boost::asio::error::eof;
                return {};
            }
        }
        return plaintexts;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, boost::system::error_code& ec)
    {
        ec.clear();
        if (plaintext.empty())
            return {};

        auto ciphertext =
            reality::TlsRecordLayer::encrypt_record(write_key_, write_iv_, write_seq_, plaintext, reality::CONTENT_TYPE_APPLICATION_DATA, ec);

        if (ec)
        {
            LOG_ERROR("[RealityEngine] Encrypt failed at seq={}: {}", write_seq_, ec.message());
            return {};
        }

        LOG_TRACE("[RealityEngine] Encrypted seq={} len={}->{}", write_seq_, plaintext.size(), ciphertext.size());
        write_seq_++;
        return ciphertext;
    }

   private:
    void compact_if_needed()
    {
        size_t space_at_tail = rx_buf_.size() - rx_end_;
        if (space_at_tail < COMPACT_THRESHOLD)
        {
            if (rx_pos_ > 0)
            {
                size_t data_len = rx_end_ - rx_pos_;
                if (data_len > 0)
                {
                    std::memmove(rx_buf_.data(), rx_buf_.data() + rx_pos_, data_len);
                }
                rx_pos_ = 0;
                rx_end_ = data_len;
            }
        }
    }

    std::vector<uint8_t> read_key_, read_iv_, write_key_, write_iv_;
    uint64_t read_seq_ = 0, write_seq_ = 0;
    std::vector<uint8_t> rx_buf_;
    size_t rx_pos_ = 0;
    size_t rx_end_ = 0;
};

#endif
