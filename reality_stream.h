#ifndef REALITY_STREAM_H
#define REALITY_STREAM_H

#include <vector>
#include <memory>
#include <cstring>
#include <boost/asio.hpp>
#include "log.h"
#include "reality_core.h"

namespace reality
{

template <typename NextLayer>
class reality_stream
{
   public:
    using executor_type = typename NextLayer::executor_type;
    using lowest_layer_type = typename NextLayer::lowest_layer_type;

    reality_stream(NextLayer next, std::vector<uint8_t> r_key, std::vector<uint8_t> r_iv, std::vector<uint8_t> w_key, std::vector<uint8_t> w_iv)
        : next_layer_(std::move(next)),
          read_key_(std::move(r_key)),
          read_iv_(std::move(r_iv)),
          write_key_(std::move(w_key)),
          write_iv_(std::move(w_iv))
    {
    }

    executor_type get_executor() { return next_layer_.get_executor(); }
    lowest_layer_type& lowest_layer() { return next_layer_.lowest_layer(); }
    const lowest_layer_type& lowest_layer() const { return next_layer_.lowest_layer(); }

    void on_write(boost::system::error_code ec, std::size_t /*written*/)
    {
        if (ec)
        {
            LOG_ERROR("reality stream write failed: {}", ec.message());
        }
    }
    template <typename ConstBufferSequence, typename WriteToken>
    auto async_write_some(const ConstBufferSequence& buffers, WriteToken&& token)
    {
        return boost::asio::async_initiate<WriteToken, void(boost::system::error_code, std::size_t)>(
            [this](auto handler, const ConstBufferSequence& buffers)
            {
                std::size_t buffer_size = boost::asio::buffer_size(buffers);
                if (buffer_size == 0)
                {
                    auto ex = boost::asio::get_associated_executor(handler, get_executor());
                    boost::asio::post(ex, [handler = std::move(handler)]() mutable { handler(boost::system::error_code(), 0); });
                    return;
                }

                std::size_t bytes_to_encrypt = std::min(buffer_size, MAX_TLS_PLAINTEXT_LEN);

                std::vector<uint8_t> plaintext(bytes_to_encrypt);
                boost::asio::buffer_copy(boost::asio::buffer(plaintext), buffers, bytes_to_encrypt);

                LOG_DEBUG("encrypting app data: {} bytes, seq: {}", bytes_to_encrypt, write_seq_);

                boost::system::error_code ec;
                std::vector<uint8_t> ciphertext =
                    TlsRecordLayer::encrypt_record(write_key_, write_iv_, write_seq_, plaintext, CONTENT_TYPE_APPLICATION_DATA, ec);

                if (ec)
                {
                    LOG_ERROR("reality stream encryption failed: {}", ec.message());
                    auto ex = boost::asio::get_associated_executor(handler, get_executor());
                    boost::asio::post(ex, [handler = std::move(handler), ec]() mutable { handler(ec, 0); });
                    return;
                }

                write_seq_++;

                auto ciphertext_ptr = std::make_shared<std::vector<uint8_t>>(std::move(ciphertext));

                boost::asio::async_write(
                    next_layer_,
                    boost::asio::buffer(*ciphertext_ptr),
                    [this, handler = std::move(handler), ciphertext_ptr, bytes_to_encrypt](boost::system::error_code ec, std::size_t written) mutable
                    {
                        on_write(ec, written);
                        handler(ec, ec ? 0 : bytes_to_encrypt);
                    });
            },
            token,
            buffers);
    }

    template <typename MutableBufferSequence, typename ReadToken>
    auto async_read_some(const MutableBufferSequence& buffers, ReadToken&& token)
    {
        return boost::asio::async_initiate<ReadToken, void(boost::system::error_code, std::size_t)>(
            [this](auto handler, const MutableBufferSequence& buffers)
            {
                if (!decrypted_buffer_.empty())
                {
                    auto bytes_copied = boost::asio::buffer_copy(buffers, boost::asio::buffer(decrypted_buffer_));

                    if (bytes_copied == decrypted_buffer_.size())
                    {
                        decrypted_buffer_.clear();
                    }
                    else
                    {
                        decrypted_buffer_.erase(decrypted_buffer_.begin(), decrypted_buffer_.begin() + bytes_copied);
                    }

                    auto ex = boost::asio::get_associated_executor(handler, get_executor());
                    boost::asio::post(ex,
                                      [handler = std::move(handler), bytes_copied]() mutable { handler(boost::system::error_code(), bytes_copied); });
                    return;
                }

                read_loop(std::move(handler), buffers);
            },
            token,
            buffers);
    }

    template <typename ShutdownToken>
    auto async_shutdown(ShutdownToken&& token)
    {
        return boost::asio::async_initiate<ShutdownToken, void(boost::system::error_code)>(
            [this](auto handler)
            {
                auto ex = boost::asio::get_associated_executor(handler, get_executor());
                boost::asio::post(ex, [handler = std::move(handler)]() mutable { handler(boost::system::error_code()); });
            },
            token);
    }

   private:
    template <typename ReadHandler, typename MutableBufferSequence>
    void read_loop(ReadHandler handler, const MutableBufferSequence& out_buffers)
    {
        if (incoming_buffer_.size() < TLS_RECORD_HEADER_SIZE)
        {
            std::size_t bytes_needed = TLS_RECORD_HEADER_SIZE - incoming_buffer_.size();

            auto temp_buf = std::make_shared<std::vector<uint8_t>>(bytes_needed);

            boost::asio::async_read(next_layer_,
                                    boost::asio::buffer(*temp_buf),
                                    [this, handler = std::move(handler), out_buffers, temp_buf](boost::system::error_code ec, std::size_t n) mutable
                                    {
                                        if (ec)
                                        {
                                            handler(ec, 0);
                                            return;
                                        }

                                        incoming_buffer_.insert(
                                            incoming_buffer_.end(), temp_buf->begin(), temp_buf->begin() + static_cast<uint32_t>(n));
                                        read_loop(std::move(handler), out_buffers);
                                    });
            return;
        }

        uint16_t record_len = (static_cast<uint16_t>(incoming_buffer_[3]) << 8) | incoming_buffer_[4];
        uint32_t total_frame_size = TLS_RECORD_HEADER_SIZE + record_len;

        if (incoming_buffer_.size() < total_frame_size)
        {
            std::size_t bytes_needed = total_frame_size - incoming_buffer_.size();
            auto temp_buf = std::make_shared<std::vector<uint8_t>>(bytes_needed);

            boost::asio::async_read(next_layer_,
                                    boost::asio::buffer(*temp_buf),
                                    [this, handler = std::move(handler), out_buffers, temp_buf](boost::system::error_code ec, std::size_t n) mutable
                                    {
                                        if (ec)
                                        {
                                            handler(ec, 0);
                                            return;
                                        }

                                        incoming_buffer_.insert(
                                            incoming_buffer_.end(), temp_buf->begin(), temp_buf->begin() + static_cast<uint32_t>(n));
                                        read_loop(std::move(handler), out_buffers);
                                    });
            return;
        }

        uint8_t content_type = 0;
        boost::system::error_code ec;

        std::vector<uint8_t> record_data(incoming_buffer_.begin(), incoming_buffer_.begin() + total_frame_size);

        if (incoming_buffer_.size() == total_frame_size)
        {
            incoming_buffer_.clear();
        }
        else
        {
            incoming_buffer_.erase(incoming_buffer_.begin(), incoming_buffer_.begin() + total_frame_size);
        }

        std::vector<uint8_t> plaintext = TlsRecordLayer::decrypt_record(read_key_, read_iv_, read_seq_, record_data, content_type, ec);

        if (ec)
        {
            LOG_ERROR("app layer decrypt failed: {}", ec.message());
            handler(ec, 0);
            return;
        }

        read_seq_++;

        if (content_type == CONTENT_TYPE_APPLICATION_DATA)
        {
            LOG_DEBUG("decrypted app data: {} bytes", plaintext.size());

            decrypted_buffer_.insert(decrypted_buffer_.end(), plaintext.begin(), plaintext.end());

            auto bytes_copied = boost::asio::buffer_copy(out_buffers, boost::asio::buffer(decrypted_buffer_));

            if (bytes_copied == decrypted_buffer_.size())
            {
                decrypted_buffer_.clear();
            }
            else
            {
                decrypted_buffer_.erase(decrypted_buffer_.begin(), decrypted_buffer_.begin() + bytes_copied);
            }

            handler(boost::system::error_code(), bytes_copied);
        }
        else if (content_type == CONTENT_TYPE_ALERT)
        {
            LOG_INFO("received tls alert");
            handler(boost::asio::error::eof, 0);
        }
        else if (content_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC)
        {
            LOG_DEBUG("ignored post-handshake ccs");
            read_loop(std::move(handler), out_buffers);
        }
        else if (content_type == CONTENT_TYPE_HANDSHAKE)
        {
            LOG_DEBUG("ignored post-handshake handshake msg");
            read_loop(std::move(handler), out_buffers);
        }
        else
        {
            LOG_ERROR("unknown content type: {}", content_type);
            handler(boost::system::error_code(boost::asio::error::invalid_argument), 0);
        }
    }

    NextLayer next_layer_;

    std::vector<uint8_t> read_key_;
    std::vector<uint8_t> read_iv_;
    std::vector<uint8_t> write_key_;
    std::vector<uint8_t> write_iv_;

    uint64_t read_seq_ = 0;
    uint64_t write_seq_ = 0;

    std::vector<uint8_t> incoming_buffer_;
    std::vector<uint8_t> decrypted_buffer_;
};

}    // namespace reality

#endif
