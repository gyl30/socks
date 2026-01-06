#ifndef PREFIXED_STREAM_H
#define PREFIXED_STREAM_H

#include <boost/asio.hpp>
#include <vector>
#include <algorithm>
#include <utility>

template <typename NextLayer>
class PrefixedStream
{
   public:
    using executor_type = typename NextLayer::executor_type;
    using lowest_layer_type = typename NextLayer::lowest_layer_type;

    PrefixedStream(NextLayer next, std::vector<uint8_t> prefix) : next_layer_(std::move(next)), prefix_(std::move(prefix)) {}

    executor_type get_executor() { return next_layer_.get_executor(); }
    lowest_layer_type& lowest_layer() { return next_layer_.lowest_layer(); }
    const lowest_layer_type& lowest_layer() const { return next_layer_.lowest_layer(); }
    NextLayer& next_layer() { return next_layer_; }

    template <typename MutableBufferSequence, typename ReadToken>
    auto async_read_some(const MutableBufferSequence& buffers, ReadToken&& token)
    {
        return boost::asio::async_initiate<ReadToken, void(boost::system::error_code, size_t)>(
            [this](auto handler, const MutableBufferSequence& buffers)
            {
                if (!prefix_.empty())
                {
                    size_t bytes_copied = boost::asio::buffer_copy(buffers, boost::asio::buffer(prefix_));

                    if (bytes_copied >= prefix_.size())
                    {
                        prefix_.clear();
                    }
                    else
                    {
                        prefix_.erase(prefix_.begin(), prefix_.begin() + bytes_copied);
                    }

                    auto ex = boost::asio::get_associated_executor(handler, get_executor());
                    boost::asio::post(ex,
                                      [handler = std::move(handler), bytes_copied]() mutable { handler(boost::system::error_code(), bytes_copied); });
                }
                else
                {
                    next_layer_.async_read_some(buffers, std::move(handler));
                }
            },
            token,
            buffers);
    }

    template <typename ConstBufferSequence, typename WriteToken>
    auto async_write_some(const ConstBufferSequence& buffers, WriteToken&& token)
    {
        return next_layer_.async_write_some(buffers, std::forward<WriteToken>(token));
    }

   private:
    NextLayer next_layer_;
    std::vector<uint8_t> prefix_;
};

#endif
