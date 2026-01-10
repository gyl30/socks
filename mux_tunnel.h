#ifndef MUX_TUNNEL_H
#define MUX_TUNNEL_H

#include <memory>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <boost/asio.hpp>
#include "mux_protocol.h"
#include "log.h"
#include "mux_connection.h"

namespace mux
{

class mux_stream : public mux_stream_interface, public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id, const std::shared_ptr<mux_connection>& connection, const boost::asio::any_io_executor& ex)
        : id_(id), connection_(connection), recv_channel_(ex, 128)
    {
    }

    ~mux_stream() override { close_internal(); }

    [[nodiscard]] std::uint32_t id() const { return id_; }

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::vector<std::uint8_t>>> async_read_some()
    {
        co_return co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    }

    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> async_write_some(const void* data, std::size_t len)
    {
        if (is_closed_)
        {
            co_return boost::asio::error::broken_pipe;
        }
        std::vector<uint8_t> payload(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + len);
        if (!connection_)
        {
            co_return boost::asio::error::operation_aborted;
        }
        co_return co_await connection_->send_async(id_, CMD_DAT, std::move(payload));
    }

    boost::asio::awaitable<void> close();

    void on_data(std::vector<uint8_t> data) override
    {
        if (!is_closed_)
        {
            recv_channel_.try_send(boost::system::error_code(), std::move(data));
        }
    }

    void on_close() override { close_internal(); }

    void on_reset() override { close_internal(); }

   private:
    void close_internal()
    {
        bool expected = false;
        if (is_closed_.compare_exchange_strong(expected, true))
        {
            recv_channel_.close();
        }
    }

    std::uint32_t id_ = 0;
    std::shared_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<bool> is_closed_{false};
};

template <typename StreamLayer>
class mux_tunnel_impl : public std::enable_shared_from_this<mux_tunnel_impl<StreamLayer>>
{
   public:
    explicit mux_tunnel_impl(StreamLayer socket, reality_engine engine)
        : connection_(std::make_shared<mux_connection>(std::move(socket), std::move(engine), streams_, mutex_))
    {
    }

    std::shared_ptr<mux_connection> get_connection() const { return connection_; }

    void register_stream(uint32_t id, std::shared_ptr<mux_stream_interface> stream)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_[id] = stream;
    }

    boost::asio::awaitable<void> run()
    {
        if (connection_)
        {
            co_await connection_->start();
        }
    }

    std::shared_ptr<mux_stream> create_stream()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::uint32_t id = next_local_id_;
        next_local_id_ += 2;
        auto stream = std::make_shared<mux_stream>(id, connection_, connection_->get_executor());
        streams_[id] = stream;
        return stream;
    }

    void remove_stream(std::uint32_t id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        streams_.erase(id);
    }

   private:
    mux_connection::stream_map_t streams_;
    std::mutex mutex_;
    std::shared_ptr<mux_connection> connection_;
    std::uint32_t next_local_id_ = 1;
};

inline boost::asio::awaitable<void> mux_stream::close()
{
    if (is_closed_)
    {
        co_return;
    }
    close_internal();
    if (connection_)
    {
        co_await connection_->send_async(id_, CMD_FIN, {});
    }
}

}    // namespace mux
#endif
