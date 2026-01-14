#ifndef MUX_STREAM_H
#define MUX_STREAM_H

#include <memory>
#include <vector>
#include <atomic>
#include <boost/asio.hpp>
#include "log.h"
#include "mux_protocol.h"
#include "mux_connection.h"

namespace mux
{

class mux_stream : public mux_stream_interface, public std::enable_shared_from_this<mux_stream>
{
   public:
    mux_stream(std::uint32_t id, std::uint32_t cid, const std::shared_ptr<mux_connection> &connection, const boost::asio::any_io_executor &ex)
        : id_(id), cid_(cid), connection_(connection), recv_channel_(ex, 128)
    {
    }

    ~mux_stream() override { close_internal(); }

    [[nodiscard]] std::uint32_t id() const { return id_; }

    [[nodiscard]] boost::asio::awaitable<std::tuple<boost::system::error_code, std::vector<std::uint8_t>>> async_read_some()
    {
        co_return co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    }

    [[nodiscard]] boost::asio::awaitable<boost::system::error_code> async_write_some(const void *data, std::size_t len)
    {
        if (is_closed_)
        {
            co_return boost::asio::error::broken_pipe;
        }

        std::vector<uint8_t> payload(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + len);
        tx_bytes_.fetch_add(len, std::memory_order_relaxed);
        auto conn = connection_.lock();
        if (!conn)
        {
            co_return boost::asio::error::operation_aborted;
        }
        co_return co_await conn->send_async(id_, CMD_DAT, std::move(payload));
    }

    boost::asio::awaitable<void> close()
    {
        if (is_closed_)
        {
            co_return;
        }

        close_internal();
        if (auto conn = connection_.lock())
        {
            co_await conn->send_async(id_, CMD_FIN, {});
        }
    }

    void on_data(std::vector<uint8_t> data) override
    {
        if (!is_closed_)
        {
            rx_bytes_.fetch_add(data.size(), std::memory_order_relaxed);
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
            LOG_INFO("mux {} stream {} closed stats tx {} rx {}", cid_, id_, tx_bytes_.load(), rx_bytes_.load());
            if (auto conn = connection_.lock())
            {
                conn->remove_stream(id_);
            }
        }
    }

    std::uint32_t id_ = 0;
    std::uint32_t cid_ = 0;
    std::weak_ptr<mux_connection> connection_;
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::uint8_t>)> recv_channel_;
    std::atomic<bool> is_closed_{false};
    std::atomic<uint64_t> tx_bytes_{0};
    std::atomic<uint64_t> rx_bytes_{0};
};

}    // namespace mux

#endif
