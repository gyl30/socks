#include "mux_stream.h"

namespace mux
{

mux_stream::mux_stream(std::uint32_t id,
                       std::uint32_t cid,
                       const std::string& trace_id,
                       const std::shared_ptr<mux_connection>& connection,
                       const asio::any_io_executor& ex)
    : id_(id), connection_(connection), recv_channel_(ex, 128)
{
    ctx_.trace_id = trace_id;
    ctx_.conn_id = cid;
    ctx_.stream_id = id;
}

mux_stream::~mux_stream()
{
    close_internal();
}

std::uint32_t mux_stream::id() const
{
    return id_;
}

asio::awaitable<std::tuple<std::error_code, std::vector<std::uint8_t>>> mux_stream::async_read_some()
{
    co_return co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
}

asio::awaitable<std::error_code> mux_stream::async_write_some(const void* data, std::size_t len)
{
    if (fin_sent_)
    {
        co_return asio::error::broken_pipe;
    }

    std::vector<uint8_t> payload(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + len);
    tx_bytes_.fetch_add(len, std::memory_order_relaxed);
    auto conn = connection_.lock();
    if (!conn)
    {
        co_return asio::error::operation_aborted;
    }
    co_return co_await conn->send_async(id_, CMD_DAT, std::move(payload));
}

asio::awaitable<void> mux_stream::close()
{
    bool expected = false;
    if (!fin_sent_.compare_exchange_strong(expected, true))
    {
        co_return;
    }

    LOG_CTX_DEBUG(ctx_, "{} sending FIN", log_event::MUX);
    if (auto conn = connection_.lock())
    {
        co_await conn->send_async(id_, CMD_FIN, {});
    }

    if (fin_received_)
    {
        close_internal();
    }
}

void mux_stream::on_data(std::vector<uint8_t> data)
{
    if (!fin_received_)
    {
        rx_bytes_.fetch_add(data.size(), std::memory_order_relaxed);
        recv_channel_.try_send(std::error_code(), std::move(data));
    }
}

void mux_stream::on_close()
{
    bool expected = false;
    if (!fin_received_.compare_exchange_strong(expected, true))
    {
        return;
    }

    LOG_CTX_DEBUG(ctx_, "{} received FIN", log_event::MUX);
    recv_channel_.close();

    if (fin_sent_)
    {
        close_internal();
    }
}

void mux_stream::on_reset()
{
    close_internal();
}

void mux_stream::close_internal()
{
    bool expected = false;
    if (is_closed_.compare_exchange_strong(expected, true))
    {
        recv_channel_.close();
        LOG_CTX_INFO(ctx_, "{} closed stats tx {} rx {}", log_event::MUX, tx_bytes_.load(), rx_bytes_.load());
        if (auto conn = connection_.lock())
        {
            conn->remove_stream(id_);
        }
    }
}

}    // namespace mux
