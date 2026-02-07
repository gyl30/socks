#include <tuple>
#include <vector>
#include <string>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

#include <asio/error.hpp>
#include <asio/as_tuple.hpp>
#include <asio/awaitable.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/any_io_executor.hpp>

#include "log.h"
#include "mux_stream.h"
#include "log_context.h"
#include "mux_protocol.h"
#include "mux_connection.h"

namespace mux
{

mux_stream::mux_stream(std::uint32_t id,
                       std::uint32_t cid,
                       const std::string& trace_id,
                       const std::shared_ptr<mux_connection>& connection,
                       const asio::any_io_executor& ex)
    : id_(id), connection_(connection), recv_channel_(ex, 1024)
{
    ctx_.trace_id(trace_id);
    ctx_.conn_id(cid);
    ctx_.stream_id(id);
}

mux_stream::~mux_stream() { close_internal(); }

std::uint32_t mux_stream::id() const { return id_; }

asio::awaitable<std::tuple<std::error_code, std::vector<std::uint8_t>>> mux_stream::async_read_some()
{
    const auto [ec, data] = co_await recv_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
    if (ec)
    {
        co_return std::make_tuple(ec, std::vector<std::uint8_t>{});
    }
    if (data.empty())
    {
        co_return std::make_tuple(asio::error::eof, std::vector<std::uint8_t>{});
    }
    rx_bytes_ += data.size();
    co_return std::make_tuple(std::error_code{}, std::move(data));
}

asio::awaitable<std::error_code> mux_stream::async_write_some(const void* data, std::size_t len)
{
    if (is_closed_)
    {
        co_return asio::error::operation_aborted;
    }

    const auto connection = connection_.lock();
    if (!connection)
    {
        co_return asio::error::connection_aborted;
    }

    std::vector<std::uint8_t> payload(static_cast<const std::uint8_t*>(data), static_cast<const std::uint8_t*>(data) + len);
    const auto ec = co_await connection->send_async(id_, kCmdDat, std::move(payload));
    if (!ec)
    {
        tx_bytes_ += len;
    }
    co_return ec;
}

asio::awaitable<void> mux_stream::close()
{
    if (is_closed_.exchange(true))
    {
        co_return;
    }

    const auto connection = connection_.lock();
    if (connection)
    {
        if (!fin_sent_.exchange(true))
        {
            LOG_CTX_DEBUG(ctx_, "{} stream {} sending fin", log_event::kMux, id_);
            (void)co_await connection->send_async(id_, kCmdFin, {});
        }
    }

    close_internal();
}

void mux_stream::on_data(std::vector<std::uint8_t> data)
{
    if (!is_closed_)
    {
        recv_channel_.try_send(std::error_code{}, std::move(data));
    }
}

void mux_stream::on_close()
{
    if (!fin_received_.exchange(true))
    {
        LOG_CTX_DEBUG(ctx_, "{} stream {} received fin", log_event::kMux, id_);
        recv_channel_.try_send(std::error_code{}, std::vector<std::uint8_t>{});
    }
}

void mux_stream::on_reset()
{
    is_closed_ = true;
    recv_channel_.close();
}

void mux_stream::close_internal()
{
    is_closed_ = true;
    recv_channel_.close();
}

}    // namespace mux
