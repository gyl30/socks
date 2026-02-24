#include <tuple>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <boost/asio/error.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>

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
                       boost::asio::io_context& io_context)
    : id_(id), connection_(connection), recv_channel_(io_context, 1024)
{
    ctx_.trace_id(trace_id);
    ctx_.conn_id(cid);
    ctx_.stream_id(id);
}

mux_stream::~mux_stream() { close_internal(); }

std::uint32_t mux_stream::id() const { return id_; }

boost::asio::awaitable<std::tuple<boost::system::error_code, std::vector<std::uint8_t>>> mux_stream::async_read_some()
{
    auto [ec, data] = co_await recv_channel_.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
    if (ec)
    {
        co_return std::make_tuple(ec, std::vector<std::uint8_t>{});
    }
    if (data.empty())
    {
        co_return std::make_tuple(boost::asio::error::eof, std::vector<std::uint8_t>{});
    }
    rx_bytes_ += data.size();
    co_return std::make_tuple(boost::system::error_code{}, data);
}

boost::asio::awaitable<boost::system::error_code> mux_stream::async_write_some(const void* data, std::size_t len)
{
    if (len == 0)
    {
        co_return boost::asio::error::invalid_argument;
    }
    if (data == nullptr)
    {
        co_return boost::asio::error::invalid_argument;
    }
    std::vector<std::uint8_t> payload(static_cast<const std::uint8_t*>(data), static_cast<const std::uint8_t*>(data) + len);
    co_return co_await async_write_some(std::move(payload));
}

boost::asio::awaitable<boost::system::error_code> mux_stream::async_write_some(std::vector<std::uint8_t> payload)
{
    if (payload.empty())
    {
        co_return boost::asio::error::invalid_argument;
    }
    if (is_closed_.load(std::memory_order_acquire) || fin_sent_.load(std::memory_order_acquire))
    {
        co_return boost::asio::error::operation_aborted;
    }

    const auto connection = connection_.lock();
    if (!connection)
    {
        co_return boost::asio::error::connection_aborted;
    }

    const auto len = payload.size();
    const auto ec = co_await connection->send_async(id_, kCmdDat, std::move(payload));
    if (!ec)
    {
        tx_bytes_ += len;
    }
    co_return ec;
}

boost::asio::awaitable<void> mux_stream::close()
{
    if (is_closed_.exchange(true, std::memory_order_acq_rel))
    {
        co_return;
    }

    co_await send_fin_if_needed();
    close_internal();
}

boost::asio::awaitable<void> mux_stream::shutdown_send()
{
    if (is_closed_.load(std::memory_order_acquire))
    {
        co_return;
    }
    co_await send_fin_if_needed();
}

boost::asio::awaitable<void> mux_stream::send_fin_if_needed()
{
    if (fin_sent_.exchange(true, std::memory_order_acq_rel))
    {
        co_return;
    }
    const auto connection = connection_.lock();
    if (!connection)
    {
        co_return;
    }
    LOG_CTX_DEBUG(ctx_, "{} stream {} sending fin", log_event::kMux, id_);
    (void)co_await connection->send_async(id_, kCmdFin, {});
}

bool mux_stream::on_ack(std::vector<std::uint8_t> data)
{
    if (is_closed_.load(std::memory_order_acquire))
    {
        return false;
    }

    bool expected = true;
    if (!ack_pending_.compare_exchange_strong(expected, false, std::memory_order_acq_rel, std::memory_order_acquire))
    {
        return false;
    }

    if (!recv_channel_.try_send(boost::system::error_code{}, std::move(data)))
    {
        LOG_CTX_WARN(ctx_, "{} stream {} recv channel unavailable on ack", log_event::kMux, id_);
        close_internal();
        return false;
    }
    return true;
}

void mux_stream::on_data(std::vector<std::uint8_t> data)
{
    if (is_closed_.load(std::memory_order_acquire))
    {
        return;
    }
    ack_pending_.store(false, std::memory_order_release);
    if (!recv_channel_.try_send(boost::system::error_code{}, std::move(data)))
    {
        LOG_CTX_WARN(ctx_, "{} stream {} recv channel unavailable on data", log_event::kMux, id_);
        close_internal();
    }
}

void mux_stream::on_close()
{
    ack_pending_.store(false, std::memory_order_release);
    if (!fin_received_.exchange(true))
    {
        LOG_CTX_DEBUG(ctx_, "{} stream {} received fin", log_event::kMux, id_);
        if (!recv_channel_.try_send(boost::system::error_code{}, std::vector<std::uint8_t>{}))
        {
            LOG_CTX_WARN(ctx_, "{} stream {} recv channel unavailable on fin", log_event::kMux, id_);
            close_internal();
        }
    }
}

void mux_stream::on_reset()
{
    is_closed_.store(true, std::memory_order_release);
    ack_pending_.store(false, std::memory_order_release);
    recv_channel_.close();
}

void mux_stream::close_internal()
{
    is_closed_.store(true, std::memory_order_release);
    ack_pending_.store(false, std::memory_order_release);
    recv_channel_.close();
}

}    // namespace mux
