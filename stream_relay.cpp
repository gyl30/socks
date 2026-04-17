#include "stream_relay.h"

#include <algorithm>
#include <chrono>
#include <span>
#include <vector>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "log.h"
#include "net_utils.h"
#include "task_group.h"
#include "trace_store.h"

namespace relay
{

namespace
{

boost::asio::awaitable<void> relay_direction(stream_relay_context& context,
                                             stream_relay_transport& source,
                                             stream_relay_transport& destination,
                                             std::string_view stage_name,
                                             uint64_t& bytes_counter,
                                             const bool is_tx_direction)
{
    boost::system::error_code ec;
    std::vector<uint8_t> buffer(8192);
    for (;;)
    {
        const auto bytes_read = co_await source.read(buffer, ec);
        if (ec)
        {
            if (ec == boost::asio::error::timed_out)
            {
                continue;
            }
            if (ec == boost::asio::error::eof)
            {
                boost::system::error_code shutdown_ec;
                co_await destination.shutdown_send(shutdown_ec);
            }
            else
            {
                LOG_WARN("{} trace {:016x} conn {} stage relay {} read failed {}",
                         context.log_event_name,
                         context.trace_id,
                         context.conn_id,
                         stage_name,
                         ec.message());
                co_await destination.close();
            }
            break;
        }

        const auto bytes_written = co_await destination.write(std::span<const uint8_t>(buffer.data(), bytes_read), ec);
        if (ec)
        {
            LOG_WARN("{} trace {:016x} conn {} stage relay {} write failed {}",
                     context.log_event_name,
                     context.trace_id,
                     context.conn_id,
                     stage_name,
                     ec.message());
            co_await destination.close();
            break;
        }
        bytes_counter += bytes_written;
        context.last_activity_time_ms = net::now_ms();
        if (is_tx_direction)
        {
            trace_store::instance().add_live_tx_bytes(bytes_written);
        }
        else
        {
            trace_store::instance().add_live_rx_bytes(bytes_written);
        }
    }
}

boost::asio::awaitable<void> relay_idle_watchdog(stream_relay_context& context)
{
    const auto idle_timeout_ms = static_cast<uint64_t>(context.timeout.idle) * 1000ULL;
    while (true)
    {
        context.idle_timer.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await context.idle_timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }
        if (net::now_ms() - context.last_activity_time_ms <= idle_timeout_ms)
        {
            continue;
        }

        LOG_WARN("{} trace {:016x} conn {} stage relay idle timeout {}s",
                 context.log_event_name,
                 context.trace_id,
                 context.conn_id,
                 context.timeout.idle);
        co_await context.inbound.close();
        co_await context.outbound.close();
        break;
    }
}

}    // namespace

boost::asio::awaitable<stream_relay_result> relay_streams(stream_relay_context& context)
{
    stream_relay_result result;
    using boost::asio::experimental::awaitable_operators::operator||;
    auto executor = co_await boost::asio::this_coro::executor;
    auto& io_context = static_cast<boost::asio::io_context&>(executor.context());
    task_group tg(io_context);

    tg.spawn([&context]() -> boost::asio::awaitable<void>
             { co_await relay_direction(context,
                                        context.inbound,
                                        context.outbound,
                                        context.inbound_to_outbound_stage,
                                        context.tx_bytes,
                                        true); });
    tg.spawn([&context]() -> boost::asio::awaitable<void>
             { co_await relay_direction(context,
                                        context.outbound,
                                        context.inbound,
                                        context.outbound_to_inbound_stage,
                                        context.rx_bytes,
                                        false); });

    if (context.timeout.idle == 0)
    {
        const auto wait_ec = co_await tg.async_wait();
        (void)wait_ec;
    }
    else
    {
        auto wait_or_timeout = co_await (tg.async_wait() || relay_idle_watchdog(context));
        if (wait_or_timeout.index() == 1)
        {
            tg.emit(boost::asio::cancellation_type::all);
            const auto wait_ec = co_await tg.async_wait();
            (void)wait_ec;
        }
    }
    result.tx_bytes = context.tx_bytes;
    result.rx_bytes = context.rx_bytes;
    co_return result;
}

}    // namespace relay
