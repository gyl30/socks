#include "stream_relay.h"

#include <algorithm>
#include <chrono>
#include <mutex>
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

struct relay_result_state
{
    stream_relay_result& result;
    std::mutex mutex;

    explicit relay_result_state(stream_relay_result& result_ref) : result(result_ref) {}

    void record(const stream_relay_result::close_reason reason, const boost::system::error_code& ec = {})
    {
        std::scoped_lock lock(mutex);
        if (result.reason != stream_relay_result::close_reason::kUnknown)
        {
            return;
        }
        result.reason = reason;
        if (ec)
        {
            result.ec = ec;
        }
    }
};

[[nodiscard]] stream_relay_result::close_reason eof_reason(const bool source_is_inbound)
{
    return source_is_inbound ? stream_relay_result::close_reason::kInboundEof : stream_relay_result::close_reason::kOutboundEof;
}

[[nodiscard]] stream_relay_result::close_reason write_error_reason(const bool destination_is_inbound)
{
    return destination_is_inbound ? stream_relay_result::close_reason::kInboundError : stream_relay_result::close_reason::kOutboundError;
}

[[nodiscard]] stream_relay_result::close_reason io_error_reason(const bool source_is_inbound, const boost::system::error_code& ec)
{
    if (net::is_basic_close_error(ec))
    {
        return stream_relay_result::close_reason::kStopped;
    }
    return source_is_inbound ? stream_relay_result::close_reason::kInboundError : stream_relay_result::close_reason::kOutboundError;
}

boost::asio::awaitable<void> apply_close_action(stream_relay_transport& transport, const stream_relay_result::close_action action)
{
    boost::system::error_code ec;
    switch (action)
    {
        case stream_relay_result::close_action::kNone:
            co_return;
        case stream_relay_result::close_action::kShutdownSend:
            co_await transport.shutdown_send(ec);
            co_return;
        case stream_relay_result::close_action::kClose:
        case stream_relay_result::close_action::kAbort:
            co_await transport.close();
            co_return;
    }
}

boost::asio::awaitable<void> apply_close_policy(stream_relay_context& context, const stream_relay_result::close_reason reason)
{
    const auto policy = default_close_policy(reason);
    co_await apply_close_action(context.inbound, policy.inbound_action);
    co_await apply_close_action(context.outbound, policy.outbound_action);
}

boost::asio::awaitable<void> relay_direction(stream_relay_context& context,
                                             stream_relay_transport& source,
                                             stream_relay_transport& destination,
                                             std::string_view stage_name,
                                             uint64_t& bytes_counter,
                                             const bool is_tx_direction,
                                             relay_result_state& result_state)
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
                const auto reason = eof_reason(is_tx_direction);
                result_state.record(reason);
                const auto policy = default_close_policy(reason);
                co_await apply_close_action(destination, is_tx_direction ? policy.outbound_action : policy.inbound_action);
            }
            else
            {
                const auto reason = io_error_reason(is_tx_direction, ec);
                result_state.record(reason, ec);
                LOG_WARN("{} trace {:016x} conn {} stage relay {} read failed {}",
                         context.log_event_name,
                         context.trace_id,
                         context.conn_id,
                         stage_name,
                         ec.message());
                co_await apply_close_policy(context, reason);
            }
            break;
        }

        const auto bytes_written = co_await destination.write(std::span<const uint8_t>(buffer.data(), bytes_read), ec);
        if (ec)
        {
            const auto reason = write_error_reason(!is_tx_direction);
            result_state.record(reason, ec);
            LOG_WARN("{} trace {:016x} conn {} stage relay {} write failed {}",
                     context.log_event_name,
                     context.trace_id,
                     context.conn_id,
                     stage_name,
                     ec.message());
            co_await apply_close_policy(context, reason);
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
        co_await apply_close_policy(context, stream_relay_result::close_reason::kIdleTimeout);
        break;
    }
}

}    // namespace

boost::asio::awaitable<stream_relay_result> relay_streams(stream_relay_context& context)
{
    stream_relay_result result;
    relay_result_state result_state(result);
    using boost::asio::experimental::awaitable_operators::operator||;
    auto executor = co_await boost::asio::this_coro::executor;
    auto& io_context = static_cast<boost::asio::io_context&>(executor.context());
    task_group tg(io_context);

    tg.spawn([&context, &result_state]() -> boost::asio::awaitable<void>
             { co_await relay_direction(context,
                                        context.inbound,
                                        context.outbound,
                                        context.inbound_to_outbound_stage,
                                        context.tx_bytes,
                                        true,
                                        result_state); });
    tg.spawn([&context, &result_state]() -> boost::asio::awaitable<void>
             { co_await relay_direction(context,
                                        context.outbound,
                                        context.inbound,
                                        context.outbound_to_inbound_stage,
                                        context.rx_bytes,
                                        false,
                                        result_state); });

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
            result_state.record(stream_relay_result::close_reason::kIdleTimeout, boost::asio::error::timed_out);
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
