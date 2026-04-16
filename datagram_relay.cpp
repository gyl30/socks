#include <chrono>
#include <functional>
#include <cstdint>

#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "datagram_relay.h"
#include "net_utils.h"

namespace relay
{

boost::asio::awaitable<void> run_datagram_idle_watchdog(datagram_idle_watchdog_context context, std::function<void()> on_timeout)
{
    if (context.idle_timeout_sec == 0)
    {
        co_return;
    }

    const auto idle_timeout_ms = static_cast<uint64_t>(context.idle_timeout_sec) * 1000ULL;
    for (;;)
    {
        context.timer.expires_after(std::chrono::seconds(1));
        const auto [wait_ec] = co_await context.timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
        if (wait_ec)
        {
            break;
        }

        if (net::now_ms() - context.last_activity_time_ms > idle_timeout_ms)
        {
            on_timeout();
            break;
        }
    }
}

}    // namespace relay
