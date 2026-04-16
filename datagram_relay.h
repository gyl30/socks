#ifndef DATAGRAM_RELAY_H
#define DATAGRAM_RELAY_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "net_utils.h"
#include "proxy_protocol.h"
#include "trace_store.h"
#include "udp_proxy_outbound.h"

namespace relay
{

struct udp_socket_reply_relay_context
{
    boost::asio::ip::udp::socket& socket;
    uint64_t& last_activity_time_ms;
    uint64_t& rx_bytes;
};

template <typename AcceptReplyFn, typename WriteReplyFn, typename ErrorFn>
boost::asio::awaitable<void> relay_udp_socket_replies(udp_socket_reply_relay_context context,
                                                      AcceptReplyFn accept_reply,
                                                      WriteReplyFn write_reply,
                                                      ErrorFn on_error)
{
    std::vector<uint8_t> buffer(65535);
    boost::asio::ip::udp::endpoint sender;
    for (;;)
    {
        const auto [read_ec, bytes_read] =
            co_await context.socket.async_receive_from(boost::asio::buffer(buffer), sender, boost::asio::as_tuple(boost::asio::use_awaitable));
        if (read_ec)
        {
            on_error(read_ec);
            break;
        }

        const auto now_ms = net::now_ms();
        if (!accept_reply(sender, now_ms))
        {
            continue;
        }

        boost::system::error_code write_ec;
        const auto accounted_bytes = co_await write_reply(sender, buffer.data(), bytes_read, write_ec);
        if (write_ec)
        {
            on_error(write_ec);
            break;
        }

        context.last_activity_time_ms = net::now_ms();
        context.rx_bytes += accounted_bytes;
        trace_store::instance().add_live_rx_bytes(accounted_bytes);
    }
}

struct proxy_outbound_reply_relay_context
{
    uint32_t read_timeout_sec = 0;
    uint64_t& last_activity_time_ms;
    uint64_t& rx_bytes;
};

template <typename ShouldStopFn, typename WriteReplyFn, typename ErrorFn>
boost::asio::awaitable<void> relay_proxy_outbound_replies(const std::shared_ptr<udp_proxy_outbound>& outbound,
                                                          proxy_outbound_reply_relay_context context,
                                                          ShouldStopFn should_stop,
                                                          WriteReplyFn write_reply,
                                                          ErrorFn on_error)
{
    if (outbound == nullptr)
    {
        co_return;
    }

    for (;;)
    {
        if (should_stop())
        {
            break;
        }

        boost::system::error_code read_ec;
        const auto datagram = co_await outbound->receive_datagram(context.read_timeout_sec, read_ec);
        if (read_ec)
        {
            if (read_ec == boost::asio::error::timed_out)
            {
                continue;
            }
            on_error(read_ec);
            break;
        }

        boost::system::error_code write_ec;
        const auto accounted_bytes = co_await write_reply(datagram, write_ec);
        if (write_ec)
        {
            on_error(write_ec);
            break;
        }

        context.last_activity_time_ms = net::now_ms();
        context.rx_bytes += accounted_bytes;
        trace_store::instance().add_live_rx_bytes(accounted_bytes);
    }
}

struct datagram_idle_watchdog_context
{
    boost::asio::steady_timer& timer;
    uint32_t idle_timeout_sec = 0;
    uint64_t& last_activity_time_ms;
};

boost::asio::awaitable<void> run_datagram_idle_watchdog(datagram_idle_watchdog_context context, std::function<void()> on_timeout);

}    // namespace relay

#endif
