#ifndef TRANSPARENT_UDP_SESSION_FLOW_H
#define TRANSPARENT_UDP_SESSION_FLOW_H

#include <cstdint>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace relay
{

template <typename ForwardFn, typename ReplyFn, typename IdleFn>
boost::asio::awaitable<void> run_transparent_udp_relay_tasks(const uint32_t idle_timeout_sec,
                                                             ForwardFn forward,
                                                             ReplyFn reply,
                                                             IdleFn idle)
{
    using boost::asio::experimental::awaitable_operators::operator||;

    if (idle_timeout_sec == 0)
    {
        co_await (forward() || reply());
        co_return;
    }

    co_await (forward() || reply() || idle());
}

template <typename OpenFn, typename ForwardFn, typename ReplyFn, typename IdleFn, typename CloseFn>
boost::asio::awaitable<bool> run_transparent_udp_mode(const uint32_t idle_timeout_sec,
                                                      OpenFn open_mode,
                                                      ForwardFn forward,
                                                      ReplyFn reply,
                                                      IdleFn idle,
                                                      CloseFn close_mode)
{
    if (!(co_await open_mode()))
    {
        co_return false;
    }

    co_await run_transparent_udp_relay_tasks(idle_timeout_sec, forward, reply, idle);
    co_await close_mode();
    co_return true;
}

}    // namespace relay

#endif
