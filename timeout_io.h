#ifndef TIMEOUT_IO_H
#define TIMEOUT_IO_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <tuple>
#include <string_view>

#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "mux_protocol.h"

namespace mux::timeout_io
{

inline std::uint64_t timeout_seconds_to_milliseconds(const std::uint32_t timeout_sec) { return static_cast<std::uint64_t>(timeout_sec) * 1000ULL; }
inline std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}
inline boost::asio::awaitable<void> wait_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                              const boost::asio::ip::tcp::endpoint& endpoint,
                                                              const std::uint32_t timeout_sec,
                                                              boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        co_await socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto connect_or_timeout = co_await (socket.async_connect(endpoint, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                        timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (connect_or_timeout.index() == 0)
    {
        const auto& [op_ec] = std::get<0>(connect_or_timeout);
        ec = op_ec;
    }
    else
    {
        const auto& [wait_ec] = std::get<1>(connect_or_timeout);
        ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    }

    co_return;
}

template <typename MultipleBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                  const MultipleBufferSequence& buffer,
                                                                  const std::uint32_t timeout_sec,
                                                                  boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        auto [read_ec, read_size] = co_await boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = read_ec;
        co_return read_size;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));
    using boost::asio::experimental::awaitable_operators::operator||;
    auto read_or_timeout = co_await (boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                     timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (read_or_timeout.index() == 0)
    {
        const auto& [read_ec, read_size] = std::get<0>(read_or_timeout);
        ec = read_ec;
        co_return read_size;
    }

    const auto& [timeout_ec] = std::get<1>(read_or_timeout);
    if (timeout_ec)
    {
        ec = timeout_ec;
    }
    else
    {
        ec = boost::asio::error::timed_out;
    }

    co_return 0;
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                   const ConstBufferSequence& buffers,
                                                                   const std::uint32_t timeout_sec,
                                                                   boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        std::size_t n = co_await boost::asio::async_write(socket, buffers, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return n;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto write_or_timeout = co_await (boost::asio::async_write(socket, buffers, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                      timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (write_or_timeout.index() == 0)
    {
        const auto& [op_ec, bytes_transferred] = std::get<0>(write_or_timeout);
        ec = op_ec;
        co_return bytes_transferred;
    }

    const auto& [wait_ec] = std::get<1>(write_or_timeout);
    ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    co_return 0;
}

template <typename MutableBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                       const MutableBufferSequence& buffers,
                                                                       const std::uint32_t timeout_sec,
                                                                       boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        std::size_t n = co_await socket.async_read_some(buffers, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return n;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto read_or_timeout = co_await (socket.async_read_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                     timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (read_or_timeout.index() == 0)
    {
        const auto& [op_ec, bytes_transferred] = std::get<0>(read_or_timeout);
        ec = op_ec;
        co_return bytes_transferred;
    }

    const auto& [wait_ec] = std::get<1>(read_or_timeout);
    ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    co_return 0;
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                        const ConstBufferSequence& buffers,
                                                                        const std::uint32_t timeout_sec,
                                                                        boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        std::size_t n = co_await socket.async_write_some(buffers, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return n;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto write_or_timeout = co_await (socket.async_write_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                      timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (write_or_timeout.index() == 0)
    {
        const auto& [op_ec, bytes_transferred] = std::get<0>(write_or_timeout);
        ec = op_ec;
        co_return bytes_transferred;
    }

    const auto& [wait_ec] = std::get<1>(write_or_timeout);
    ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    co_return 0;
}

template <typename InternetProtocol>
inline boost::asio::awaitable<typename boost::asio::ip::basic_resolver<InternetProtocol>::results_type> wait_resolve_with_timeout(
    boost::asio::ip::basic_resolver<InternetProtocol>& resolver,
    const std::string_view host,
    const std::string_view service,
    const std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    using results_type = typename boost::asio::ip::basic_resolver<InternetProtocol>::results_type;

    if (timeout_sec == 0)
    {
        results_type results = co_await resolver.async_resolve(host, service, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        co_return results;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto resolve_or_timeout = co_await (resolver.async_resolve(host, service, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                        timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (resolve_or_timeout.index() == 0)
    {
        auto& [op_ec, results] = std::get<0>(resolve_or_timeout);
        ec = op_ec;
        co_return std::move(results);
    }

    const auto& [wait_ec] = std::get<1>(resolve_or_timeout);
    ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    co_return results_type{};
}

////////////////////////////////////////////////////////////////////////////////////////////////////

template <typename ValueType>
inline boost::asio::awaitable<ValueType> wait_receive_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        auto [op_ec, data] = co_await chan.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = op_ec;
        co_return std::move(data);
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto receive_or_timeout = co_await (chan.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                                        timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (receive_or_timeout.index() == 0)
    {
        auto& [op_ec, data] = std::get<0>(receive_or_timeout);
        ec = op_ec;
        co_return std::move(data);
    }

    const auto& [wait_ec] = std::get<1>(receive_or_timeout);
    ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    co_return ValueType{};
}

template <typename ValueType>
inline boost::asio::awaitable<void> wait_send_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    ValueType data,
    std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    if (timeout_sec == 0)
    {
        auto [op_ec] = co_await chan.async_send(boost::system::error_code{}, std::move(data), boost::asio::as_tuple(boost::asio::use_awaitable));
        ec = op_ec;
        co_return;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto send_or_timeout =
        co_await (chan.async_send(boost::system::error_code{}, std::move(data), boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                  timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));

    if (send_or_timeout.index() == 0)
    {
        const auto& [op_ec] = std::get<0>(send_or_timeout);
        ec = op_ec;
    }
    else
    {
        const auto& [wait_ec] = std::get<1>(send_or_timeout);
        ec = wait_ec ? wait_ec : boost::system::error_code(boost::asio::error::timed_out);
    }
    co_return;
}

}    // namespace mux::timeout_io

#endif
