#ifndef TIMEOUT_IO_H
#define TIMEOUT_IO_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/detail/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace mux::timeout_io
{

namespace detail
{

inline boost::system::error_code timeout_error(const boost::system::error_code& wait_ec)
{
    if (wait_ec)
    {
        return wait_ec;
    }
    return {boost::asio::error::timed_out};
}

template <typename WaitResult>
inline void assign_timeout_error(const WaitResult& wait_result, boost::system::error_code& ec)
{
    const auto& [wait_ec] = wait_result;
    ec = timeout_error(wait_ec);
}

template <typename OpFactory, typename SuccessHandler, typename TimeoutHandler>
inline boost::asio::awaitable<void> await_with_timeout(const std::uint32_t timeout_sec,
                                                       OpFactory&& op_factory,
                                                       SuccessHandler&& on_success,
                                                       TimeoutHandler&& on_timeout)
{
    if (timeout_sec == 0)
    {
        auto op_result = co_await op_factory();
        on_success(op_result);
        co_return;
    }

    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;

    auto op_or_timeout = co_await (op_factory() || timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));
    if (op_or_timeout.index() == 0)
    {
        auto op_result = std::move(std::get<0>(op_or_timeout));
        on_success(op_result);
        co_return;
    }

    on_timeout(std::get<1>(op_or_timeout));
}

}    // namespace detail

inline std::uint64_t timeout_seconds_to_milliseconds(const std::uint32_t timeout_sec) { return static_cast<std::uint64_t>(timeout_sec) * 1000ULL; }
inline std::uint64_t now_ms()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}
inline std::uint32_t remaining_timeout_seconds(const std::uint64_t start_ms, const std::uint32_t timeout_sec, boost::system::error_code& ec)
{
    ec.clear();
    if (timeout_sec == 0)
    {
        return 0;
    }

    const auto timeout_ms = timeout_seconds_to_milliseconds(timeout_sec);
    const auto elapsed_ms = now_ms() - start_ms;
    if (elapsed_ms >= timeout_ms)
    {
        ec = boost::asio::error::timed_out;
        return 0;
    }

    const auto remaining_ms = timeout_ms - elapsed_ms;
    return static_cast<std::uint32_t>((remaining_ms + 999ULL) / 1000ULL);
}
inline std::uint64_t now_second()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline boost::asio::awaitable<void> wait_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                              const boost::asio::ip::tcp::endpoint& endpoint,
                                                              const std::uint32_t timeout_sec,
                                                              boost::system::error_code& ec)
{
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return socket.async_connect(endpoint, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec] = result;
            ec = op_ec;
        },
        [&](const auto& wait_result) { detail::assign_timeout_error(wait_result, ec); });
}

template <typename MultipleBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                  const MultipleBufferSequence& buffer,
                                                                  const std::uint32_t timeout_sec,
                                                                  boost::system::error_code& ec)
{
    std::size_t read_size = 0;
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [read_ec, n] = result;
            ec = read_ec;
            read_size = n;
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            read_size = 0;
        });
    co_return read_size;
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                   const ConstBufferSequence& buffers,
                                                                   const std::uint32_t timeout_sec,
                                                                   boost::system::error_code& ec)
{
    std::size_t write_size = 0;
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return boost::asio::async_write(socket, buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec, n] = result;
            ec = op_ec;
            write_size = n;
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            write_size = 0;
        });
    co_return write_size;
}

template <typename MutableBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                       const MutableBufferSequence& buffers,
                                                                       const std::uint32_t timeout_sec,
                                                                       boost::system::error_code& ec)
{
    std::size_t read_size = 0;
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return socket.async_read_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec, n] = result;
            ec = op_ec;
            read_size = n;
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            read_size = 0;
        });
    co_return read_size;
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                        const ConstBufferSequence& buffers,
                                                                        const std::uint32_t timeout_sec,
                                                                        boost::system::error_code& ec)
{
    std::size_t write_size = 0;
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return socket.async_write_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec, n] = result;
            ec = op_ec;
            write_size = n;
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            write_size = 0;
        });
    co_return write_size;
}

template <typename InternetProtocol>
inline boost::asio::awaitable<typename boost::asio::ip::basic_resolver<InternetProtocol>::results_type> wait_resolve_with_timeout(
    boost::asio::ip::basic_resolver<InternetProtocol>& resolver,
    std::string host,
    std::string service,
    const std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    using results_type = boost::asio::ip::basic_resolver<InternetProtocol>::results_type;
    results_type results;
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return resolver.async_resolve(host, service, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](auto& result)
        {
            auto& [op_ec, resolved] = result;
            ec = op_ec;
            results = std::move(resolved);
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            results = results_type{};
        });
    co_return results;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

template <typename ValueType>
inline boost::asio::awaitable<ValueType> wait_receive_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    ValueType data{};
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return chan.async_receive(boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](auto& result)
        {
            auto& [op_ec, received] = result;
            ec = op_ec;
            data = std::move(received);
        },
        [&](const auto& wait_result)
        {
            detail::assign_timeout_error(wait_result, ec);
            data = ValueType{};
        });
    co_return data;
}

template <typename ValueType>
inline boost::asio::awaitable<void> wait_send_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    ValueType data,
    std::uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    co_await detail::await_with_timeout(
        timeout_sec,
        [&]() { return chan.async_send(boost::system::error_code{}, std::move(data), boost::asio::as_tuple(boost::asio::use_awaitable)); },
        [&](const auto& result)
        {
            const auto& [op_ec] = result;
            ec = op_ec;
        },
        [&](const auto& wait_result) { detail::assign_timeout_error(wait_result, ec); });
}

}    // namespace mux::timeout_io

#endif
