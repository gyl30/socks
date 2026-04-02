#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <tuple>
#include <chrono>
#include <string>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
namespace mux::net
{

#ifdef _WIN32
using socket_handle_t = std::uintptr_t;
#else
using socket_handle_t = int;
#endif

void set_socket_mark(socket_handle_t fd, uint32_t mark, boost::system::error_code& ec);

void set_socket_transparent_v4(int fd, boost::system::error_code& ec);

void set_socket_transparent_v6(int fd, boost::system::error_code& ec);

void set_socket_transparent(int fd, bool ipv6, boost::system::error_code& ec);

void set_socket_recv_origdst_v4(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst_v6(int fd, boost::system::error_code& ec);

void set_socket_recv_origdst(int fd, bool ipv6, boost::system::error_code& ec);

[[nodiscard]] boost::asio::ip::address normalize_address(const boost::asio::ip::address& addr);

[[nodiscard]] boost::asio::ip::udp::endpoint normalize_endpoint(const boost::asio::ip::udp::endpoint& ep);

struct udp_endpoint_hash
{
    std::size_t operator()(const boost::asio::ip::udp::endpoint& ep) const noexcept
    {
        const auto normalized = normalize_endpoint(ep);
        std::size_t h = 1469598103934665603ULL;
        auto mix = [&](uint8_t b)
        {
            h ^= b;
            h *= 1099511628211ULL;
        };
        if (normalized.address().is_v4())
        {
            const auto bytes = normalized.address().to_v4().to_bytes();
            for (const auto b : bytes)
            {
                mix(b);
            }
        }
        else
        {
            const auto bytes = normalized.address().to_v6().to_bytes();
            for (const auto b : bytes)
            {
                mix(b);
            }
        }
        const auto port = normalized.port();
        mix(static_cast<uint8_t>(port >> 8));
        mix(static_cast<uint8_t>(port & 0xFF));
        return h;
    }
};

struct udp_endpoint_equal
{
    bool operator()(const boost::asio::ip::udp::endpoint& lhs, const boost::asio::ip::udp::endpoint& rhs) const noexcept
    {
        return normalize_endpoint(lhs) == normalize_endpoint(rhs);
    }
};

[[nodiscard]] uint64_t fnv1a_64(std::string_view data);

[[nodiscard]] uint64_t endpoint_hash(const boost::asio::ip::udp::endpoint& endpoint);

#ifdef __linux__
[[nodiscard]] std::optional<boost::asio::ip::udp::endpoint> parse_original_dst(const msghdr& msg);
#endif

[[nodiscard]] boost::asio::ip::udp::endpoint endpoint_from_sockaddr(const sockaddr_storage& addr, std::size_t len);

[[nodiscard]] bool get_original_tcp_dst(boost::asio::ip::tcp::socket& socket,
                                        boost::asio::ip::tcp::endpoint& endpoint,
                                        boost::system::error_code& ec);

namespace detail
{

template <typename OpFactory, typename SuccessHandler, typename TimeoutHandler>
inline boost::asio::awaitable<void> await_with_timeout(uint32_t timeout_sec,
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

template <typename OpFactory>
inline boost::asio::awaitable<std::size_t> wait_size_op_with_timeout(uint32_t timeout_sec, OpFactory&& op_factory, boost::system::error_code& ec)
{
    std::size_t transfer_size = 0;
    co_await await_with_timeout(
        timeout_sec,
        std::forward<OpFactory>(op_factory),
        [&](const auto& result)
        {
            const auto& [op_ec, n] = result;
            ec = op_ec;
            transfer_size = n;
        },
        [&](const auto& wait_result)
        {
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
            transfer_size = 0;
        });
    co_return transfer_size;
}

}    // namespace detail

inline uint64_t timeout_seconds_to_milliseconds(uint32_t timeout_sec) { return static_cast<uint64_t>(timeout_sec) * 1000ULL; }

inline uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline uint32_t remaining_timeout_seconds(uint64_t start_ms, uint32_t timeout_sec, boost::system::error_code& ec)
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
    return static_cast<uint32_t>((remaining_ms + 999ULL) / 1000ULL);
}

inline uint64_t now_second()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

template <typename Rep, typename Period>
inline boost::asio::awaitable<boost::system::error_code> wait_for(boost::asio::io_context& io_context,
                                                                  const std::chrono::duration<Rep, Period>& delay)
{
    boost::asio::steady_timer timer(io_context);
    timer.expires_after(delay);
    const auto [wait_ec] = co_await timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable));
    co_return wait_ec;
}

inline boost::asio::awaitable<void> wait_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                              const boost::asio::ip::tcp::endpoint& endpoint,
                                                              uint32_t timeout_sec,
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
        [&](const auto& wait_result)
        {
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
        });
}

template <typename MultipleBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                  const MultipleBufferSequence& buffer,
                                                                  uint32_t timeout_sec,
                                                                  boost::system::error_code& ec)
{
    co_return co_await detail::wait_size_op_with_timeout(
        timeout_sec,
        [&]() { return boost::asio::async_read(socket, buffer, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        ec);
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                   const ConstBufferSequence& buffers,
                                                                   uint32_t timeout_sec,
                                                                   boost::system::error_code& ec)
{
    co_return co_await detail::wait_size_op_with_timeout(
        timeout_sec,
        [&]() { return boost::asio::async_write(socket, buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        ec);
}

template <typename MutableBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_read_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                       const MutableBufferSequence& buffers,
                                                                       uint32_t timeout_sec,
                                                                       boost::system::error_code& ec)
{
    co_return co_await detail::wait_size_op_with_timeout(
        timeout_sec,
        [&]() { return socket.async_read_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        ec);
}

template <typename ConstBufferSequence>
inline boost::asio::awaitable<std::size_t> wait_write_some_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                        const ConstBufferSequence& buffers,
                                                                        uint32_t timeout_sec,
                                                                        boost::system::error_code& ec)
{
    co_return co_await detail::wait_size_op_with_timeout(
        timeout_sec,
        [&]() { return socket.async_write_some(buffers, boost::asio::as_tuple(boost::asio::use_awaitable)); },
        ec);
}

template <typename InternetProtocol>
inline boost::asio::awaitable<typename boost::asio::ip::basic_resolver<InternetProtocol>::results_type> wait_resolve_with_timeout(
    boost::asio::ip::basic_resolver<InternetProtocol>& resolver,
    std::string host,
    std::string service,
    uint32_t timeout_sec,
    boost::system::error_code& ec)
{
    using results_type = typename boost::asio::ip::basic_resolver<InternetProtocol>::results_type;
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
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
            results = results_type{};
        });
    co_return results;
}

template <typename ValueType>
inline boost::asio::awaitable<ValueType> wait_receive_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    uint32_t timeout_sec,
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
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
            data = ValueType{};
        });
    co_return data;
}

template <typename ValueType>
inline boost::asio::awaitable<void> wait_send_with_timeout(
    boost::asio::experimental::concurrent_channel<void(boost::system::error_code, ValueType)>& chan,
    ValueType data,
    uint32_t timeout_sec,
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
        [&](const auto& wait_result)
        {
            const auto& [wait_ec] = wait_result;
            ec = wait_ec ? wait_ec : boost::system::error_code{boost::asio::error::timed_out};
        });
}

}    // namespace mux::net

#endif
