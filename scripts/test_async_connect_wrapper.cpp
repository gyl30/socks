#include <chrono>
#include <string>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <boost/asio.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace
{

boost::asio::awaitable<boost::system::error_code> async_connect_with_timeout(boost::asio::ip::tcp::socket& socket,
                                                                             const boost::asio::ip::tcp::endpoint& endpoint,
                                                                             uint32_t timeout_sec)
{
    boost::asio::steady_timer timer(socket.get_executor());
    timer.expires_after(std::chrono::seconds(timeout_sec));

    using boost::asio::experimental::awaitable_operators::operator||;
    auto result = co_await (socket.async_connect(endpoint, boost::asio::as_tuple(boost::asio::use_awaitable)) ||
                            timer.async_wait(boost::asio::as_tuple(boost::asio::use_awaitable)));
    if (result.index() == 0)
    {
        const auto& [ec] = std::get<0>(result);
        co_return ec;
    }

    boost::system::error_code cancel_ec;
    socket.cancel(cancel_ec);
    (void)cancel_ec;
    co_return boost::asio::error::timed_out;
}

std::optional<int> get_socket_error(const int fd)
{
    int value = 0;
    socklen_t len = sizeof(value);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &len) != 0)
    {
        return std::nullopt;
    }
    return value;
}

boost::asio::awaitable<void> run_probe(const std::string host, const uint16_t port, const uint32_t timeout_sec)
{
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::ip::tcp::socket socket(executor);

    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(host, ec);
    if (ec)
    {
        std::cout << "parse_ec=" << ec.value() << " msg=" << ec.message() << '\n';
        co_return;
    }

    const boost::asio::ip::tcp::endpoint endpoint(address, port);
    socket.open(endpoint.protocol(), ec);
    if (ec)
    {
        std::cout << "open_ec=" << ec.value() << " msg=" << ec.message() << '\n';
        co_return;
    }

    ec = co_await async_connect_with_timeout(socket, endpoint, timeout_sec);
    std::cout << "connect_ec=" << ec.value() << " msg=" << ec.message();

    boost::system::error_code local_ep_ec;
    const auto local_ep = socket.local_endpoint(local_ep_ec);
    if (local_ep_ec)
    {
        std::cout << " local=unavailable(" << local_ep_ec.message() << ')';
    }
    else
    {
        std::cout << " local=" << local_ep.address().to_string() << ':' << local_ep.port();
    }

    const auto so_error = get_socket_error(socket.native_handle());
    if (so_error.has_value())
    {
        std::cout << " so_error=" << *so_error;
        if (*so_error != 0)
        {
            std::cout << '(' << std::strerror(*so_error) << ')';
        }
    }
    else
    {
        std::cout << " so_error=unavailable";
    }

    std::cout << " open=" << socket.is_open() << '\n';

    boost::system::error_code close_ec;
    socket.close(close_ec);
}

}    // namespace

int main(int argc, char* argv[])
{
    if (argc < 3 || argc > 4)
    {
        std::cerr << "usage: " << argv[0] << " <host> <port> [timeout]\n";
        return 1;
    }

    const std::string host = argv[1];
    const auto port = static_cast<uint16_t>(std::strtoul(argv[2], nullptr, 10));
    const auto timeout_sec = argc == 4 ? static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 10)) : 5U;

    boost::asio::io_context io_context;
    boost::asio::co_spawn(io_context, run_probe(host, port, timeout_sec), boost::asio::detached);
    io_context.run();
    return 0;
}
