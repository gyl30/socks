#include <future>
#include <thread>
#include <vector>
#include <chrono>
#include <iostream>
#include <optional>
#include <cstdint>

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>

#include "net_utils.h"

namespace
{

using namespace std::chrono_literals;

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

boost::asio::ip::tcp::resolver::results_type make_results(const std::vector<boost::asio::ip::tcp::endpoint>& endpoints)
{
    return boost::asio::ip::tcp::resolver::results_type::create(endpoints.begin(), endpoints.end(), "127.0.0.1", "0");
}

void prepare_socket(boost::asio::ip::tcp::socket& socket,
                    const boost::asio::ip::tcp::endpoint& endpoint,
                    boost::system::error_code& ec,
                    int& prepare_count)
{
    ++prepare_count;
    if (socket.is_open())
    {
        boost::system::error_code close_ec;
        close_ec = socket.close(close_ec);
    }
    ec = socket.open(endpoint.protocol(), ec);
}

bool test_connect_uses_second_endpoint()
{
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor acceptor(
        io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    const auto listener_endpoint = acceptor.local_endpoint();
    const auto refused_endpoint =
        boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), static_cast<uint16_t>(listener_endpoint.port() + 1));
    const auto endpoints = make_results({refused_endpoint, listener_endpoint});

    std::promise<boost::system::error_code> accept_promise;
    auto accept_result = accept_promise.get_future();
    std::thread accept_thread([&acceptor, &accept_promise, &io_context]()
                              {
                                  boost::asio::ip::tcp::socket peer(io_context);
                                  boost::system::error_code ec;
                                  acceptor.accept(peer, ec);
                                  accept_promise.set_value(ec);
                              });

    auto future = boost::asio::co_spawn(
        io_context,
        [&]() -> boost::asio::awaitable<bool>
        {
            boost::asio::ip::tcp::socket socket(io_context);
            boost::system::error_code ec;
            int prepare_count = 0;
            const auto connected = co_await relay::net::connect_resolved_endpoints_with_timeout(
                socket,
                endpoints,
                relay::net::now_ms(),
                2,
                ec,
                [&](const boost::asio::ip::tcp::endpoint& endpoint, boost::system::error_code& prepare_ec)
                { prepare_socket(socket, endpoint, prepare_ec, prepare_count); });
            socket.close(ec);
            co_return require(!ec, "second_endpoint socket close failed") &&
                   require(connected != endpoints.end(), "second_endpoint expected a successful connection") &&
                   require(connected->endpoint() == listener_endpoint, "second_endpoint expected listener endpoint") &&
                   require(prepare_count == 2, "second_endpoint expected both endpoints to be attempted");
        },
        boost::asio::use_future);

    io_context.run();
    const auto ok = future.get() &&
                    require(accept_result.wait_for(1s) == std::future_status::ready, "second_endpoint accept did not finish") &&
                    require(!accept_result.get(), "second_endpoint accept returned an error");
    acceptor.close();
    if (accept_thread.joinable())
    {
        accept_thread.join();
    }
    return ok;
}

bool test_expired_deadline_skips_connect_attempts()
{
    boost::asio::io_context io_context;
    const auto endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 9);
    const auto endpoints = make_results({endpoint, endpoint});

    auto future = boost::asio::co_spawn(
        io_context,
        [&]() -> boost::asio::awaitable<bool>
        {
            boost::asio::ip::tcp::socket socket(io_context);
            boost::system::error_code ec;
            int prepare_count = 0;
            const auto start_ms = relay::net::now_ms();
            std::this_thread::sleep_for(1100ms);
            const auto connected = co_await relay::net::connect_resolved_endpoints_with_timeout(
                socket,
                endpoints,
                start_ms,
                1,
                ec,
                [&](const boost::asio::ip::tcp::endpoint& target, boost::system::error_code& prepare_ec)
                { prepare_socket(socket, target, prepare_ec, prepare_count); });
            co_return require(connected == endpoints.end(), "expired_deadline expected no connected endpoint") &&
                   require(ec == boost::asio::error::timed_out, "expired_deadline expected timed_out") &&
                   require(prepare_count == 0, "expired_deadline expected no connect attempts after deadline");
        },
        boost::asio::use_future);

    io_context.run();
    return future.get();
}

}    // namespace

int main()
{
    const bool ok = test_connect_uses_second_endpoint() && test_expired_deadline_skips_connect_attempts();
    return ok ? 0 : 1;
}
