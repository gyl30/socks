#include <charconv>
#include <chrono>
#include <cstdint>
#include <future>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "config.h"
#include "log.h"
#include "proxy_reality_connection.h"
#include "scoped_exit.h"

namespace
{

void print_usage(const char* prog)
{
    std::cerr << "Usage: " << prog << " <config> <outbound_tag> <payload_hex>\n";
}

std::optional<std::vector<uint8_t>> parse_hex_bytes(const std::string_view text)
{
    if ((text.size() % 2U) != 0U)
    {
        return std::nullopt;
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(text.size() / 2U);
    for (std::size_t index = 0; index < text.size(); index += 2U)
    {
        uint8_t value = 0;
        const auto* begin = text.data() + index;
        const auto* end = begin + 2;
        const auto [ptr, ec] = std::from_chars(begin, end, value, 16);
        if (ec != std::errc{} || ptr != end)
        {
            return std::nullopt;
        }
        bytes.push_back(value);
    }
    return bytes;
}

boost::asio::awaitable<int> run_case(const relay::config& cfg, const std::string outbound_tag, const std::vector<uint8_t> payload)
{
    boost::system::error_code ec;
    const auto executor = co_await boost::asio::this_coro::executor;
    auto connection = co_await relay::proxy_reality_connection::connect(executor, cfg, outbound_tag, 0, 1, 0, ec);
    if (connection == nullptr)
    {
        std::cerr << "connect failed: " << ec.message() << '\n';
        co_return 1;
    }

    co_await connection->write_packet(payload, ec);
    if (ec)
    {
        std::cerr << "write_packet failed: " << ec.message() << '\n';
        co_return 1;
    }

    boost::asio::steady_timer timer(executor);
    timer.expires_after(std::chrono::milliseconds(200));
    co_await timer.async_wait(boost::asio::use_awaitable);

    connection->close(ec);
    co_return 0;
}

}    // namespace

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        print_usage(argv[0]);
        return 1;
    }

    const auto parsed = relay::parse_config(argv[1]);
    if (!parsed.has_value())
    {
        return 1;
    }

    const auto payload = parse_hex_bytes(argv[3]);
    if (!payload.has_value())
    {
        std::cerr << "invalid payload hex\n";
        return 1;
    }

    init_log(parsed->log.file);
    set_level(parsed->log.level);
    DEFER(shutdown_log());

    boost::asio::io_context io_context;
    std::optional<int> exit_code;
    bool coroutine_failed = false;
    boost::asio::co_spawn(
        io_context,
        run_case(*parsed, argv[2], *payload),
        [&](std::exception_ptr ex, int result)
        {
            coroutine_failed = (ex != nullptr);
            exit_code = result;
        });
    io_context.run();
    if (coroutine_failed || !exit_code.has_value())
    {
        std::cerr << "coroutine failed\n";
        return 1;
    }
    return *exit_code;
}
