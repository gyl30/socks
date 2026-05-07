#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <cstdint>

#include <boost/asio.hpp>

#include "config.h"
#include "net_utils.h"
#include "protocol.h"
#include "proxy_protocol.h"
#include "proxy_reality_connection.h"
#include "request_context.h"
#include "router.h"
#include "session_result.h"
#include "stream_relay_transport.h"
#include "tcp_outbound_stream.h"

#define private public
#include "reality_tcp_session.h"
#undef private

namespace
{

bool require(const bool condition, const std::string& message)
{
    if (condition)
    {
        return true;
    }
    std::cerr << message << '\n';
    return false;
}

class fake_tcp_outbound final : public relay::tcp_outbound_stream
{
   public:
    boost::asio::awaitable<relay::tcp_outbound_connect_result> connect(const std::string& host,
                                                                       const uint16_t port,
                                                                       const uint32_t timeout_sec) override
    {
        target_host = host;
        target_port = port;
        seen_timeout_sec = timeout_sec;
        relay::tcp_outbound_connect_result result;
        result.socks_rep = socks::kRepSuccess;
        co_return result;
    }

    boost::asio::awaitable<std::size_t> read(std::span<uint8_t>, boost::system::error_code& ec) override
    {
        ec = boost::asio::error::operation_not_supported;
        co_return 0;
    }

    boost::asio::awaitable<std::size_t> write(std::span<const uint8_t>, boost::system::error_code& ec) override
    {
        ec = boost::asio::error::operation_not_supported;
        co_return 0;
    }

    boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec) override
    {
        ec.clear();
        co_return;
    }

    boost::asio::awaitable<void> close() override
    {
        co_return;
    }

    std::string target_host = "unknown";
    uint16_t target_port = 0;
    uint32_t seen_timeout_sec = 0;
};

boost::asio::awaitable<bool> run_reality_tcp_budget_regression()
{
    boost::asio::io_context io_context;
    relay::config cfg;
    cfg.timeout.connect = 5;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;

    auto backend = std::make_shared<fake_tcp_outbound>();
    auto session = std::make_shared<relay::reality_tcp_session>(
        io_context, nullptr, nullptr, 1, 0x7200000000000001ULL, "reality-in", cfg, false);

    session->target_host_ = "127.0.0.1";
    session->target_port_ = 443;
    session->route_name_ = "direct";
    session->request_timeout_sec_ = 2;
    session->request_start_ms_ = relay::net::now_ms() - 1500ULL;

    const auto result = co_await session->connect_backend(backend, "127.0.0.1", 443, relay::route_type::kDirect, "direct");
    const bool ok = require(!result.ec, "connect_backend should reach fake backend") &&
                    require(backend->target_host == "127.0.0.1" && backend->target_port == 443, "fake backend target mismatch") &&
                    require(backend->seen_timeout_sec == 1, "expected remaining timeout to be rounded up to 1 second");
    co_return ok;
}

}    // namespace

int main()
{
    boost::asio::io_context io_context;
    auto future = boost::asio::co_spawn(io_context, run_reality_tcp_budget_regression(), boost::asio::use_future);
    io_context.run();
    return future.get() ? 0 : 1;
}
