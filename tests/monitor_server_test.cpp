#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <asio.hpp>
#include <gtest/gtest.h>

#include "monitor_server.h"
#include "statistics.h"

namespace
{

std::uint16_t pick_free_port()
{
    asio::io_context ioc;
    asio::ip::tcp::acceptor acceptor(ioc, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    return acceptor.local_endpoint().port();
}

std::string read_response(std::uint16_t port, const std::string& request)
{
    asio::io_context ioc;
    asio::ip::tcp::socket socket(ioc);
    asio::error_code ec;
    socket.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
    if (ec)
    {
        return {};
    }

    asio::write(socket, asio::buffer(request), ec);
    if (ec)
    {
        return {};
    }

    std::string out;
    std::array<char, 1024> buffer{};
    for (;;)
    {
        const auto n = socket.read_some(asio::buffer(buffer), ec);
        if (n > 0)
        {
            out.append(buffer.data(), n);
        }
        if (ec == asio::error::eof)
        {
            break;
        }
        if (ec)
        {
            return out;
        }
    }
    return out;
}

std::string request_with_retry(std::uint16_t port, const std::string& request)
{
    for (int i = 0; i < 30; ++i)
    {
        const auto resp = read_response(port, request);
        if (!resp.empty())
        {
            return resp;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return read_response(port, request);
}

class monitor_server_env
{
   public:
    template <typename... Args>
    explicit monitor_server_env(Args&&... args) : server_(std::make_shared<mux::monitor_server>(ioc_, std::forward<Args>(args)...))
    {
        server_->start();
        thread_ = std::thread([this]() { ioc_.run(); });
    }

    ~monitor_server_env()
    {
        ioc_.stop();
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

   private:
    asio::io_context ioc_;
    std::shared_ptr<mux::monitor_server> server_;
    std::thread thread_;
};

}    // namespace

namespace mux
{

TEST(MonitorServerTest, EmptyTokenReturnsMetrics)
{
    statistics::instance().inc_total_connections();

    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());

    const auto resp = request_with_retry(port, "metrics\n");
    EXPECT_NE(resp.find("socks_uptime_seconds "), std::string::npos);
    EXPECT_NE(resp.find("socks_total_connections "), std::string::npos);
    EXPECT_NE(resp.find("socks_auth_failures_total "), std::string::npos);
}

TEST(MonitorServerTest, TokenRequiredAndRateLimit)
{
    const auto port = pick_free_port();
    monitor_server_env env(port, std::string("secret"), 500);

    const auto unauth = read_response(port, "no token\n");
    EXPECT_TRUE(unauth.empty());

    const auto authed = request_with_retry(port, "token=secret\n");
    EXPECT_NE(authed.find("socks_total_connections "), std::string::npos);

    const auto limited = read_response(port, "token=secret\n");
    EXPECT_TRUE(limited.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(550));
    const auto after_window = read_response(port, "token=secret\n");
    EXPECT_NE(after_window.find("socks_uptime_seconds "), std::string::npos);
}

TEST(MonitorServerTest, EscapesPrometheusLabels)
{
    auto& stats = statistics::instance();
    stats.inc_handshake_failure_by_sni(statistics::handshake_failure_reason::kShortId, "line1\"x\\y\nline2");

    const auto port = pick_free_port();
    monitor_server_env env(port, std::string());
    const auto resp = request_with_retry(port, "metrics\n");

    EXPECT_NE(resp.find("reason=\"short_id\""), std::string::npos);
    EXPECT_NE(resp.find("sni=\"line1\\\"x\\\\y\\nline2\""), std::string::npos);
}

}    // namespace mux
