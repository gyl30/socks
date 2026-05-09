#include <array>
#include <span>
#include <thread>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <utility>
#include <iostream>
#include <stdexcept>

#include <boost/asio.hpp>

#include "config.h"
#include "outbound.h"
#include "protocol.h"

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

std::vector<uint8_t> read_exact(boost::asio::ip::tcp::socket& socket, const std::size_t size)
{
    std::vector<uint8_t> data(size);
    boost::asio::read(socket, boost::asio::buffer(data));
    return data;
}

void consume_socks_request_tail(boost::asio::ip::tcp::socket& socket, const uint8_t atyp)
{
    if (atyp == socks::kAtypIpv4)
    {
        (void)read_exact(socket, 6);
        return;
    }
    if (atyp == socks::kAtypIpv6)
    {
        (void)read_exact(socket, 18);
        return;
    }
    if (atyp == socks::kAtypDomain)
    {
        const auto length = read_exact(socket, 1);
        (void)read_exact(socket, static_cast<std::size_t>(length[0]) + 2U);
        return;
    }
    throw std::runtime_error("unexpected request atyp");
}

struct fake_socks_reply_scenario
{
    uint8_t expected_cmd = 0;
    std::vector<uint8_t> reply;
};

class fake_socks_server
{
   public:
    explicit fake_socks_server(fake_socks_reply_scenario scenario)
        : acceptor_(io_context_, boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0)),
          scenario_(std::move(scenario)),
          thread_([this] { serve(); })
    {
    }

    ~fake_socks_server()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    [[nodiscard]] uint16_t port() const
    {
        return acceptor_.local_endpoint().port();
    }

    [[nodiscard]] bool join_ok(const std::string& label)
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
        return require(error_.empty(), label + ": " + error_);
    }

   private:
    void serve()
    {
        try
        {
            boost::asio::ip::tcp::socket socket(io_context_);
            acceptor_.accept(socket);

            const auto method_request = read_exact(socket, 3);
            if (method_request != std::vector<uint8_t>({socks::kVer, 0x01, socks::kMethodNoAuth}))
            {
                throw std::runtime_error("unexpected method request");
            }
            const std::array<uint8_t, 2> method_reply{socks::kVer, socks::kMethodNoAuth};
            boost::asio::write(socket, boost::asio::buffer(method_reply));

            const auto request_head = read_exact(socket, 4);
            if (request_head[0] != socks::kVer || request_head[1] != scenario_.expected_cmd || request_head[2] != 0x00)
            {
                throw std::runtime_error("unexpected request head");
            }
            consume_socks_request_tail(socket, request_head[3]);
            boost::asio::write(socket, boost::asio::buffer(scenario_.reply));
        }
        catch (const std::exception& ex)
        {
            error_ = ex.what();
        }
    }

   private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    fake_socks_reply_scenario scenario_;
    std::thread thread_;
    std::string error_;
};

relay::config make_socks_outbound_config(const uint16_t port)
{
    relay::config cfg;
    cfg.timeout.read = 5;
    cfg.timeout.write = 5;
    cfg.timeout.connect = 5;
    cfg.timeout.idle = 0;

    relay::config::outbound_entry_t outbound;
    outbound.type = "socks";
    outbound.tag = "socks-out";
    outbound.socks = relay::config::socks_t{};
    outbound.socks->host = "127.0.0.1";
    outbound.socks->port = port;
    outbound.socks->auth = false;
    cfg.outbounds.push_back(std::move(outbound));
    return cfg;
}

boost::asio::awaitable<bool> run_tcp_invalid_rsv_regression()
{
    fake_socks_reply_scenario scenario;
    scenario.expected_cmd = socks::kCmdConnect;
    scenario.reply = {socks::kVer, socks::kRepSuccess, 0x01, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    fake_socks_server server(std::move(scenario));
    auto executor = co_await boost::asio::this_coro::executor;
    auto cfg = make_socks_outbound_config(server.port());
    const auto resolved = relay::resolve_outbound(cfg, "socks-out");
    auto outbound = relay::create_tcp_outbound_for_resolved(executor, 1, 1, cfg, "socks-out", resolved, 0);

    bool ok = require(outbound != nullptr, "tcp invalid rsv outbound create failed");
    if (!ok)
    {
        co_return false;
    }
    const auto result = co_await outbound->connect("example.com", 443, cfg.timeout.connect);
    ok = ok && require(result.ec == boost::asio::error::invalid_argument, "tcp invalid rsv should fail with invalid_argument");
    co_await outbound->close();
    ok = ok && server.join_ok("tcp invalid rsv server failed");
    co_return ok;
}

boost::asio::awaitable<bool> run_tcp_zero_domain_len_regression()
{
    fake_socks_reply_scenario scenario;
    scenario.expected_cmd = socks::kCmdConnect;
    scenario.reply = {socks::kVer, socks::kRepSuccess, 0x00, socks::kAtypDomain, 0x00, 0x00, 0x00};
    fake_socks_server server(std::move(scenario));
    auto executor = co_await boost::asio::this_coro::executor;
    auto cfg = make_socks_outbound_config(server.port());
    const auto resolved = relay::resolve_outbound(cfg, "socks-out");
    auto outbound = relay::create_tcp_outbound_for_resolved(executor, 2, 2, cfg, "socks-out", resolved, 0);

    bool ok = require(outbound != nullptr, "tcp zero domain outbound create failed");
    if (!ok)
    {
        co_return false;
    }
    const auto result = co_await outbound->connect("example.com", 443, cfg.timeout.connect);
    ok = ok && require(result.ec == boost::asio::error::invalid_argument, "tcp zero domain reply should fail with invalid_argument");
    co_await outbound->close();
    ok = ok && server.join_ok("tcp zero domain server failed");
    co_return ok;
}

boost::asio::awaitable<bool> run_tcp_invalid_domain_regression()
{
    fake_socks_reply_scenario scenario;
    scenario.expected_cmd = socks::kCmdConnect;
    scenario.reply = {socks::kVer, socks::kRepSuccess, 0x00, socks::kAtypDomain, 0x03, 'a', ' ', 'b', 0x01, 0xBB};
    fake_socks_server server(std::move(scenario));
    auto executor = co_await boost::asio::this_coro::executor;
    auto cfg = make_socks_outbound_config(server.port());
    const auto resolved = relay::resolve_outbound(cfg, "socks-out");
    auto outbound = relay::create_tcp_outbound_for_resolved(executor, 3, 3, cfg, "socks-out", resolved, 0);

    bool ok = require(outbound != nullptr, "tcp invalid domain outbound create failed");
    if (!ok)
    {
        co_return false;
    }
    const auto result = co_await outbound->connect("example.com", 443, cfg.timeout.connect);
    ok = ok && require(result.ec == boost::asio::error::invalid_argument, "tcp invalid domain reply should fail with invalid_argument");
    co_await outbound->close();
    ok = ok && server.join_ok("tcp invalid domain server failed");
    co_return ok;
}

boost::asio::awaitable<bool> run_udp_invalid_rsv_regression()
{
    fake_socks_reply_scenario scenario;
    scenario.expected_cmd = socks::kCmdUdpAssociate;
    scenario.reply = {socks::kVer, socks::kRepSuccess, 0x01, socks::kAtypIpv4, 0, 0, 0, 0, 0, 0};
    fake_socks_server server(std::move(scenario));
    auto executor = co_await boost::asio::this_coro::executor;
    auto cfg = make_socks_outbound_config(server.port());

    bool ok = true;
    const auto result = co_await relay::connect_udp_proxy_outbound(executor, 4, 4, cfg, "socks-out", 0, cfg.timeout.connect);
    ok = ok && require(result.ec == boost::asio::error::invalid_argument, "udp invalid rsv should fail with invalid_argument");
    ok = ok && server.join_ok("udp invalid rsv server failed");
    co_return ok;
}

}    // namespace

int main()
{
    boost::asio::io_context io_context;
    auto result = boost::asio::co_spawn(
        io_context,
        []() -> boost::asio::awaitable<bool>
        {
            const auto tcp_invalid_rsv_ok = co_await run_tcp_invalid_rsv_regression();
            if (!tcp_invalid_rsv_ok)
            {
                co_return false;
            }
            const auto tcp_zero_domain_ok = co_await run_tcp_zero_domain_len_regression();
            if (!tcp_zero_domain_ok)
            {
                co_return false;
            }
            const auto tcp_invalid_domain_ok = co_await run_tcp_invalid_domain_regression();
            if (!tcp_invalid_domain_ok)
            {
                co_return false;
            }
            co_return co_await run_udp_invalid_rsv_regression();
        }(),
        boost::asio::use_future);
    io_context.run();
    return result.get() ? 0 : 1;
}
