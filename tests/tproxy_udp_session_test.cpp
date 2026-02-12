#include <array>
#include <chrono>
#include <memory>
#include <vector>
#include <thread>

#include <gtest/gtest.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include "router.h"
#include "ip_matcher.h"
#include "domain_matcher.h"
#include "mux_stream.h"
#include "context_pool.h"
#define private public
#include "tproxy_udp_session.h"
#include "tproxy_client.h"
#undef private

namespace
{

class direct_router : public mux::router
{
   public:
    direct_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();

        direct_ip_matcher()->add_rule("0.0.0.0/0");
        direct_ip_matcher()->add_rule("::/0");
        direct_ip_matcher()->optimize();
    }
};

std::uint64_t now_ms()
{
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

}    // namespace

TEST(TproxyUdpSessionTest, IdleDetection)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 1;

    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 1, cfg, client_ep);
    session->start();

    const asio::ip::udp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), 53);
    std::array<std::uint8_t, 1> data = {0};
    asio::co_spawn(
        ctx,
        [session, dst_ep, data]() -> asio::awaitable<void> { co_await session->handle_packet(dst_ep, data.data(), data.size()); },
        asio::detached);

    for (int i = 0; i < 5; ++i)
    {
        ctx.poll();
    }

    const auto now = now_ms();
    EXPECT_FALSE(session->is_idle(now, 1000));
    EXPECT_TRUE(session->is_idle(now + 2000, 1000));

    session->stop();
    ctx.poll();
}

TEST(TproxyUdpSessionTest, IdleTimeoutZeroNeverExpires)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    cfg.timeout.idle = 1;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12345);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 2, cfg, client_ep);

    EXPECT_FALSE(session->is_idle(now_ms(), 0));
}

TEST(TproxyUdpSessionTest, InternalGuardBranches)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    mux::config cfg;
    const asio::ip::udp::endpoint client_ep(asio::ip::make_address("127.0.0.1"), 12346);
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx, nullptr, router, nullptr, 3, cfg, client_ep);

    asio::ip::udp::endpoint src_ep;
    std::vector<std::uint8_t> payload;
    EXPECT_FALSE(session->decode_proxy_packet({0x00, 0x01}, src_ep, payload));

    socks_udp_header h;
    h.addr = "not-an-ip";
    h.port = 5353;
    auto pkt = socks_codec::encode_udp_header(h);
    pkt.push_back(0x42);
    EXPECT_FALSE(session->decode_proxy_packet(pkt, src_ep, payload));

    session->maybe_start_proxy_reader(false);

    bool should_start_reader = false;
    session->stream_ =
        std::make_shared<mux::mux_stream>(1, 1, "trace", std::shared_ptr<mux::mux_connection>{}, ctx);
    EXPECT_FALSE(session->install_proxy_stream(nullptr, nullptr, should_start_reader));
}

TEST(TproxyClientTest, DisabledStartSetsStopFlag)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = false;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, InvalidRealityAuthConfigStopsEarly)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.reality.fingerprint = "invalid-fingerprint";
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    client->stop();
}

TEST(TproxyClientTest, TcpPortZeroStopsEarlyAndEndpointKeyWorks)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.tcp_port = 0;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_TRUE(client->stop_.load(std::memory_order_acquire));
    EXPECT_EQ(client->endpoint_key(asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 5353)), "127.0.0.1:5353");
    client->stop();
}

TEST(TproxyClientTest, UdpPortFallsBackToTcpPortWhenConfiguredZero)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = 31081;
    cfg.tproxy.udp_port = 0;

    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);
    client->start();

    EXPECT_EQ(client->udp_port(), cfg.tproxy.tcp_port);
    client->stop();
    pool.stop();
}

TEST(TproxyClientTest, AcceptAndUdpLoopReturnOnInvalidListenHost)
{
    std::error_code ec;
    mux::io_context_pool pool(1, ec);
    ASSERT_FALSE(ec);

    mux::config cfg;
    cfg.tproxy.enabled = true;
    cfg.tproxy.listen_host = "invalid host value";
    cfg.tproxy.mark = 0;
    cfg.tproxy.tcp_port = 31091;
    cfg.tproxy.udp_port = 31092;
    auto client = std::make_shared<mux::tproxy_client>(pool, cfg);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->accept_tcp_loop();
                       co_return;
                   },
                   asio::detached);

    asio::co_spawn(pool.get_io_context(),
                   [client]() -> asio::awaitable<void>
                   {
                       co_await client->udp_loop();
                       co_return;
                   },
                   asio::detached);

    std::thread runner([&pool]() { pool.run(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    pool.stop();
    runner.join();
}
