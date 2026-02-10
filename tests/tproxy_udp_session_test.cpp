#include <array>
#include <chrono>
#include <memory>

#include <gtest/gtest.h>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>

#include "router.h"
#include "ip_matcher.h"
#include "domain_matcher.h"
#include "tproxy_udp_session.h"

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
    const auto session = std::make_shared<mux::tproxy_udp_session>(ctx.get_executor(), nullptr, router, nullptr, 1, cfg, client_ep);
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
