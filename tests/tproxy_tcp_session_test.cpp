#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <cstdint>

#include <gtest/gtest.h>
#include <asio/write.hpp>
#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/redirect_error.hpp>

#include "router.h"
#include "ip_matcher.h"
#include "domain_matcher.h"
#include "tproxy_tcp_session.h"

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

}    // namespace

TEST(TproxyTcpSessionTest, DirectEcho)
{
    asio::io_context ctx;
    auto router = std::make_shared<direct_router>();

    asio::ip::tcp::acceptor echo_acceptor(ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto echo_port = echo_acceptor.local_endpoint().port();

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket echo_socket = co_await echo_acceptor.async_accept(asio::use_awaitable);
            std::array<char, 64> buf = {};
            const auto [read_ec, n] = co_await echo_socket.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (!read_ec && n > 0)
            {
                co_await asio::async_write(echo_socket, asio::buffer(buf.data(), n), asio::use_awaitable);
            }
            co_return;
        },
        asio::detached);

    asio::ip::tcp::acceptor tproxy_acceptor(ctx, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    const auto tproxy_port = tproxy_acceptor.local_endpoint().port();

    mux::config cfg;
    cfg.tproxy.mark = 0;
    cfg.timeout.idle = 3;

    const asio::ip::tcp::endpoint dst_ep(asio::ip::make_address("127.0.0.1"), echo_port);

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket sock = co_await tproxy_acceptor.async_accept(asio::use_awaitable);
            auto session = std::make_shared<mux::tproxy_tcp_session>(std::move(sock), nullptr, router, 1, cfg, dst_ep);
            session->start();
            co_return;
        },
        asio::detached);

    std::atomic<bool> done{false};
    std::atomic<bool> ok{false};

    asio::co_spawn(
        ctx,
        [&]() -> asio::awaitable<void>
        {
            asio::ip::tcp::socket client(ctx);
            std::error_code ec;
            co_await client.async_connect({asio::ip::make_address("127.0.0.1"), tproxy_port}, asio::redirect_error(asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            const std::string msg = "tproxy-echo";
            co_await asio::async_write(client, asio::buffer(msg), asio::redirect_error(asio::use_awaitable, ec));
            if (ec)
            {
                done = true;
                ctx.stop();
                co_return;
            }

            std::array<char, 32> buf = {};
            const auto [read_ec, n] = co_await client.async_read_some(asio::buffer(buf), asio::as_tuple(asio::use_awaitable));
            if (!read_ec && n == msg.size() && std::string(buf.data(), n) == msg)
            {
                ok = true;
            }

            done = true;
            ctx.stop();
            co_return;
        },
        asio::detached);

    asio::steady_timer timer(ctx);
    timer.expires_after(std::chrono::seconds(5));
    timer.async_wait(
        [&](const std::error_code& ec)
        {
            if (!ec)
            {
                ctx.stop();
            }
        });

    ctx.run();

    EXPECT_TRUE(done);
    EXPECT_TRUE(ok);
}
