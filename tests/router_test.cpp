#include <gtest/gtest.h>
#include <asio.hpp>
#include "router.h"

using namespace mux;

class TestRouter : public router
{
   public:
    TestRouter()
    {
        // 手动初始化匹配器
        block_ip_matcher_ = std::make_shared<ip_matcher>();
        direct_ip_matcher_ = std::make_shared<ip_matcher>();
        proxy_domain_matcher_ = std::make_shared<domain_matcher>();
        block_domain_matcher_ = std::make_shared<domain_matcher>();
        direct_domain_matcher_ = std::make_shared<domain_matcher>();
    }

    void add_block_ip(const std::string& cidr)
    {
        block_ip_matcher_->add_rule(cidr);
        block_ip_matcher_->optimize();
    }

    void add_direct_ip(const std::string& cidr)
    {
        direct_ip_matcher_->add_rule(cidr);
        direct_ip_matcher_->optimize();
    }

    void add_proxy_domain(const std::string& domain) { proxy_domain_matcher_->add(domain); }

    void add_block_domain(const std::string& domain) { block_domain_matcher_->add(domain); }

    void add_direct_domain(const std::string& domain) { direct_domain_matcher_->add(domain); }
};

class RouterTest : public ::testing::Test
{
   protected:
    void SetUp() override { test_router_ = std::make_shared<TestRouter>(); }

    // 辅助函数：同步运行 awaitable
    route_type run_decision(const std::string& host)
    {
        route_type result;
        asio::io_context ctx;
        connection_context conn_ctx;    // dummy context

        asio::co_spawn(
            ctx,
            [&]() -> asio::awaitable<void> { result = co_await test_router_->decide(conn_ctx, host, co_await asio::this_coro::executor); },
            asio::detached);

        ctx.run();
        return result;
    }

    std::shared_ptr<TestRouter> test_router_;
};

TEST_F(RouterTest, BlockIP)
{
    test_router_->add_block_ip("10.0.0.0/8");
    EXPECT_EQ(run_decision("10.1.2.3"), route_type::block);
    // 不匹配的 IP 应该继续传递（默认逻辑取决于 IP流）
    // router::decide_ip 逻辑: block -> direct -> proxy (默认)
    EXPECT_EQ(run_decision("192.168.1.1"), route_type::proxy);
}

TEST_F(RouterTest, DirectIP)
{
    test_router_->add_direct_ip("192.168.0.0/16");
    EXPECT_EQ(run_decision("192.168.1.100"), route_type::direct);
}

TEST_F(RouterTest, BlockPrioritizesOverDirect)
{
    // 如果一个 IP 同时存在于两者中，router 实现中会优先检查 Block
    test_router_->add_block_ip("1.1.1.1/32");
    test_router_->add_direct_ip("1.1.1.0/24");

    EXPECT_EQ(run_decision("1.1.1.1"), route_type::block);
    EXPECT_EQ(run_decision("1.1.1.2"), route_type::direct);
}

TEST_F(RouterTest, BlockDomain)
{
    test_router_->add_block_domain("ad.com");
    EXPECT_EQ(run_decision("ad.com"), route_type::block);
    EXPECT_EQ(run_decision("sub.ad.com"), route_type::block);
}

TEST_F(RouterTest, DirectDomain)
{
    test_router_->add_direct_domain("google.com");
    EXPECT_EQ(run_decision("google.com"), route_type::direct);
    EXPECT_EQ(run_decision("www.google.com"), route_type::direct);
}

TEST_F(RouterTest, ProxyDomain)
{
    test_router_->add_proxy_domain("netflix.com");
    EXPECT_EQ(run_decision("netflix.com"), route_type::proxy);
}

TEST_F(RouterTest, DomainPriority)
{
    // 当前 router 优先级: Block -> Direct -> Proxy -> Default(Direct)
    test_router_->add_block_domain("bad.example.com");
    test_router_->add_direct_domain("example.com");

    EXPECT_EQ(run_decision("bad.example.com"), route_type::block);
    EXPECT_EQ(run_decision("good.example.com"), route_type::direct);

    // 域名的默认规则是 direct
    EXPECT_EQ(run_decision("unknown.com"), route_type::direct);
}
