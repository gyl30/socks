#include <memory>
#include <string>

#include <gtest/gtest.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include "router.h"
#include "ip_matcher.h"
#include "log_context.h"
#include "domain_matcher.h"

class test_router : public mux::router
{
   public:
    test_router()
    {
        block_ip_matcher() = std::make_shared<mux::ip_matcher>();
        direct_ip_matcher() = std::make_shared<mux::ip_matcher>();
        proxy_domain_matcher() = std::make_shared<mux::domain_matcher>();
        block_domain_matcher() = std::make_shared<mux::domain_matcher>();
        direct_domain_matcher() = std::make_shared<mux::domain_matcher>();
    }

    void add_block_ip(const std::string& cidr)
    {
        block_ip_matcher()->add_rule(cidr);
        block_ip_matcher()->optimize();
    }

    void add_direct_ip(const std::string& cidr)
    {
        direct_ip_matcher()->add_rule(cidr);
        direct_ip_matcher()->optimize();
    }

    void add_proxy_domain(const std::string& domain) { proxy_domain_matcher()->add(domain); }

    void add_block_domain(const std::string& domain) { block_domain_matcher()->add(domain); }

    void add_direct_domain(const std::string& domain) { direct_domain_matcher()->add(domain); }
};

class router_test : public ::testing::Test
{
   protected:
    void SetUp() override { test_router_ = std::make_shared<test_router>(); }

    mux::route_type run_decision(const std::string& host)
    {
        mux::route_type result = mux::route_type::kDirect;
        boost::asio::io_context ctx;
        mux::connection_context conn_ctx;

        boost::asio::co_spawn(
            ctx,
            [&]() -> boost::asio::awaitable<void> { result = co_await test_router_->decide(conn_ctx, host); },
            boost::asio::detached);

        ctx.run();
        return result;
    }

   protected:
    std::shared_ptr<test_router>& router_instance() { return test_router_; }

   private:
    std::shared_ptr<test_router> test_router_;
};

TEST_F(router_test, BlockIP)
{
    router_instance()->add_block_ip("10.0.0.0/8");
    EXPECT_EQ(run_decision("10.1.2.3"), mux::route_type::kBlock);

    EXPECT_EQ(run_decision("192.168.1.1"), mux::route_type::kProxy);
}

TEST_F(router_test, DirectIP)
{
    router_instance()->add_direct_ip("192.168.0.0/16");
    EXPECT_EQ(run_decision("192.168.1.100"), mux::route_type::kDirect);
}

TEST_F(router_test, BlockPrioritizesOverDirect)
{
    router_instance()->add_block_ip("1.1.1.1/32");
    router_instance()->add_direct_ip("1.1.1.0/24");

    EXPECT_EQ(run_decision("1.1.1.1"), mux::route_type::kBlock);
    EXPECT_EQ(run_decision("1.1.1.2"), mux::route_type::kDirect);
}

TEST_F(router_test, BlockDomain)
{
    router_instance()->add_block_domain("ad.com");
    EXPECT_EQ(run_decision("ad.com"), mux::route_type::kBlock);
    EXPECT_EQ(run_decision("sub.ad.com"), mux::route_type::kBlock);
}

TEST_F(router_test, DirectDomain)
{
    router_instance()->add_direct_domain("google.com");
    EXPECT_EQ(run_decision("google.com"), mux::route_type::kDirect);
    EXPECT_EQ(run_decision("www.google.com"), mux::route_type::kDirect);
}

TEST_F(router_test, ProxyDomain)
{
    router_instance()->add_proxy_domain("netflix.com");
    EXPECT_EQ(run_decision("netflix.com"), mux::route_type::kProxy);
}

TEST_F(router_test, DomainPriority)
{
    router_instance()->add_block_domain("bad.example.com");
    router_instance()->add_direct_domain("example.com");

    EXPECT_EQ(run_decision("bad.example.com"), mux::route_type::kBlock);
    EXPECT_EQ(run_decision("good.example.com"), mux::route_type::kDirect);

    EXPECT_EQ(run_decision("unknown.com"), mux::route_type::kDirect);
}
